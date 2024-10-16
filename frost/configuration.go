package frost

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Configuration struct {
	PublicKey             *btcec.JacobianPoint
	SignerPublicKeyShards []PublicKeyShard
	Threshold             int
	MaxSigners            int

	initialized bool
}

// Init verifies whether the configuration's components are valid, in which case it initializes internal values, or
// returns an error otherwise.
func (c *Configuration) Init() error {
	if err := c.verifyConfiguration(); err != nil {
		return fmt.Errorf("error verifying configuration: %w", err)
	}

	if err := c.verifySignerPublicKeyShards(); err != nil {
		return fmt.Errorf("error verifying public key shards: %w", err)
	}

	c.initialized = true

	return nil
}

// Signer returns a new participant of the protocol instantiated from the Configuration and the signer's key shard.
func (c *Configuration) Signer(keyshard KeyShard) (*Signer, error) {
	if !c.initialized {
		return nil, fmt.Errorf("configuration must be initialized")
	}

	if err := c.ValidateKeyShard(keyshard); err != nil {
		return nil, err
	}

	return &Signer{
		LambdaRegistry:   make(LambdaRegistry),
		KeyShard:         keyshard,
		NonceCommitments: make(map[uint64]Nonce),
		Configuration:    c,
	}, nil
}

func (c *Configuration) ValidatePublicKeyShard(pks PublicKeyShard) error {
	if pks.ID == 0 {
		return fmt.Errorf("identifier can't be zero")
	}

	if pks.ID > c.MaxSigners {
		return fmt.Errorf("identifier can't be bigger than the max number of signers")
	}

	if err := c.validatePoint(pks.PublicKey); err != nil {
		return fmt.Errorf("public key is invalid: %w", err)
	}

	return nil
}

func (c *Configuration) ValidateKeyShard(keyshard KeyShard) error {
	if !c.initialized {
		return fmt.Errorf("configuration must be initialized")
	}

	if err := c.ValidatePublicKeyShard(keyshard.PublicKeyShard); err != nil {
		return err
	}

	if !c.PublicKey.X.Equals(&keyshard.PublicKey.X) || !c.PublicKey.Y.Equals(&keyshard.PublicKey.Y) {
		return fmt.Errorf("provided key shard has a different public key than the one registered for that signer in the configuration")
	}

	if keyshard.Secret == nil || keyshard.Secret.IsZero() {
		return fmt.Errorf("provided secret is nil or zero")
	}

	pt := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(keyshard.Secret, pt)
	pt.ToAffine()

	if !pt.X.Equals(&keyshard.PublicKeyShard.PublicKey.X) || !pt.Y.Equals(&keyshard.PublicKeyShard.PublicKey.Y) {
		public := make([]byte, 33)
		if keyshard.PublicKey.Y.IsOdd() {
			public[0] = secp256k1.PubKeyFormatCompressedOdd
		} else {
			public[0] = secp256k1.PubKeyFormatCompressedOdd
		}
		keyshard.PublicKey.X.PutBytesUnchecked(public[1:])

		derived := make([]byte, 33)
		if pt.Y.IsOdd() {
			derived[0] = secp256k1.PubKeyFormatCompressedOdd
		} else {
			derived[0] = secp256k1.PubKeyFormatCompressedOdd
		}
		pt.X.PutBytesUnchecked(derived[1:])

		return fmt.Errorf("provided key shard has a public key (%x) that doesn't match its own secret key (%x)",
			public, derived)
	}

	return nil
}

func (c *Configuration) verifySignerPublicKeyShards() error {
	length := len(c.SignerPublicKeyShards)
	if length < c.Threshold || length > c.MaxSigners {
		return fmt.Errorf("number of public key shards (%d) is smaller than threshold (%d) or bigger than max (%d)",
			length, c.Threshold, c.MaxSigners)
	}

	for p, pks := range c.SignerPublicKeyShards {
		if err := c.ValidatePublicKeyShard(pks); err != nil {
			return fmt.Errorf("error validating public key shards: %w", err)
		}

		// verify whether the ID or public key have duplicates
		for _, prev := range c.SignerPublicKeyShards[0:p] {
			if prev.ID == pks.ID {
				return fmt.Errorf("found duplicate identifier for signer %d", pks.ID)
			}
			if prev.PublicKey.X.Equals(&pks.PublicKey.X) || prev.PublicKey.Y.Equals(&pks.PublicKey.Y) {
				return fmt.Errorf("found duplicate public keys for signers %d and %d", pks.ID, prev.ID)
			}
		}
	}

	return nil
}

func (c *Configuration) verifyConfiguration() error {
	if c.Threshold == 0 || c.Threshold > c.MaxSigners {
		return fmt.Errorf("threshold (%d) must be positive and smaller than max signers (%d)",
			c.Threshold, c.MaxSigners)
	}

	if err := c.validatePoint(c.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}

	return nil
}

func (c *Configuration) validatePoint(pt *btcec.JacobianPoint) error {
	if pt == nil {
		return fmt.Errorf("public key can't be nil")
	}

	if pt.X.IsZero() || pt.Y.IsZero() {
		return fmt.Errorf("public key can't be zero")
	}

	G := new(btcec.JacobianPoint)
	btcec.Generator().AsJacobian(G)
	if G.X.Equals(&pt.X) || G.Y.Equals(&pt.Y) {
		return fmt.Errorf("public key can't be G")
	}

	return nil
}

func (c *Configuration) Hex() string { return hex.EncodeToString(c.Encode()) }
func (c *Configuration) DecodeHex(x string) error {
	b, err := hex.DecodeString(x)
	if err != nil {
		return err
	}
	return c.Decode(b)
}

func (c *Configuration) Encode() []byte {
	out := make([]byte, 6+33, 6+33+len(c.SignerPublicKeyShards)*(6+33+33*c.Threshold))

	binary.LittleEndian.PutUint16(out[0:2], uint16(c.Threshold))
	binary.LittleEndian.PutUint16(out[2:4], uint16(c.MaxSigners))
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(c.SignerPublicKeyShards)))

	writePointTo(out[6:], c.PublicKey)

	for _, pks := range c.SignerPublicKeyShards {
		out = append(out, pks.Encode()...)
	}

	return out
}

func (c *Configuration) Decode(in []byte) error {
	if len(in) < 6+33 {
		return fmt.Errorf("too small")
	}

	c.Threshold = int(binary.LittleEndian.Uint16(in[0:2]))
	c.MaxSigners = int(binary.LittleEndian.Uint16(in[2:4]))
	c.SignerPublicKeyShards = make([]PublicKeyShard, binary.LittleEndian.Uint16(in[4:6]))

	if pk, err := secp256k1.ParsePubKey(in[6 : 6+33]); err != nil {
		return fmt.Errorf("failed to decode pubkey: %w", err)
	} else {
		c.PublicKey = new(btcec.JacobianPoint)
		pk.AsJacobian(c.PublicKey)
	}

	curr := 6 + 33
	for i := range c.SignerPublicKeyShards {
		n, err := c.SignerPublicKeyShards[i].Decode(in[curr:])
		if err != nil {
			return fmt.Errorf("failed to decode pubkey shard %d: %w", i, err)
		}

		curr += n
	}

	return nil
}
