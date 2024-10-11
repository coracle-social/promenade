package frost

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Configuration struct {
	PublicKey             *btcec.JacobianPoint
	SignerPublicKeyShares []PublicKeyShare
	Threshold             int
	MaxSigners            int
	verified              bool
	keysVerified          bool
}

// Init verifies whether the configuration's components are valid, in which case it initializes internal values, or
// returns an error otherwise.
func (c *Configuration) Init() error {
	if !c.verified {
		if err := c.verifyConfiguration(); err != nil {
			return err
		}
	}

	if !c.keysVerified {
		if err := c.verifySignerPublicKeyShares(); err != nil {
			return err
		}
	}

	return nil
}

// Signer returns a new participant of the protocol instantiated from the Configuration and the signer's key share.
func (c *Configuration) Signer(keyShare *KeyShare) (*Signer, error) {
	if !c.verified || !c.keysVerified {
		return nil, fmt.Errorf("Configuration must be initialized")
	}

	if err := c.ValidateKeyShare(keyShare); err != nil {
		return nil, err
	}

	return &Signer{
		KeyShare:         keyShare,
		NonceCommitments: make(map[uint64]*Nonce),
		Configuration:    c,
	}, nil
}

func (c *Configuration) ValidatePublicKeyShare(pks *PublicKeyShare) error {
	if !c.verified {
		if err := c.verifyConfiguration(); err != nil {
			return err
		}
	}

	if pks == nil {
		return errors.New("public key share is nil")
	}

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

func (c *Configuration) ValidateKeyShare(keyShare *KeyShare) error {
	if !c.verified || !c.keysVerified {
		return fmt.Errorf("Configuration must be initialized")
	}

	if keyShare == nil {
		return fmt.Errorf("provided key share is nil")
	}

	if err := c.ValidatePublicKeyShare(&keyShare.PublicKeyShare); err != nil {
		return err
	}

	if !c.PublicKey.X.Equals(&keyShare.PublicKey.X) || !c.PublicKey.Y.Equals(&keyShare.PublicKey.Y) {
		return fmt.Errorf("provided key share has a different public key than the one registered for that signer in the configuration")
	}

	if keyShare.Secret == nil || keyShare.Secret.IsZero() {
		return fmt.Errorf("provided secret is nil or zero")
	}

	pt := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(keyShare.Secret, pt)

	if !pt.X.Equals(&keyShare.PublicKey.X) || !pt.Y.Equals(&keyShare.PublicKey.Y) {
		return fmt.Errorf("provided key share has a public key that doesn't match its own secret key")
	}

	return nil
}

func (c *Configuration) verifySignerPublicKeyShares() error {
	length := len(c.SignerPublicKeyShares)
	if length < c.Threshold || length > c.MaxSigners {
		return fmt.Errorf("number of public key shares (%d) is smaller than threshold (%d) or bigger than max (%d)",
			length, c.Threshold, c.MaxSigners)
	}

	for i, pks := range c.SignerPublicKeyShares {
		if pks == nil {
			return fmt.Errorf("empty public key share at index %d", i)
		}

		if err := c.ValidatePublicKeyShare(pks); err != nil {
			return err
		}

		// verify whether the ID or public key have duplicates
		for _, prev := range c.SignerPublicKeyShares {
			if prev.ID == pks.ID {
				return fmt.Errorf("found duplicate identifier for signer %d", pks.ID)
			}
			if prev.PublicKey.X.Equals(&pks.PublicKey.X) || prev.PublicKey.Y.Equals(&pks.PublicKey.Y) {
				return fmt.Errorf("found duplicate public keys for signers %d and %d", pks.ID, prev.ID)
			}
		}
	}

	c.keysVerified = true

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

	c.verified = true

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
	out := make([]byte, 6+33+len(c.SignerPublicKeyShares)*33)
	binary.LittleEndian.PutUint16(out[0:2], uint16(c.Threshold))
	binary.LittleEndian.PutUint16(out[2:4], uint16(c.MaxSigners))
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(c.SignerPublicKeyShares)))

	if c.PublicKey.Y.IsOdd() {
		out[6] = secp256k1.PubKeyFormatCompressedOdd
	} else {
		out[6] = secp256k1.PubKeyFormatCompressedEven
	}
	c.PublicKey.X.PutBytesUnchecked(out[7:])

	curr := 6 + 33
	for _, pks := range c.SignerPublicKeyShares {
		curr += pks.EncodeTo(out[curr:])
	}

	return out
}

func (c *Configuration) Decode(in []byte) error {
	if len(in) < 6+33 {
		return nil
	}

	c.Threshold = int(binary.LittleEndian.Uint16(in[0:2]))
	c.MaxSigners = int(binary.LittleEndian.Uint16(in[2:4]))
	c.SignerPublicKeyShares = make([]PublicKeyShare, binary.LittleEndian.Uint16(in[4:6]))

	pk, err := secp256k1.ParsePubKey(in[6 : 6+33])
	if err != nil {
		return err
	}

	pk.AsJacobian(c.PublicKey)

	return nil
}
