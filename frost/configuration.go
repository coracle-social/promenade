package frost

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Configuration struct {
	PublicKey    *btcec.JacobianPoint
	Threshold    int
	MaxSigners   int
	Participants []int
}

// Signer returns a new participant of the protocol instantiated from the Configuration and the signer's key shard.
func (c *Configuration) Signer(keyshard KeyShard) (*Signer, error) {
	if err := c.ValidateKeyShard(keyshard); err != nil {
		return nil, err
	}

	return &Signer{
		LambdaRegistry: make(LambdaRegistry),
		KeyShard:       keyshard,
		Configuration:  c,
	}, nil
}

func (c *Configuration) ComputeGroupCommitment(commitments []Commitment, message []byte) (
	groupCommitment BinoncePublic,
	bindingCoefficient *btcec.ModNScalar,
	finalNonce *btcec.JacobianPoint,
) {
	// PreAgg(pk, {ρi}i∈S) -- from https://eprint.iacr.org/2023/899.pdf, page 15
	// 2 : {(Di, Ei)}i∈S ← {ρi}i∈S
	// 3 : D ← ∏i∈S Di
	// 4 : E ← ∏i∈S Ei
	// 5 : ρ ← (D, E)
	groupCommitment = BinoncePublic{
		new(btcec.JacobianPoint),
		new(btcec.JacobianPoint),
	}
	for _, com := range commitments {
		btcec.AddNonConst(groupCommitment[0], com.BinoncePublic[0], groupCommitment[0])
		btcec.AddNonConst(groupCommitment[1], com.BinoncePublic[1], groupCommitment[1])
	}
	groupCommitment[0].ToAffine()
	groupCommitment[1].ToAffine()

	// SignRound(ski, pk, S, statei, ρ, m) -- from https://eprint.iacr.org/2023/899.pdf, page 15
	// 6 : b ← Hnon(X, S, ρ, m)
	bindingCoefficient = computeBindingCoefficient(c.PublicKey, groupCommitment, message, c.Participants)

	// 7 : R ← DEb
	finalNonce, negate := bindFinalNonce(groupCommitment, bindingCoefficient)

	// BIP-340 special
	if negate {
		for i := range commitments {
			commitments[i].BinoncePublic[0].X.Negate(1)
			commitments[i].BinoncePublic[0].X.Normalize()
			commitments[i].BinoncePublic[1].X.Negate(1)
			commitments[i].BinoncePublic[1].X.Normalize()
		}
	}

	return groupCommitment, bindingCoefficient, finalNonce
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
	if err := c.ValidatePublicKeyShard(keyshard.PublicKeyShard); err != nil {
		return err
	}

	if !c.PublicKey.X.Equals(&keyshard.PublicKey.X) || (c.PublicKey.Y.IsOdd() != keyshard.PublicKey.Y.IsOdd()) {
		return fmt.Errorf("provided key shard has a different public key than the one registered for that signer in the configuration: expected %s/%v, got %s/%v",
			c.PublicKey.X, c.PublicKey.Y.IsOdd(),
			keyshard.PublicKey.X, keyshard.PublicKey.Y.IsOdd(),
		)
	}

	if keyshard.Secret == nil || keyshard.Secret.IsZero() {
		return fmt.Errorf("provided secret is nil or zero")
	}

	pt := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(keyshard.Secret, pt)
	pt.ToAffine()

	if !pt.X.Equals(&keyshard.PublicKeyShard.PublicKey.X) || !pt.Y.Equals(&keyshard.PublicKeyShard.PublicKey.Y) {
		public := make([]byte, 33)
		writePointTo(public, keyshard.PublicKeyShard.PublicKey)

		derived := make([]byte, 33)
		writePointTo(derived, pt)

		return fmt.Errorf("provided key shard has a public key (%x) that doesn't match its own secret key (%x=>%x)",
			public, keyshard.Secret.Bytes(), derived)
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
	out := make([]byte, 6+33+len(c.Participants)*2)

	binary.LittleEndian.PutUint16(out[0:2], uint16(c.Threshold))
	binary.LittleEndian.PutUint16(out[2:4], uint16(c.MaxSigners))
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(c.Participants)))

	writePointTo(out[6:6+33], c.PublicKey)

	for i, part := range c.Participants {
		binary.BigEndian.PutUint16(out[6+33+i*2:], uint16(part))
	}

	return out
}

func (c *Configuration) Decode(in []byte) error {
	if len(in) < 6+33 {
		return fmt.Errorf("too small")
	}

	c.Threshold = int(binary.LittleEndian.Uint16(in[0:2]))
	c.MaxSigners = int(binary.LittleEndian.Uint16(in[2:4]))
	c.Participants = make([]int, binary.LittleEndian.Uint16(in[4:6]))

	if pk, err := secp256k1.ParsePubKey(in[6 : 6+33]); err != nil {
		return fmt.Errorf("failed to decode pubkey: %w", err)
	} else {
		c.PublicKey = new(btcec.JacobianPoint)
		pk.AsJacobian(c.PublicKey)
	}

	for i := range c.Participants {
		c.Participants[i] = int(binary.BigEndian.Uint16(in[6+33+i*2 : 6+33+(i+1)*2]))
	}

	return nil
}
