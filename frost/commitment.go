package frost

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Commitment is a participant's one-time commitment holding its identifier, and hiding and binding nonces.
type Commitment struct {
	HidingNonceCommitment  *btcec.JacobianPoint
	BindingNonceCommitment *btcec.JacobianPoint
	CommitmentID           uint64
	SignerID               int
}

// ValidateCommitmentList returns an error if at least one of the following conditions is not met:
// - list length is within [threshold;max].
// - no signer identifier in commitments is 0.
// - no singer identifier in commitments is > max signers.
// - no duplicated in signer identifiers.
// - all commitment signer identifiers are registered in the configuration.
func (c *Configuration) ValidateCommitmentList(commitments []Commitment) error {
	if !c.initialized {
		return fmt.Errorf("configuration must be initialized")
	}

	if length := len(commitments); length < c.Threshold || length > c.MaxSigners {
		return fmt.Errorf("invalid number of commitments: %d (needs at least %d and at most %d)",
			length, c.Threshold, c.MaxSigners)
	}

	for i, commitment := range commitments {
		if err := c.ValidateCommitment(commitment); err != nil {
			return err
		}

		// check for duplicate participant entries
		for _, prev := range commitments[:i] {
			if prev.SignerID == commitment.SignerID {
				return fmt.Errorf("commitment list contains multiple commitments of participant %d", commitment.SignerID)
			}
		}

		// list must be sorted, compare with the next commitment
		if i <= len(commitments)-2 {
			if cmp.Compare(commitment.SignerID, commitments[i+1].SignerID) > 0 {
				return fmt.Errorf("commitment list is not sorted")
			}
		}
	}

	return nil
}

func (c *Configuration) ValidateCommitment(commitment Commitment) error {
	if !c.initialized {
		return fmt.Errorf("configuration must be initialized")
	}

	if commitment.SignerID == 0 || commitment.SignerID > c.MaxSigners {
		return fmt.Errorf("identifier can't be zero or bigger than the max number of signers")
	}

	if err := c.validatePoint(commitment.HidingNonceCommitment); err != nil {
		return fmt.Errorf(
			"invalid commitment %d for signer %d, the hiding nonce commitment %w",
			commitment.CommitmentID,
			commitment.SignerID,
			err,
		)
	}

	if err := c.validatePoint(commitment.BindingNonceCommitment); err != nil {
		return fmt.Errorf(
			"invalid commitment %d for signer %d, the binding nonce commitment %w",
			commitment.CommitmentID,
			commitment.SignerID,
			err,
		)
	}

	// Validate that the commitment comes from a registered signer.
	// TODO
	// if !c.isSignerRegistered(commitment.SignerID) {
	// 	return fmt.Errorf(
	// 		"signer identifier %d for commitment %d is not registered in the configuration",
	// 		commitment.SignerID,
	// 		commitment.CommitmentID,
	// 	)
	// }

	return nil
}

func commitmentsBindingFactors(
	commitments []Commitment,
	publicKey *btcec.JacobianPoint,
	message []byte,
) map[int]*btcec.ModNScalar {
	coms := commitmentsWithEncodedID(commitments)

	encodedCommitHash := chainhash.TaggedHash([]byte("FROST/bf1"), encodeCommitmentList(coms))
	h := chainhash.TaggedHash([]byte("FROST/bf2"), message)

	rhoInputPrefix := make([]byte, 33+32+32)

	writePointTo(rhoInputPrefix[0:33], publicKey)
	copy(rhoInputPrefix[33:], h[:])
	copy(rhoInputPrefix[33+32:], encodedCommitHash[:])

	bindingFactors := make(map[int]*btcec.ModNScalar, len(commitments))

	pre := ""
	for _, com := range coms {
		pre += "  "
		hash := chainhash.TaggedHash([]byte("FROST/rho"), rhoInputPrefix, com.ParticipantID[:])
		bf := new(btcec.ModNScalar)
		bf.SetBytes((*[32]byte)(hash))
		bindingFactors[com.Commitment.SignerID] = bf
	}

	return bindingFactors
}

type commitmentWithEncodedID struct {
	Commitment
	ParticipantID [32]byte
}

func commitmentsWithEncodedID(commitments []Commitment) []commitmentWithEncodedID {
	r := make([]commitmentWithEncodedID, len(commitments))
	for i, com := range commitments {
		r[i] = commitmentWithEncodedID{
			ParticipantID: new(btcec.ModNScalar).SetInt(uint32(com.SignerID)).Bytes(),
			Commitment:    com,
		}
	}

	return r
}

func encodeCommitmentList(commitments []commitmentWithEncodedID) []byte {
	size := len(commitments) * (32 + 2*33)
	encoded := make([]byte, size)

	for i, com := range commitments {
		base := i * (32 + 2*33)

		copy(encoded[base:], com.ParticipantID[:])

		writePointTo(encoded[base+32:base+32+33], com.HidingNonceCommitment)
		writePointTo(encoded[base+32+33:base+32+33+33], com.BindingNonceCommitment)
	}

	return encoded
}

func groupCommitment(commitments []Commitment, bindingFactors map[int]*btcec.ModNScalar) *btcec.JacobianPoint {
	gc := new(btcec.JacobianPoint)

	for _, com := range commitments {
		factor := bindingFactors[com.SignerID]

		bindingNonce := new(btcec.JacobianPoint)
		bindingNonce.Set(com.BindingNonceCommitment)
		btcec.ScalarMultNonConst(factor, bindingNonce, bindingNonce)

		btcec.AddNonConst(com.BindingNonceCommitment, gc, gc)
		btcec.AddNonConst(bindingNonce, gc, gc)
	}

	gc.ToAffine()
	return gc
}

func (c Commitment) Hex() string { return hex.EncodeToString(c.Encode()) }
func (c *Commitment) DecodeHex(x string) error {
	b, err := hex.DecodeString(x)
	if err != nil {
		return err
	}
	return c.Decode(b)
}

func (c Commitment) Encode() []byte {
	out := make([]byte, 8+2+33+33)

	binary.LittleEndian.PutUint64(out[0:8], c.CommitmentID)
	binary.LittleEndian.PutUint16(out[8:8+2], uint16(c.SignerID))

	writePointTo(out[8+2:8+2+33], c.BindingNonceCommitment)
	writePointTo(out[8+2+33:8+2+33+33], c.HidingNonceCommitment)

	return out
}

func (c *Commitment) Decode(in []byte) error {
	if len(in) < 8+2+33+33 {
		return fmt.Errorf("too small")
	}

	c.CommitmentID = binary.LittleEndian.Uint64(in[0:8])
	c.SignerID = int(binary.LittleEndian.Uint16(in[8 : 8+2]))

	if pt, err := btcec.ParsePubKey(in[8+2 : 8+2+33]); err != nil {
		return fmt.Errorf("failed to decode binding nonce: %w", err)
	} else {
		c.BindingNonceCommitment = new(btcec.JacobianPoint)
		pt.AsJacobian(c.BindingNonceCommitment)
	}

	if pt, err := btcec.ParsePubKey(in[8+2+33 : 8+2+33+33]); err != nil {
		return fmt.Errorf("failed to decode hiding nonce: %w", err)
	} else {
		c.HidingNonceCommitment = new(btcec.JacobianPoint)
		pt.AsJacobian(c.HidingNonceCommitment)
	}

	return nil
}
