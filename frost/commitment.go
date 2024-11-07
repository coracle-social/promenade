package frost

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type BinoncePublic [2]*btcec.JacobianPoint // (D, E)

type BinonceSecret [2]*btcec.ModNScalar // (d, e)

type Commitment struct {
	BinoncePublic
	SignerID int
}

// ValidateCommitmentList returns an error if at least one of the following conditions is not met:
// - list length is within [threshold;max].
// - no signer identifier in commitments is 0.
// - no singer identifier in commitments is > max signers.
// - no duplicated in signer identifiers.
// - all commitment signer identifiers are registered in the configuration.
func (c *Configuration) ValidateCommitmentList(commitments []Commitment) error {
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
	if commitment.SignerID == 0 || commitment.SignerID > c.MaxSigners {
		return fmt.Errorf("identifier can't be zero or bigger than the max number of signers")
	}

	if err := c.validatePoint(commitment.BinoncePublic[0]); err != nil {
		return fmt.Errorf(
			"invalid commitment for signer %d, the hiding nonce commitment %w",
			commitment.SignerID,
			err,
		)
	}

	if err := c.validatePoint(commitment.BinoncePublic[1]); err != nil {
		return fmt.Errorf(
			"invalid commitment for signer %d, the binding nonce commitment %w",
			commitment.SignerID,
			err,
		)
	}

	return nil
}

func computeBindingCoefficient(
	publicKey *btcec.JacobianPoint,
	aggNonce BinoncePublic,
	message []byte,
	participants []int,
) *btcec.ModNScalar {
	preimage := make([]byte, 32+4+32*len(participants)+33+len(message))

	publicKey.X.PutBytesUnchecked(preimage[0:32])
	binary.BigEndian.PutUint32(preimage[32:32+4], uint32(len(participants)))
	for i, part := range participants {
		new(btcec.ModNScalar).SetInt(uint32(part)).PutBytesUnchecked(preimage[32+4+i*32 : 32+4+(i+1)*32])
	}
	writePointTo(preimage[32+4+len(participants)*32+32:32+4+len(participants)*32+32+33], aggNonce[0])
	copy(preimage[32+4+len(participants)*32+32+33:], message)

	hash := chainhash.TaggedHash([]byte("frost/binding"), preimage)
	s := new(btcec.ModNScalar)
	s.SetBytes((*[32]byte)(hash))

	return s
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

		writePointTo(encoded[base+32:base+32+33], com.BinoncePublic[0])
		writePointTo(encoded[base+32+33:base+32+33+33], com.BinoncePublic[1])
	}

	return encoded
}

func bindFinalNonce(
	groupCommitment BinoncePublic,
	bindingCoeff *btcec.ModNScalar,
) (finalNonce *btcec.JacobianPoint, negate bool) {
	finalNonce = new(btcec.JacobianPoint)

	btcec.ScalarMultNonConst(bindingCoeff, groupCommitment[1], finalNonce)
	btcec.AddNonConst(finalNonce, groupCommitment[0], finalNonce)
	finalNonce.ToAffine()

	if finalNonce.Y.IsOdd() {
		finalNonce.Y.Negate(1)
		finalNonce.Y.Normalize()
		negate = true
	}

	return finalNonce, negate
}

func (c BinoncePublic) Hex() string { return hex.EncodeToString(c.Encode()) }
func (c *BinoncePublic) DecodeHex(x string) error {
	b, err := hex.DecodeString(x)
	if err != nil {
		return err
	}
	return c.Decode(b)
}

func (c BinoncePublic) Encode() []byte {
	out := make([]byte, 33+33)
	c.encodeTo(out)
	return out
}

func (c BinoncePublic) encodeTo(out []byte) {
	writePointTo(out[0:33], c[0])
	writePointTo(out[33:33+33], c[1])
}

func (c *BinoncePublic) Decode(in []byte) error {
	if len(in) < 33+33 {
		return fmt.Errorf("too small")
	}

	if pt, err := btcec.ParsePubKey(in[0:33]); err != nil {
		return fmt.Errorf("failed to decode binding nonce: %w", err)
	} else {
		c[0] = new(btcec.JacobianPoint)
		pt.AsJacobian(c[0])
	}

	if pt, err := btcec.ParsePubKey(in[33 : 33+33]); err != nil {
		return fmt.Errorf("failed to decode hiding nonce: %w", err)
	} else {
		c[1] = new(btcec.JacobianPoint)
		pt.AsJacobian(c[1])
	}

	return nil
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
	out := make([]byte, 2+33+33)

	binary.LittleEndian.PutUint16(out[0:2], uint16(c.SignerID))

	c.BinoncePublic.encodeTo(out[2:])

	return out
}

func (c *Commitment) Decode(in []byte) error {
	if len(in) < 2+33+33 {
		return fmt.Errorf("too small")
	}

	c.SignerID = int(binary.LittleEndian.Uint16(in[0:2]))

	if err := c.BinoncePublic.Decode(in[2:]); err != nil {
		return err
	}

	return nil
}
