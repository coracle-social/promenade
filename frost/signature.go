package frost

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func (c *Configuration) AggregateSignatures(
	finalNonce *btcec.JacobianPoint,
	partialSigs []PartialSignature,
) (*schnorr.Signature, error) {
	// SignAgg(pk, ρ, {σi}i∈S, m) -- https://eprint.iacr.org/2023/899.pdf, page 15

	// 5 : s ′ ← ∑∈S σi
	z := new(btcec.ModNScalar)
	for _, partialSig := range partialSigs {
		if partialSig.Value == nil || partialSig.Value.IsZero() {
			return nil, errors.New("invalid signature shard (nil or zero scalar)")
		}
		z.Add(partialSig.Value)
	}

	return schnorr.NewSignature(&finalNonce.X, z), nil
}

func (c *Configuration) validatePartialSignatureExtensive(partialSig PartialSignature) error {
	if partialSig.Value == nil || partialSig.Value.IsZero() {
		return errors.New("invalid signature shard (nil or zero scalar)")
	}

	if partialSig.SignerIdentifier == 0 || partialSig.SignerIdentifier > c.MaxSigners {
		return fmt.Errorf("identifier can't be zero or bigger than the max number of signers")
	}

	return nil
}

func (c *Configuration) VerifyPartialSignature(
	pks PublicKeyShard,
	commit BinoncePublic,
	bindingCoefficient *btcec.ModNScalar,
	finalNonce *btcec.JacobianPoint,
	partialSig PartialSignature,
	message []byte,
) error {
	if err := c.validatePartialSignatureExtensive(partialSig); err != nil {
		return err
	}

	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		finalNonce.X.Bytes()[:],
		c.PublicKey.X.Bytes()[:],
		message,
	)
	challengeScalar := new(btcec.ModNScalar)
	challengeScalar.SetBytes((*[32]byte)(challenge))

	// copied from https://github.com/LLFourn/secp256kfun/blob/8e6fd712717692d475287f4a964be57c8584f54e/schnorr_fun/src/frost/session.rs#L93
	// R1, R2 = nonces
	// b = bindingCoefficient
	// c = challenge
	// lambda = lambda
	// X = pks.PublicKey
	// s = partialSig.Value
	// G = base
	//
	// R1 + b * R2 + (c * lambda) * X - s * G

	// (c * lambda)
	first := ComputeLambda(partialSig.SignerIdentifier, c.Participants)
	first.Mul(challengeScalar)

	// b * R2
	second := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(bindingCoefficient, commit[1], second)

	// R1 + b * R2
	third := new(btcec.JacobianPoint)
	btcec.AddNonConst(second, commit[0], third)

	// (c * lambda) * X
	fourth := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(first, pks.PublicKey, fourth)

	// b * R2 + (c * lambda) * X
	btcec.AddNonConst(fourth, second, fourth)
	fourth.ToAffine()

	// s * G
	fifth := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(partialSig.Value, fifth)
	fifth.ToAffine()

	// R1 + b * R2 + (c * lambda) * X == s * G
	if !fourth.X.Equals(&fifth.X) || !fourth.Y.Equals(&fifth.Y) {
		return fmt.Errorf("invalid signature shard for signer %d", partialSig.SignerIdentifier)
	}

	return nil
}

type PartialSignature struct {
	Value            *btcec.ModNScalar
	SignerIdentifier int
}

func (s *PartialSignature) Encode() []byte {
	out := make([]byte, 2+32)

	binary.LittleEndian.PutUint16(out[0:2], uint16(s.SignerIdentifier))
	s.Value.PutBytesUnchecked(out[2 : 2+32])

	return out
}

func (s *PartialSignature) Decode(in []byte) error {
	if len(in) < 32+2 {
		return fmt.Errorf("too small")
	}

	s.SignerIdentifier = int(binary.LittleEndian.Uint16(in[0:2]))

	s.Value = new(btcec.ModNScalar)
	s.Value.SetBytes((*[32]byte)(in[2 : 2+32]))

	return nil
}

func (s *PartialSignature) Hex() string { return hex.EncodeToString(s.Encode()) }
func (s *PartialSignature) DecodeHex(x string) error {
	b, err := hex.DecodeString(x)
	if err != nil {
		return err
	}
	return s.Decode(b)
}
