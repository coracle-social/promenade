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

func (c *Configuration) VerifyPartialSignature(
	pks PublicKeyShard,
	commit BinoncePublic,
	bindingCoefficient *btcec.ModNScalar,
	finalNonce *btcec.JacobianPoint,
	partialSig PartialSignature,
	message []byte,
	lambdaRegistry LambdaRegistry,
) error {
	if partialSig.Value == nil || partialSig.Value.IsZero() {
		return fmt.Errorf("invalid signature shard (nil or zero scalar): %v", partialSig.Value)
	}

	if partialSig.SignerIdentifier == 0 || partialSig.SignerIdentifier > c.MaxSigners {
		return fmt.Errorf("identifier can't be zero or bigger than the max number of signers")
	}

	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		finalNonce.X.Bytes()[:],
		c.PublicKey.X.Bytes()[:],
		message,
	)

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
	sAux := new(btcec.ModNScalar)
	sAux.SetBytes((*[32]byte)(challenge))
	sAux.Mul(lambdaRegistry.getOrNew(c.Participants, partialSig.SignerIdentifier))

	// b * R2
	leftSide := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(bindingCoefficient, commit[1], leftSide)

	// R1 + b * R2
	btcec.AddNonConst(leftSide, commit[0], leftSide)

	// (c * lambda) * X
	aux := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(sAux, pks.PublicKey, aux)

	// R1 + b * R2 + (c * lambda) * X
	btcec.AddNonConst(leftSide, aux, leftSide)

	// s * G
	rightSide := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(partialSig.Value, rightSide)

	// R1 + b * R2 + (c * lambda) * X == s * G
	leftSide.ToAffine()
	rightSide.ToAffine()
	if !leftSide.X.Equals(&rightSide.X) || !leftSide.Y.Equals(&rightSide.Y) {
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
