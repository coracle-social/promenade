package frost

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// AggregateSignatures enables a coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid, deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the signer from the set of allowed participants in future runs of FROST. If verify
// is set to true, AggregateSignatures will automatically verify the signature shares, and will return an error on the
// first encountered invalid signature share.
func (c *Configuration) AggregateSignatures(
	message []byte,
	partialSigs []PartialSignature,
	commitments []Commitment,
) (*schnorr.Signature, error) {
	if !c.initialized {
		return nil, fmt.Errorf("configuration must be initialized")
	}

	groupCommitment, _, _, err := c.preparePartialSignatureVerification(message, commitments)
	if err != nil {
		return nil, err
	}

	signature, err := c.sumShares(partialSigs, groupCommitment)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (c *Configuration) sumShares(shares []PartialSignature, groupCommitment *btcec.JacobianPoint) (*schnorr.Signature, error) {
	z := new(btcec.ModNScalar)

	for _, partialSig := range shares {
		if partialSig.PartialSignature == nil || partialSig.PartialSignature.IsZero() {
			return nil, errors.New("invalid signature share (nil or zero scalar)")
		}

		z.Add(partialSig.PartialSignature)
	}

	return schnorr.NewSignature(&groupCommitment.X, z), nil
}

// VerifyPartialSignature verifies a signature share. partialSig is the signer's signature share to be verified.
//
// The CommitmentList must be sorted in ascending order by identifier.
func (c *Configuration) VerifyPartialSignature(
	partialSig PartialSignature,
	message []byte,
	commitments []Commitment,
) error {
	if !c.initialized {
		return fmt.Errorf("configuration must be initialized")
	}

	groupCommitment, bindingFactors, participants, err := c.preparePartialSignatureVerification(message, commitments)
	if err != nil {
		return err
	}

	return c.verifyPartialSignature(partialSig, message, commitments, participants, groupCommitment, bindingFactors)
}

func (c *Configuration) preparePartialSignatureVerification(message []byte, commitments []Commitment) (
	groupCommit *btcec.JacobianPoint,
	bindingFactors map[int]*btcec.ModNScalar,
	participants []*btcec.ModNScalar,
	err error,
) {
	slices.SortFunc(commitments, func(a, b Commitment) int { return cmp.Compare(a.SignerID, b.SignerID) })

	// Validate general consistency of the commitment list.
	if err := c.ValidateCommitmentList(commitments); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid list of commitments: %w", err)
	}

	bindingFactors = commitmentsBindingFactors(commitments, c.PublicKey, message)
	groupCommit = groupCommitment(commitments, bindingFactors)

	participants = makePolynomialFromListFunc(commitments, func(c Commitment) *btcec.ModNScalar {
		s := new(btcec.ModNScalar)
		s.SetInt(uint32(c.SignerID))
		return s
	})

	return groupCommit, bindingFactors, participants, nil
}

func (c *Configuration) validatePartialSignatureExtensive(partialSig PartialSignature) error {
	if partialSig.PartialSignature == nil || partialSig.PartialSignature.IsZero() {
		return errors.New("invalid signature share (nil or zero scalar)")
	}

	if partialSig.SignerIdentifier == 0 || partialSig.SignerIdentifier > c.MaxSigners {
		return fmt.Errorf("identifier can't be zero or bigger than the max number of signers")
	}

	idx := slices.IndexFunc(c.SignerPublicKeyShares, func(pks PublicKeyShare) bool { return pks.ID == partialSig.SignerIdentifier })
	if idx == -1 {
		return fmt.Errorf("no public key registered for signer %d", partialSig.SignerIdentifier)
	}

	return nil
}

func (c *Configuration) verifyPartialSignature(
	partialSig PartialSignature,
	message []byte,
	commitments []Commitment,
	participants []*btcec.ModNScalar,
	groupCommitment *btcec.JacobianPoint,
	bindingFactors map[int]*btcec.ModNScalar,
) error {
	if err := c.validatePartialSignatureExtensive(partialSig); err != nil {
		return err
	}

	idx := slices.IndexFunc(commitments, func(commit Commitment) bool { return commit.SignerID == partialSig.SignerIdentifier })
	if idx == -1 {
		return fmt.Errorf("commitment for signer %d is missing", partialSig.SignerIdentifier)
	}
	commit := commitments[idx]

	pkidx := slices.IndexFunc(c.SignerPublicKeyShares, func(pks PublicKeyShare) bool { return pks.ID == partialSig.SignerIdentifier })
	pk := c.SignerPublicKeyShares[pkidx].PublicKey

	lambda := ComputeLambda(partialSig.SignerIdentifier, participants)
	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		groupCommitment.X.Bytes()[:],
		c.PublicKey.X.Bytes()[:],
		message,
	)
	challengeScalar := new(btcec.ModNScalar)
	challengeScalar.SetBytes((*[32]byte)(challenge))
	lambdaChall := new(btcec.ModNScalar).Mul2(lambda, challengeScalar)

	// commitment KeyShare: r = g(h + b*f + l*s)
	bindingFactor := bindingFactors[partialSig.SignerIdentifier]
	// commShare := commit.HidingNonceCommitment.Copy().Add(commit.BindingNonceCommitment.Copy().Multiply(bindingFactor))

	bncbf := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(bindingFactor, commit.BindingNonceCommitment, bncbf)

	commShare := new(btcec.JacobianPoint)
	btcec.AddNonConst(bncbf, commit.HidingNonceCommitment, commShare)

	r := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(lambdaChall, pk, r)
	btcec.AddNonConst(r, commShare, r)
	r.ToAffine()

	l := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(partialSig.PartialSignature, l)
	l.ToAffine()

	if !l.X.Equals(&r.X) || !l.Y.Equals(&r.Y) {
		return fmt.Errorf("invalid signature share for signer %d", partialSig.SignerIdentifier)
	}

	return nil
}

type PartialSignature struct {
	PartialSignature *btcec.ModNScalar
	SignerIdentifier int
}

func (s *PartialSignature) Encode() []byte {
	out := make([]byte, 2+32)

	binary.LittleEndian.PutUint16(out[0:2], uint16(s.SignerIdentifier))
	s.PartialSignature.PutBytesUnchecked(out[2:])

	return out
}

func (s *PartialSignature) Decode(in []byte) error {
	if len(in) < 32+2 {
		return fmt.Errorf("too small")
	}

	s.SignerIdentifier = int(binary.LittleEndian.Uint16(in[0:2]))

	s.PartialSignature = new(btcec.ModNScalar)
	s.PartialSignature.SetBytes((*[32]byte)(in[2 : 2+32]))

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
