package frost

import (
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Signer is a participant in a signing group.
type Signer struct {
	// The KeyShare holds the signer's secret and public info, such as keys and identifier.
	KeyShare KeyShare

	// LambdaRegistry records all interpolating values for the signers for different combinations of participant
	// groups. Each group makes up a unique polynomial defined by the participants' identifiers. A value will be
	// computed once for the first time a group is encountered, and kept across encodings and decodings of the signer,
	// accelerating subsequent signatures within the same group of signers.
	LambdaRegistry LambdaRegistry

	// NonceCommitments maps Nonce and their NonceCommitments to their Commitment's identifier.
	NonceCommitments map[uint64]Nonce

	// Configuration is the core FROST setup configuration.
	Configuration *Configuration
}

// Nonce holds the signing nonces and their commitments. The Signer.Commit() method will generate and record a new nonce and return the Commitment to that nonce. That Commitment will be used in Signer.Sign() and the associated nonces to create a signature share. Note that nonces and their commitments are agnostic of the upcoming message to sign, and
// can therefore be pre-computed and the commitments shared before the signing session, saving a round-trip.
type Nonce struct {
	HidingNonce  *btcec.ModNScalar
	BindingNonce *btcec.ModNScalar
	Commitment
}

func (s *Signer) clearNonceCommitment(commitmentID uint64) {
	if com, ok := s.NonceCommitments[commitmentID]; ok {
		com.HidingNonce.Zero()
		com.BindingNonce.Zero()
		com.HidingNonceCommitment.X.Zero()
		com.HidingNonceCommitment.Y.Zero()
		com.HidingNonceCommitment.Z.Zero()
		com.BindingNonceCommitment.X.Zero()
		com.BindingNonceCommitment.Y.Zero()
		com.BindingNonceCommitment.Z.Zero()
		delete(s.NonceCommitments, commitmentID)
	}
}

func (s *Signer) generateNonce(
	secretShare *btcec.ModNScalar,
	pubkey *btcec.JacobianPoint,
) (secNonce *btcec.ModNScalar, pubNonce *btcec.JacobianPoint) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Errorf("failed to read random: %w", err))
	}

	secBytes := secretShare.Bytes()

	xoredRandom := chainhash.TaggedHash([]byte("FROST/aux"), random[:])
	// xor
	for i, b := range secBytes[:] {
		xoredRandom[i] ^= b
	}
	random = *xoredRandom

	// k1/k2 preparation
	noncePreimage := make([]byte, 32+32+33+1)
	copy(noncePreimage, random[:])
	copy(noncePreimage[32:], secBytes[:])

	writePointTo(noncePreimage[32+32:], pubkey)

	// k1
	noncePreimage[32+32+33] = 1
	nonceHash1 := chainhash.TaggedHash([]byte("FROST/nonce"), noncePreimage)
	k1 := new(btcec.ModNScalar)
	k1.SetBytes((*[32]byte)(nonceHash1))

	// k2
	noncePreimage[32+32+33] = 2
	nonceHash2 := chainhash.TaggedHash([]byte("FROST/nonce"), noncePreimage)
	k2 := new(btcec.ModNScalar)
	k2.SetBytes((*[32]byte)(nonceHash2))

	// zero stuff
	for i := range noncePreimage {
		noncePreimage[i] = 0
	}
	for i := range secBytes {
		secBytes[i] = 0
	}

	Rs1 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(k1, Rs1)
	Rs2 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(k2, Rs2)
	pt := new(btcec.JacobianPoint)
	btcec.AddNonConst(Rs1, Rs2, pt)
	pt.ToAffine()

	return k1.Add(k2), pt
}

func randomCommitmentID() uint64 {
	buf := make([]byte, 8)

	// In the extremely rare and unlikely case the CSPRNG returns, panic. It's over.
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("FATAL: %w", err))
	}

	return binary.LittleEndian.Uint64(buf)
}

func (s *Signer) genNonceID() uint64 {
	var cid uint64

	// In the extremely rare and unlikely case the CSPRNG returns an already registered ID, we try again 128 times max
	// before failing. CSPRNG is a serious issue at which point protocol execution must be stopped.
	for range 128 {
		cid = randomCommitmentID()
		if _, exists := s.NonceCommitments[cid]; !exists {
			return cid
		}
	}

	panic("FATAL: CSPRNG could not generate unique commitment identifiers over 128 iterations")
}

// Commit generates a signer's nonces and commitment, to be used in the second FROST round. The internal nonce must
// be kept secret, and the returned commitment sent to the signature aggregator.
func (s *Signer) Commit() Commitment {
	cid := s.genNonceID()
	secHN, pubHN := s.generateNonce(s.KeyShare.Secret, s.Configuration.PublicKey)
	secBN, pubBN := s.generateNonce(s.KeyShare.Secret, s.Configuration.PublicKey)

	x := make([]byte, 32)
	x[0] = 6
	secHN.SetByteSlice(x)
	btcec.ScalarBaseMultNonConst(secHN, pubHN)
	pubHN.ToAffine()

	secBN.SetByteSlice(x)
	btcec.ScalarBaseMultNonConst(secBN, pubBN)
	pubBN.ToAffine()

	com := Commitment{
		SignerID:               s.KeyShare.ID,
		CommitmentID:           cid,
		HidingNonceCommitment:  pubHN,
		BindingNonceCommitment: pubBN,
	}
	s.NonceCommitments[cid] = Nonce{
		HidingNonce:  secHN,
		BindingNonce: secBN,
		Commitment:   com,
	}

	return com
}

func (s *Signer) verifyNonces(com Commitment) error {
	nonces, ok := s.NonceCommitments[com.CommitmentID]
	if !ok {
		return fmt.Errorf(
			"the commitment identifier %d for signer %d in the commitments is unknown to the signer",
			com.CommitmentID,
			s.KeyShare.ID,
		)
	}

	if !nonces.HidingNonceCommitment.X.Equals(&com.HidingNonceCommitment.X) &&
		!nonces.HidingNonceCommitment.Y.Equals(&com.HidingNonceCommitment.Y) {
		return fmt.Errorf("invalid hiding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	if !nonces.BindingNonceCommitment.X.Equals(&com.BindingNonceCommitment.X) &&
		!nonces.BindingNonceCommitment.Y.Equals(&com.BindingNonceCommitment.Y) {
		return fmt.Errorf("invalid binding nonce in commitment list for signer %d", s.KeyShare.ID)
	}

	return nil
}

// VerifyCommitmentList checks for the Commitment list integrity and the signer's commitment. This function must not
// return an error for Sign to succeed.
func (s *Signer) VerifyCommitmentList(commitments []Commitment) error {
	// Validate general consistency of the commitment list.
	if err := s.Configuration.ValidateCommitmentList(commitments); err != nil {
		return fmt.Errorf("invalid list of commitments: %w", err)
	}

	// The signer's id must be among the commitments.
	cidx := slices.IndexFunc(commitments, func(c Commitment) bool { return s.KeyShare.ID == c.SignerID })
	if cidx == -1 {
		return fmt.Errorf("signer identifier %d not found in the commitment list", s.KeyShare.ID)
	}

	// Check commitment values for the signer.
	return s.verifyNonces(commitments[cidx])
}

// Sign produces a participant's signature share of the message msg. The CommitmentList must contain a Commitment
// produced on a previous call to Commit(). Once the signature share with Sign() is produced, the internal commitment
// and nonces are cleared and another call to Sign() with the same Commitment will return an error.
func (s *Signer) Sign(message []byte, commitments []Commitment) (*PartialSignature, error) {
	slices.SortFunc(commitments, func(a, b Commitment) int { return cmp.Compare(a.SignerID, b.SignerID) })

	if err := s.VerifyCommitmentList(commitments); err != nil {
		return nil, err
	}

	bindingFactors := commitmentsBindingFactors(commitments, s.Configuration.PublicKey, message)
	groupCommitment := groupCommitment(commitments, bindingFactors)

	participants := make([]int, len(commitments))
	for i, c := range commitments {
		participants[i] = c.SignerID
	}

	lambda := s.LambdaRegistry.GetOrNew(s.KeyShare.ID, participants)

	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		groupCommitment.X.Bytes()[:],
		s.Configuration.PublicKey.X.Bytes()[:],
		message,
	)
	challengeScalar := new(btcec.ModNScalar)
	challengeScalar.SetBytes((*[32]byte)(challenge))
	lambdaChall := new(btcec.ModNScalar).Mul2(lambda, challengeScalar)

	var commitment Commitment
	for _, com := range commitments {
		if com.SignerID == s.KeyShare.ID {
			commitment = com
			break
		}
	}

	commitmentID := commitment.CommitmentID
	com := s.NonceCommitments[commitmentID]

	// compute the signature share: h + b*f + l*s
	bindingFactor := bindingFactors[s.KeyShare.ID]
	sigShare := new(btcec.ModNScalar).Add2(
		com.HidingNonce,
		new(btcec.ModNScalar).Mul2(bindingFactor, com.BindingNonce),
	).
		Add(lambdaChall.Mul(s.KeyShare.Secret))

	s.clearNonceCommitment(commitmentID)

	return &PartialSignature{
		SignerIdentifier: s.KeyShare.ID,
		PartialSignature: sigShare,
	}, nil
}
