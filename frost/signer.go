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
	// The KeyShard holds the signer's secret and public info, such as keys and identifier.
	KeyShard KeyShard

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

// Nonce holds the signing nonces and their commitments. The Signer.Commit() method will generate and record a new nonce and return the Commitment to that nonce. That Commitment will be used in Signer.Sign() and the associated nonces to create a signature shard. Note that nonces and their commitments are agnostic of the upcoming message to sign, and
// can therefore be pre-computed and the commitments shardd before the signing session, saving a round-trip.
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
	secretShard *btcec.ModNScalar,
	pubkey *btcec.JacobianPoint,
) (secNonce *btcec.ModNScalar, pubNonce *btcec.JacobianPoint) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Errorf("failed to read random: %w", err))
	}

	secBytes := secretShard.Bytes()

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

func (s *Signer) genNonceID() uint64 {
	for range 128 {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			// this cannot fail
			panic(fmt.Errorf("FATAL: %w", err))
		}

		cid := binary.LittleEndian.Uint64(buf)
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
	secHN, pubHN := s.generateNonce(s.KeyShard.Secret, s.Configuration.PublicKey)
	secBN, pubBN := s.generateNonce(s.KeyShard.Secret, s.Configuration.PublicKey)

	com := Commitment{
		SignerID:               s.KeyShard.ID,
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
			s.KeyShard.ID,
		)
	}

	if !nonces.HidingNonceCommitment.X.Equals(&com.HidingNonceCommitment.X) &&
		!nonces.HidingNonceCommitment.Y.Equals(&com.HidingNonceCommitment.Y) {
		return fmt.Errorf("invalid hiding nonce in commitment list for signer %d", s.KeyShard.ID)
	}

	if !nonces.BindingNonceCommitment.X.Equals(&com.BindingNonceCommitment.X) &&
		!nonces.BindingNonceCommitment.Y.Equals(&com.BindingNonceCommitment.Y) {
		return fmt.Errorf("invalid binding nonce in commitment list for signer %d", s.KeyShard.ID)
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
	cidx := slices.IndexFunc(commitments, func(c Commitment) bool { return s.KeyShard.ID == c.SignerID })
	if cidx == -1 {
		return fmt.Errorf("signer identifier %d not found in the commitment list", s.KeyShard.ID)
	}

	// Check commitment values for the signer.
	return s.verifyNonces(commitments[cidx])
}

// Sign basically executes steps 3-6 of figure 3: https://eprint.iacr.org/2020/852.pdf (page 15)
func (s *Signer) Sign(message []byte, commitments []Commitment) (*PartialSignature, error) {
	// 3. After receiving (m, B), each Pi first validates the message m, and then checks
	// D`, E` ∈ G∗ for each commitment in B, aborting if either check fails.
	slices.SortFunc(commitments, func(a, b Commitment) int { return cmp.Compare(a.SignerID, b.SignerID) })
	if err := s.VerifyCommitmentList(commitments); err != nil {
		return nil, err
	}

	// (just get our nonces for using later)
	var ourNonces Nonce
	for _, commit := range commitments {
		if commit.SignerID == s.KeyShard.ID {
			commitmentID := commit.CommitmentID
			ourNonces = s.NonceCommitments[commitmentID]
			break
		}
	}

	// 4. Each Pi then computes the set of binding values ρ` = H1(`, m, B), ` ∈ S.
	bindingFactors := commitmentsBindingFactors(commitments, s.Configuration.PublicKey, message)
	// ...Each Pi then derives the group commitment R = Q `∈S D` · (E`) ρ` ,
	groupCommitment := groupCommitment(commitments, bindingFactors)

	// BIP-340 -- because Bitcoin is so great we have to invert stuff here
	if groupCommitment.Y.IsOdd() {
		ourNonces.BindingNonce.Negate()
		ourNonces.HidingNonce.Negate()
		for _, commit := range commitments {
			commit.BindingNonceCommitment.Y.Negate(1)
			commit.BindingNonceCommitment.Y.Normalize()
			commit.HidingNonceCommitment.Y.Negate(1)
			commit.HidingNonceCommitment.Y.Normalize()
		}
	}
	// ~

	// ...and the challenge c = H2(R, Y, m).
	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		groupCommitment.X.Bytes()[:],
		s.Configuration.PublicKey.X.Bytes()[:],
		message,
	)
	challengeScalar := new(btcec.ModNScalar)
	challengeScalar.SetBytes((*[32]byte)(challenge))

	// 5. Each Pi computes their response using their long-lived secret shard si by computing
	// zi = di + (ei · ρi) + λi · si · c, using S to determine the i th Lagrange coefficient λi.
	participants := make([]int, len(commitments))
	for i, c := range commitments {
		participants[i] = c.SignerID
	}
	lambda := s.LambdaRegistry.GetOrNew(s.KeyShard.ID, participants) // Lagrange coefficient λi

	z := new(btcec.ModNScalar).
		Mul2(
			ourNonces.BindingNonce,        // ei
			bindingFactors[s.KeyShard.ID], // ρi
		).
		Add(ourNonces.HidingNonce). // di
		Add(
			new(btcec.ModNScalar).
				Mul2(
					lambda,          // λi
					challengeScalar, // c
				).
				Mul(s.KeyShard.Secret), // si
		)

	// 6. Each Pi securely deletes ((di , Di),(ei , Ei)) from their local storage
	s.clearNonceCommitment(ourNonces.CommitmentID)

	// ...and then returns zi to SA.
	return &PartialSignature{
		SignerIdentifier: s.KeyShard.ID,
		PartialSignature: z,
	}, nil
}
