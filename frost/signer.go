package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

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

	// Configuration is the core FROST setup configuration.
	Configuration *Configuration

	// SecretNonces are our secret nonces for this session.
	SecretNonces BinonceSecret
}

func (s *Signer) clearNonceCommitment() {
	s.SecretNonces[0] = nil
	s.SecretNonces[1] = nil
}

func (s *Signer) generateNonce(
	sessionId string,
	secretShard *btcec.ModNScalar,
	pubkey *btcec.JacobianPoint,
) (secNonce *btcec.ModNScalar, pubNonce *btcec.JacobianPoint) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Errorf("failed to read random: %w", err))
	}

	// xor hashed random with secret
	secBytes := secretShard.Bytes()
	xoredRandom := sha256.Sum256(random[:])
	for i, b := range secBytes[:] {
		xoredRandom[i] ^= b
	}
	random = xoredRandom

	// add this together with more stuff into a final hash
	noncePreimage := make([]byte, 32+33+2+len(sessionId))
	copy(noncePreimage[0:32], random[:])
	writePointTo(noncePreimage[32:32+33], pubkey)
	binary.BigEndian.PutUint16(noncePreimage[32+33:32+33+2], uint16(len(sessionId)))
	copy(noncePreimage[32+33+2:], []byte(sessionId))
	kH := sha256.Sum256(noncePreimage)

	// use that as the secret nonce, take its point for the pubnonce
	k := new(btcec.ModNScalar)
	k.SetBytes(&kH)
	pt := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(k, pt)
	pt.ToAffine()

	// zero stuff
	for i := range kH {
		kH[i] = 0
	}
	for i := range noncePreimage {
		noncePreimage[i] = 0
	}
	for i := range secBytes {
		secBytes[i] = 0
	}

	return k, pt
}

// Commit generates a signer's nonces and commitment, to be used in the second FROST round. The internal nonce must
// be kept secret, and the returned commitment sent to the signature aggregator.
func (s *Signer) Commit(sessionId string) Commitment {
	secHN, pubHN := s.generateNonce(sessionId+"h", s.KeyShard.Secret, s.Configuration.PublicKey)
	secBN, pubBN := s.generateNonce(sessionId+"b", s.KeyShard.Secret, s.Configuration.PublicKey)

	com := Commitment{
		SignerID:      s.KeyShard.ID,
		BinoncePublic: BinoncePublic{pubHN, pubBN},
	}
	s.SecretNonces = BinonceSecret{secHN, secBN}

	return com
}

func (s *Signer) Sign(
	message []byte,
	groupCommitment BinoncePublic,
) (*PartialSignature, error) {
	// SignRound(ski, pk, S, statei, ρ, m) -- from https://eprint.iacr.org/2023/899.pdf

	// 6 : b ← Hnon(X, S, ρ, m)
	bindingCoefficient := computeBindingCoefficient(
		s.Configuration.PublicKey, groupCommitment, message, s.Configuration.Participants)

	// 7 : R ← DEb
	finalNonce, negate := bindFinalNonce(groupCommitment, bindingCoefficient)

	// BIP-340 special
	if negate {
		s.SecretNonces[0].Negate()
		s.SecretNonces[1].Negate()
	}

	// 8 : c ← Hsig(X, R, m)
	challenge := chainhash.TaggedHash(chainhash.TagBIP0340Challenge,
		finalNonce.X.Bytes()[:],
		s.Configuration.PublicKey.X.Bytes()[:],
		message,
	)
	challengeScalar := new(btcec.ModNScalar)
	challengeScalar.SetBytes((*[32]byte)(challenge))

	// 9 : Λi ← Lagrange(S, i)
	lambda := s.LambdaRegistry.GetOrNew(s.Configuration.Participants, s.KeyShard.ID) // Lagrange coefficient λi

	// 10 : σi ← di + bei + cΛixi
	z := new(btcec.ModNScalar).
		Mul2(
			s.SecretNonces[1],  // ei
			bindingCoefficient, // ρi
		).
		Add(s.SecretNonces[0]). // di
		Add(
			new(btcec.ModNScalar).
				Mul2(
					lambda,          // λi
					challengeScalar, // c
				).
				Mul(s.KeyShard.Secret), // si
		)

	s.clearNonceCommitment()

	// 11 : return σi
	return &PartialSignature{
		SignerIdentifier: s.KeyShard.ID,
		Value:            z,
	}, nil
}
