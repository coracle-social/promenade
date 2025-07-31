package frost

import (
	"encoding/hex"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var lambdaRegistry = make(LambdaRegistry)

func FuzzFrostTrustedKeyDealAndSigning(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, 3, 5, []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0}, 0, []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc1})

	f.Fuzz(func(t *testing.T,
		secretKeyBytes []byte,
		threshold,
		maxSigners int,
		messageBytes []byte,
		seed int,
		sessionId []byte,
	) {
		// validate inputs to avoid panics
		if len(secretKeyBytes) != 32 {
			t.Skip("secret key must be 32 bytes")
		}
		if len(messageBytes) != 32 {
			t.Skip("message must be 32 bytes")
		}
		if len(sessionId) != 32 {
			t.Skip("session id must be 32 bytes")
		}
		sessionIdHex := hex.EncodeToString(sessionId)
		if threshold < 2 || threshold > 10 {
			t.Skip("threshold must be between 2 and 10")
		}
		if maxSigners < threshold || maxSigners > 10 {
			t.Skip("maxSigners must be >= threshold and <= 10")
		}

		// create secret key from fuzz input
		secret := new(btcec.ModNScalar)
		overflow := secret.SetByteSlice(secretKeyBytes)
		if overflow {
			t.Skip("secret key overflow")
		}
		if secret.IsZero() {
			t.Skip("secret key is zero")
		}

		rnd := rand.New(rand.NewPCG(uint64(seed), 0))

		// perform trusted key deal
		shards, pubkey, commits := TrustedKeyDeal(secret, threshold, maxSigners)

		// shuffle shards
		rnd.Shuffle(len(shards), func(i, j int) {
			shards[i], shards[j] = shards[j], shards[i]
		})

		// basic validation of key deal results
		if len(shards) != maxSigners {
			t.Fatalf("expected %d shards, got %d", maxSigners, len(shards))
		}
		if len(commits) != threshold {
			t.Fatalf("expected %d commits, got %d", threshold, len(commits))
		}
		if pubkey == nil {
			t.Fatal("pubkey is nil")
		}

		// validate that each shard has correct structure
		for i, shard := range shards {
			if shard.Secret == nil || shard.Secret.IsZero() {
				t.Fatalf("shard %d has nil or zero secret", i)
			}
			if shard.PublicKey == nil {
				t.Fatalf("shard %d has nil public key", i)
			}
		}

		// test signing with a subset of signers (threshold number)
		participants := make([]int, threshold)
		for i := 0; i < threshold; i++ {
			participants[i] = shards[i].PublicKeyShard.ID
		}

		// create configuration
		cfg := &Configuration{
			Threshold:    threshold,
			MaxSigners:   maxSigners,
			PublicKey:    pubkey,
			Participants: participants,
		}

		// create signers
		signers := make([]*Signer, threshold)
		for i := 0; i < threshold; i++ {
			signer, err := cfg.Signer(shards[i], make(LambdaRegistry))
			if err != nil {
				t.Fatalf("failed to create signer %d: %v", i, err)
			}
			signers[i] = signer
		}

		// shuffle signers
		rnd.Shuffle(len(signers), func(i, j int) {
			signers[i], signers[j] = signers[j], signers[i]
		})

		// generate commitments
		commitments := make([]Commitment, threshold)
		for i, signer := range signers {
			commitments[i] = signer.Commit(sessionIdHex)
		}

		// compute group commitment
		groupCommitment, bindingCoefficient, finalNonce := cfg.ComputeGroupCommitment(commitments, messageBytes)

		// shuffle signers again
		rnd.Shuffle(len(signers), func(i, j int) {
			signers[i], signers[j] = signers[j], signers[i]
		})

		// generate partial signatures
		partialSigs := make([]PartialSignature, threshold)
		for i, signer := range signers {
			partialSig, err := signer.Sign(messageBytes, groupCommitment)
			if err != nil {
				t.Fatalf("failed to sign with signer %d: %v", i, err)
			}
			partialSigs[i] = partialSig
		}

		// verify each partial signature
		for i, partialSig := range partialSigs {
			signerID := partialSig.SignerIdentifier
			shard := shards[slices.IndexFunc(shards, func(s KeyShard) bool {
				return s.ID == signerID
			})]
			pubkeyShard := shard.PublicKeyShard
			commit := commitments[slices.IndexFunc(commitments, func(c Commitment) bool {
				return c.SignerID == signerID
			})]
			err := cfg.VerifyPartialSignature(
				pubkeyShard,
				commit.BinoncePublic,
				bindingCoefficient,
				finalNonce,
				partialSig,
				messageBytes,
				lambdaRegistry,
			)
			if err != nil {
				t.Fatalf("partial signature %d verification failed: %v", i, err)
			}
		}

		// aggregate signatures
		signature, err := cfg.AggregateSignatures(finalNonce, partialSigs)
		if err != nil {
			t.Fatalf("failed to aggregate signatures: %v", err)
		}

		// verify final signature
		pk, err := schnorr.ParsePubKey(pubkey.X.Bytes()[:])
		if err != nil {
			t.Fatalf("failed to parse public key: %v", err)
		}

		if !signature.Verify(messageBytes, pk) {
			t.Fatal("final signature verification failed")
		}

		// test encoding/decoding of key components
		testEncodingDecoding(t, shards[0], commitments[0], partialSigs[0], cfg)
	})
}

func testEncodingDecoding(t *testing.T, shard KeyShard, commitment Commitment, partialSig PartialSignature, cfg *Configuration) {
	// test keyshard encoding/decoding
	shardBytes := shard.Encode()
	decodedShard := KeyShard{}
	if err := decodedShard.Decode(shardBytes); err != nil {
		t.Fatalf("failed to decode shard: %v", err)
	}
	if !shard.Secret.Equals(decodedShard.Secret) {
		t.Fatal("shard secret mismatch after encoding/decoding")
	}

	// test commitment encoding/decoding
	commitBytes := commitment.Encode()
	decodedCommit := Commitment{}
	if err := decodedCommit.Decode(commitBytes); err != nil {
		t.Fatalf("failed to decode commitment: %v", err)
	}
	if decodedCommit.SignerID != commitment.SignerID {
		t.Fatal("commitment signer ID mismatch after encoding/decoding")
	}

	// test partialsignature encoding/decoding
	partialSigBytes := partialSig.Encode()
	decodedPartialSig := PartialSignature{}
	if err := decodedPartialSig.Decode(partialSigBytes); err != nil {
		t.Fatalf("failed to decode partial signature: %v", err)
	}
	if !partialSig.Value.Equals(decodedPartialSig.Value) {
		t.Fatal("partial signature value mismatch after encoding/decoding")
	}

	// test configuration encoding/decoding
	cfgBytes := cfg.Encode()
	decodedCfg := Configuration{}
	if err := decodedCfg.Decode(cfgBytes); err != nil {
		t.Fatalf("failed to decode configuration: %v", err)
	}
	if decodedCfg.Threshold != cfg.Threshold {
		t.Fatal("configuration threshold mismatch after encoding/decoding")
	}
}
