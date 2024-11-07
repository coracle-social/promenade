package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type ParticipantError struct {
	cfg *frost.Configuration

	index  int
	reason string
}

func (pe ParticipantError) Error() string {
	part := pe.cfg.Participants[pe.index]
	return fmt.Sprintf("participant %d (id %d) failed: %s", pe.index, part, pe.reason)
}

func main() {
	message := make([]byte, 32)
	secretKey := make([]byte, 32)

	rand.Read(message)
	rand.Read(secretKey)

	flow(
		context.Background(),
		4,
		7,
		message,
		secretKey,
	)
}

func flow(
	ctx context.Context,
	threshold int,
	totalSigners int,
	message []byte,
	secretKey []byte,
) {
	secret := new(btcec.ModNScalar)
	secret.SetByteSlice(secretKey)

	shards, pubkey, _ := frost.TrustedKeyDeal(secret, threshold, totalSigners)

	pubkeyShards := make([]frost.PublicKeyShard, len(shards))
	participants := make([]int, threshold)
	for s, shard := range shards {
		shareableHex := shard.PublicKeyShard.Hex()
		pubkeyShards[s] = frost.PublicKeyShard{}
		if err := pubkeyShards[s].DecodeHex(shareableHex); err != nil {
			panic(err)
		}
	}
	fmt.Println("pubkey:", hexPoint(pubkey)[2:])
	fmt.Println("shards:", len(shards))

	// decide who is going to sign
	signers := make([]chan string, threshold)
	for s := range signers {
		ch := make(chan string)
		go signer(ch, shards[s])
		signers[s] = ch

		participants[s] = shards[s].PublicKeyShard.ID
	}

	// start signing process
	cfg := &frost.Configuration{
		Threshold:    threshold,
		MaxSigners:   totalSigners,
		PublicKey:    pubkey,
		Participants: participants,
	}

	fmt.Println("message:", hex.EncodeToString(message))

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sig, err := coordinator(ctx, cfg, pubkeyShards, signers, message)
	if err != nil {
		panic(err)
	}

	fmt.Println("signature:", hex.EncodeToString(sig))

	sigp, _ := schnorr.ParseSignature(sig)
	pk, _ := schnorr.ParsePubKey(pubkey.X.Bytes()[:])
	fmt.Println("valid:", sigp.Verify(message, pk))
}

func coordinator(
	ctx context.Context,
	cfg *frost.Configuration,
	pubkeyShards []frost.PublicKeyShard,
	signers []chan string,
	message []byte,
) ([]byte, error) {
	// step-1 (send): initialize each participant
	cfgHex := cfg.Hex()
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout sending config"}
		case ch <- cfgHex:
		}
	}

	// step-2 (receive): get all pre-commits from signers
	commitments := make([]frost.Commitment, cfg.Threshold)
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout receiving commit"}
		case msg := <-ch:
			commit := frost.Commitment{}
			if err := commit.DecodeHex(msg); err != nil {
				return nil, err
			}
			commitments[s] = commit
		}
	}

	// step-3 (send): send group commitment and message to all signers
	groupCommitment, bindingCoefficient, finalNonce := cfg.ComputeGroupCommitment(commitments, message)

	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout sending group commit"}
		case ch <- groupCommitment.Hex():
		}

		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout sending message"}
		case ch <- hex.EncodeToString(message):
		}
	}

	// step-4 (receive): get partial signature from each participant
	partialSigs := make([]frost.PartialSignature, len(signers))
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout receiving partial signature"}
		case msg := <-ch:
			partialSig := frost.PartialSignature{}
			if err := partialSig.DecodeHex(msg); err != nil {
				return nil, err
			}
			partialSigs[s] = partialSig
		}
	}

	// aggregate signature
	signature, err := cfg.AggregateSignatures(finalNonce, partialSigs)
	if err != nil {
		return nil, err
	}

	// identify foul players if the signature is not good
	if ok := signature.Verify(message, btcec.NewPublicKey(&cfg.PublicKey.X, &cfg.PublicKey.Y)); !ok {
		for s, partialSig := range partialSigs {
			// get specific pubkeyshard for this signer
			idx := slices.IndexFunc(pubkeyShards, func(pks frost.PublicKeyShard) bool {
				return pks.ID == partialSig.SignerIdentifier
			})
			if idx == -1 {
				return nil, ParticipantError{cfg, s, "signature from unknown pubkeyshard"}
			}
			pubkeyShard := pubkeyShards[idx]

			// get specific commit for this signer
			idx = slices.IndexFunc(commitments, func(commit frost.Commitment) bool {
				return commit.SignerID == partialSig.SignerIdentifier
			})
			if idx == -1 {
				return nil, ParticipantError{cfg, s, "signature without a corresponding commit"}
			}
			commit := commitments[idx]

			if err := cfg.VerifyPartialSignature(
				pubkeyShard,
				commit.BinoncePublic,
				bindingCoefficient,
				finalNonce,
				partialSig,
				message,
			); err != nil {
				return nil, ParticipantError{cfg, s, "invalid partial signature: " + err.Error()}
			}
		}

		return nil, fmt.Errorf("signature %x is bad", signature.Serialize())
	}

	return signature.Serialize(), nil
}

func signer(ch chan string, shard frost.KeyShard) {
	// step-1 (receive): initialize ourselves
	cfg := frost.Configuration{}
	if err := cfg.DecodeHex(<-ch); err != nil {
		panic(err)
	}

	signer, err := cfg.Signer(shard)
	if err != nil {
		panic(err)
	}

	// step-2 (send): send our pre-commit to coordinator
	ourCommitment := signer.Commit("<session-id-must-be-unique>")
	ch <- ourCommitment.Hex()

	// step-3 (receive): get group commitment from other signers and the message to be signed
	var groupCommitment frost.BinoncePublic
	var message []byte
	for {
		msg := <-ch
		if len(msg) == 64 {
			message, err = hex.DecodeString(msg)
			if err != nil {
				panic(err)
			}
		} else {
			if err := groupCommitment.DecodeHex(msg); err != nil {
				panic(err)
			}
		}

		if len(message) == 32 && !groupCommitment[0].X.IsZero() {
			break
		}
	}

	// step-4 (send): sign and shard our partial signature
	partialSig, err := signer.Sign(message, groupCommitment)
	if err != nil {
		panic(err)
	}
	ch <- partialSig.Hex()
}
