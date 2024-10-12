package main

import (
	"context"
	"encoding/hex"
	"fmt"
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
	pks := pe.cfg.SignerPublicKeyShares[pe.index]
	return fmt.Sprintf("participant %d (%x/%d) failed: %s", pe.index, btcec.NewPublicKey(&pks.PublicKey.X, &pks.PublicKey.Y).SerializeCompressed(), pks.ID, pe.reason)
}

func main() {
	flow(
		context.Background(),
		2,
		2,
		"443db1f4d0e6761a4f43809cc04e21aed1e206317589c24032d366646e48c5fe",
		"a79fc3461f156c087eee20d8a79624a55cb02690eb062e871b824306b8f51896",
	)
}

func flow(
	ctx context.Context,
	threshold int,
	totalSigners int,
	messageHex string,
	secretKey string,
) {
	secret := new(btcec.ModNScalar)
	if s, err := hex.DecodeString(secretKey); err != nil {
		panic(err)
	} else {
		secret.SetByteSlice(s)
	}

	shards, pubkey, _ := frost.TrustedKeyDeal(secret, threshold, totalSigners)

	pubkeyShares := make([]frost.PublicKeyShare, len(shards))
	for s, shard := range shards {
		shareableHex := shard.PublicKeyShare.Hex()

		pubkeyShares[s] = frost.PublicKeyShare{}
		if err := pubkeyShares[s].DecodeHex(shareableHex); err != nil {
			panic(err)
		}
	}
	fmt.Println("pubkey:", hexPoint(pubkey)[2:])

	// start signing process
	cfg := &frost.Configuration{
		Threshold:             threshold,
		MaxSigners:            totalSigners,
		PublicKey:             pubkey,
		SignerPublicKeyShares: pubkeyShares,
	}

	if err := cfg.Init(); err != nil {
		panic(err)
	}

	signers := make([]chan string, len(shards))
	for s, shard := range shards {
		ch := make(chan string)
		go signer(ch, shard)
		signers[s] = ch
	}

	fmt.Println("message:", messageHex)

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sig, err := coordinator(ctx, cfg, signers, messageHex)
	if err != nil {
		panic(err)
	}

	fmt.Println("signature:", hex.EncodeToString(sig))

	sigp, _ := schnorr.ParseSignature(sig)
	message, _ := hex.DecodeString(messageHex)
	pk, _ := schnorr.ParsePubKey(pubkey.X.Bytes()[:])
	fmt.Println("valid:", sigp.Verify(message, pk))
}

func coordinator(
	ctx context.Context,
	cfg *frost.Configuration,
	signers []chan string,
	messageHex string,
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

	// step-3 (send): send commits from others and message that will be signed to each participant
	for s, ch := range signers {
		for sc, commit := range commitments {
			if sc == s {
				continue
			}
			select {
			case <-ctx.Done():
				return nil, ParticipantError{cfg, s, "timeout sending commit from other"}
			case ch <- commit.Hex():
			}
		}

		select {
		case <-ctx.Done():
			return nil, ParticipantError{cfg, s, "timeout sending message"}
		case ch <- messageHex:
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
	message, _ := hex.DecodeString(messageHex)
	signature, err := cfg.AggregateSignatures(message, partialSigs, commitments)
	if err != nil {
		return nil, err
	}

	// identify foul players if the signature is not good
	if ok := signature.Verify(message, btcec.NewPublicKey(&cfg.PublicKey.X, &cfg.PublicKey.Y)); !ok {
		for s, partialSig := range partialSigs {
			if err := cfg.VerifyPartialSignature(partialSig, message, commitments); err != nil {
				return nil, ParticipantError{cfg, s, "invalid partial signature: " + err.Error()}
			}
		}

		return nil, fmt.Errorf("signature %x is bad", signature.Serialize())
	}

	return signature.Serialize(), nil
}

func signer(ch chan string, shard frost.KeyShare) {
	// step-1 (receive): initialize ourselves
	cfg := frost.Configuration{}
	if err := cfg.DecodeHex(<-ch); err != nil {
		panic(err)
	}
	if err := cfg.Init(); err != nil {
		panic(err)
	}

	signer, err := cfg.Signer(shard)
	if err != nil {
		panic(err)
	}

	// step-2 (send): send our pre-commit to coordinator
	ourCommitment := signer.Commit()
	commitments := make([]frost.Commitment, 0, cfg.Threshold)
	commitments = append(commitments, ourCommitment)
	ch <- ourCommitment.Hex()

	// step-3 (receive): get commits from other signers and the message to be signed
	var message []byte
	for {
		msg := <-ch
		if len(msg) == 64 {
			message, err = hex.DecodeString(msg)
			if err != nil {
				panic(err)
			}
		} else {
			commit := frost.Commitment{}
			if err := commit.DecodeHex(msg); err != nil {
				panic(err)
			}

			if commit.CommitmentID != ourCommitment.CommitmentID {
				commitments = append(commitments, commit)
			}
		}

		if len(message) == 32 && len(commitments) == int(cfg.Threshold) {
			break
		}
	}

	// step-4 (send): sign and share our partial signature
	partialSig, err := signer.Sign(message, commitments)
	if err != nil {
		panic(err)
	}
	ch <- partialSig.Hex()
}
