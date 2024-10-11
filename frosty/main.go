package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
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
	// message, _ := hex.DecodeString("a9ce7954b29e133b5eb06c331fe350593aa122f146e4cfc8b1aee89732c04880")
	// key := ecc.Secp256k1Sha256.NewScalar()
	// key.DecodeHex("a79fc3461f156c087eee20d8a79624a55cb02690eb062e871b824306b8f51894")
	// sig, err := debug.Sign(frost.Secp256k1, message, key, nil)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(sig.Hex()[4:])

	flow(
		context.Background(),
		3,
		3,
		"a9ce7954b29e133b5eb06c331fe350593aa122f146e4cfc8b1aee89732c04880",
		"a79fc3461f156c087eee20d8a79624a55cb02690eb062e871b824306b8f51894",
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

	shards, pubkey, _ := frost.TrustedDealerKeygen(secret, threshold, totalSigners)

	pubkeyShares := make([]*frost.PublicKeyShare, len(shards))
	for s, shard := range shards {
		shareableHex := shard.PublicKeyShare.Hex()

		pubkeyShares[s] = &frost.PublicKeyShare{}
		pubkeyShares[s].DecodeHex(shareableHex)
	}
	fmt.Println("pubkey:", pubkey.Hex()[2:])

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

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sig, err := coordinator(ctx, cfg, signers, messageHex)
	if err != nil {
		panic(err)
	}

	fmt.Println("message:", messageHex)
	fmt.Println("signature:", sig)
}

func coordinator(
	ctx context.Context,
	cfg *frost.Configuration,
	signers []chan string,
	messageHex string,
) (string, error) {
	// step-1 (send): initialize each participant
	cfgHex := cfg.Hex()
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return "", ParticipantError{cfg, s, "timeout sending config"}
		case ch <- cfgHex:
		}
	}

	// step-2 (receive): get all pre-commits from signers
	commitments := make(frost.CommitmentList, cfg.Threshold)
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return "", ParticipantError{cfg, s, "timeout receiving commit"}
		case msg := <-ch:
			commit := frost.Commitment{}
			if err := commit.DecodeHex(msg); err != nil {
				return "", err
			}
			commitments[s] = &commit
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
				return "", ParticipantError{cfg, s, "timeout sending commit from other"}
			case ch <- commit.Hex():
			}
		}

		select {
		case <-ctx.Done():
			return "", ParticipantError{cfg, s, "timeout sending message"}
		case ch <- messageHex:
		}
	}

	// step-4 (receive): get partial signature from each participant
	partialSigs := make([]*frost.SignatureShare, len(signers))
	for s, ch := range signers {
		select {
		case <-ctx.Done():
			return "", ParticipantError{cfg, s, "timeout receiving partial signature"}
		case msg := <-ch:
			partialSig := &frost.SignatureShare{}
			if err := partialSig.DecodeHex(msg); err != nil {
				return "", err
			}
			partialSigs[s] = partialSig
		}
	}

	// aggregate signature
	message, _ := hex.DecodeString(messageHex)
	signature, err := cfg.AggregateSignatures(message, partialSigs, commitments, false)
	if err != nil {
		return "", err
	}

	// identify foul players if the signature is not good
	if err = frost.VerifySignature(frost.Secp256k1, message, signature, cfg.VerificationKey); err != nil {
		for s, partialSig := range partialSigs {
			if err := cfg.VerifySignatureShare(partialSig, message, commitments); err != nil {
				return "", ParticipantError{cfg, s, "invalid partial signature: " + err.Error()}
			}
		}

		return "", fmt.Errorf("aggregate signature is bad: %w", err)
	}

	r := signature.R.Encode()[1:]
	s := signature.Z.Encode()
	return hex.EncodeToString(append(r, s...)), nil
}

func signer(ch chan string, shard *KeyShare) {
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
	ourCommitment := signer.Commit()
	commitments := make(frost.CommitmentList, 0, cfg.Threshold)
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
			commit := &frost.Commitment{}
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
