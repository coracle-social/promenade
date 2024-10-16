package main

import (
	"encoding/hex"
	"fmt"
	"slices"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/puzpuzpuz/xsync/v3"
)

var sessions = xsync.NewMapOf[[32]byte, chan *nostr.Event]()

func startSession(ch chan *nostr.Event) error {
	// step-1 (receive): initialize ourselves
	evt := <-ch
	cfg := frost.Configuration{}
	if err := cfg.DecodeHex(evt.Content); err != nil {
		return fmt.Errorf("error decoding config: %w\n", err)
	}

	idx := slices.IndexFunc(data.KeyGroups, func(kg KeyGroup) bool {
		return kg.AggregatePublicKey == cfg.PublicKey.X.String()
	})
	if idx == -1 {
		return fmt.Errorf("unknown pubkey %x", *cfg.PublicKey.X.Bytes())
	}

	sessions.Store(*cfg.PublicKey.X.Bytes(), ch)

	shard := frost.KeyShard{}
	if err := shard.DecodeHex(data.KeyGroups[idx].EncodedSecretKeyShard); err != nil {
		return fmt.Errorf("failed to decode our shard: %w", err)
	}

	signer, err := cfg.Signer(shard)
	if err != nil {
		panic(err)
	}

	// step-2 (send): send our pre-commit to coordinator
	ourCommitment := signer.Commit()
	commitments := make([]frost.Commitment, 0, cfg.Threshold)
	commitments = append(commitments, ourCommitment)
	ch <- &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindCommit,
		Content:   ourCommitment.Hex(),
		Tags:      nostr.Tags{{"p", cfg.PublicKey.X.String()}},
	}

	// step-3 (receive): get commits from other signers and the message to be signed
	var msg []byte
	for {
		evt := <-ch

		switch evt.Kind {
		case common.KindEventToBeSigned:
			var evtToSign nostr.Event
			if err := easyjson.Unmarshal([]byte(evt.Content), &evtToSign); err != nil {
				return fmt.Errorf("failed to decode event to be signed: %w", err)
			}
			if !evt.CheckID() {
				return fmt.Errorf("event to be signed has a broken id")
			}
			msg, _ = hex.DecodeString(evt.ID)
		case common.KindCommit:
			commit := frost.Commitment{}
			if err := commit.DecodeHex(evt.Content); err != nil {
				panic(err)
			}

			if commit.CommitmentID != ourCommitment.CommitmentID {
				commitments = append(commitments, commit)
			}
		}

		if len(msg) == 32 && len(commitments) == int(cfg.Threshold) {
			break
		}
	}

	// step-4 (send): sign and shard our partial signature
	partialSig, err := signer.Sign(msg, commitments)
	if err != nil {
		panic(err)
	}
	ch <- &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindPartialSignature,
		Content:   partialSig.Hex(),
		Tags:      nostr.Tags{{"p", cfg.PublicKey.X.String()}},
	}

	return nil
}
