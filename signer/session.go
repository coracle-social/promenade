package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"time"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/puzpuzpuz/xsync/v3"
)

// signing sessions are indexed by the id of the first event that triggered them
var sessions = xsync.NewMapOf[string, chan *nostr.Event]()

func handleInSession(evt *nostr.Event) {
	eTag := evt.Tags.GetFirst([]string{"e", ""})
	if eTag == nil {
		return
	}

	if ch, ok := sessions.Load((*eTag)[1]); ok {
		ch <- evt
	}
}

func startSession(ctx context.Context, relay *nostr.Relay, ch chan *nostr.Event) error {
	sendToCoordinator := func(evt *nostr.Event) {
		if err := evt.Sign(data.SecretKey); err != nil {
			fmt.Fprintf(os.Stderr, "failed to sign %d event to %s: %s", evt.Kind, relay.URL, err)
			return
		}

		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		if err := relay.Publish(ctx, *evt); err != nil {
			fmt.Fprintf(os.Stderr, "failed to publish %d event to %s: %s", evt.Kind, relay.URL, err)
			cancel()
			return
		}
		cancel()
	}

	// step-1 (receive): initialize ourselves
	evt := <-ch
	cfg := frost.Configuration{}
	if err := cfg.DecodeHex(evt.Content); err != nil {
		return fmt.Errorf("error decoding config: %w\n", err)
	}
	if err := cfg.Init(); err != nil {
		return fmt.Errorf("error initializing config: %w", err)
	}

	idx := slices.IndexFunc(data.KeyGroups, func(kg KeyGroup) bool {
		return kg.AggregatePublicKey == cfg.PublicKey.X.String()
	})
	if idx == -1 {
		return fmt.Errorf("unknown pubkey %x", *cfg.PublicKey.X.Bytes())
	}

	sessionId := evt.ID
	sessions.Store(sessionId, ch)

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
	sendToCoordinator(&nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindCommit,
		Content:   ourCommitment.Hex(),
		Tags:      nostr.Tags{{"e", sessionId}, {"p", cfg.PublicKey.X.String()}},
	})

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
	sendToCoordinator(&nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindPartialSignature,
		Content:   partialSig.Hex(),
		Tags:      nostr.Tags{{"e", sessionId}, {"p", cfg.PublicKey.X.String()}},
	})

	return nil
}
