package main

import (
	"context"
	"encoding/hex"
	"fmt"
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

var lambdaRegistry = make(frost.LambdaRegistry)

func runSigner(ctx context.Context) {
	ourPubkey, _ := kr.GetPublicKey(ctx)

	filter := nostr.Filter{
		Kinds: []int{common.KindConfiguration, common.KindGroupCommit, common.KindEventToBeSigned},
		Tags: nostr.TagMap{
			"p": []string{ourPubkey},
		},
	}

	dfs := make([]nostr.DirectedFilters, 0, 2)
	results, err := eventsdb.QueryEvents(ctx, nostr.Filter{Kinds: []int{common.KindStoredShard}})
	if err != nil {
		panic(err)
	}

	ngroups := 0
	for shardEvt := range results {
		coordinator := shardEvt.Tags.GetFirst([]string{"coordinator", ""})

		idx := slices.IndexFunc(dfs, func(df nostr.DirectedFilters) bool {
			return df.Relay == nostr.NormalizeURL((*coordinator)[1]) &&
				df.Filters[0].Authors[0] == (*coordinator)[2]
		})
		if idx == -1 {
			// use the pubkey the coordinator had at the time of shard creation
			filter.Authors = []string{(*coordinator)[2]}

			dfs = append(dfs, nostr.DirectedFilters{
				Relay:   nostr.NormalizeURL((*coordinator)[1]),
				Filters: nostr.Filters{filter},
			})
		}

		ngroups++
	}

	mainEventStream := pool.BatchedSubMany(ctx, dfs)

	log.Debug().Msgf("[signer] started waiting for sign requests from %d key groups", ngroups)
	for ie := range mainEventStream {
		evt := ie.Event

		switch evt.Kind {
		case common.KindConfiguration:
			ch := make(chan *nostr.Event)

			go func() {
				err := startSession(ctx, ie.Relay, ch)
				if err != nil {
					log.Debug().Msgf("failed to start session: %s", err)
				}
			}()

			ch <- evt
		case common.KindGroupCommit, common.KindEventToBeSigned:
			eTag := evt.Tags.GetFirst([]string{"e", ""})
			if eTag == nil {
				return
			}

			if ch, ok := sessions.Load((*eTag)[1]); ok {
				ch <- evt
			}
		}
	}
}

func startSession(ctx context.Context, relay *nostr.Relay, ch chan *nostr.Event) error {
	sendToCoordinator := func(evt *nostr.Event) {
		if err := kr.SignEvent(ctx, evt); err != nil {
			log.Debug().Msgf("failed to sign %d event to %s: %s", evt.Kind, relay.URL, err)
			return
		}

		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		if err := relay.Publish(ctx, *evt); err != nil {
			log.Debug().Msgf("failed to publish %d event to %s: %s", evt.Kind, relay.URL, err)
			cancel()
			return
		}
		cancel()
	}

	// step-1 (receive): initialize ourselves
	evt := <-ch
	cfg := frost.Configuration{}
	if err := cfg.DecodeHex(evt.Content); err != nil {
		return fmt.Errorf("error decoding config: %w", err)
	}

	res, _ := eventsdb.QuerySync(ctx, nostr.Filter{Authors: []string{cfg.PublicKey.X.String()}})
	if len(res) == 0 {
		return fmt.Errorf("unknown pubkey %x", *cfg.PublicKey.X.Bytes())
	}

	log.Debug().Msgf("[signer] sign session started for %x", cfg.PublicKey.X.Bytes())

	sessionId := evt.ID
	sessions.Store(sessionId, ch)

	shard := frost.KeyShard{}
	if err := shard.DecodeHex(res[0].Content); err != nil {
		return fmt.Errorf("failed to decode our shard: %w", err)
	}

	signer, err := cfg.Signer(shard, lambdaRegistry)
	if err != nil {
		panic(err)
	}

	// step-2 (send): send our pre-commit to coordinator
	ourCommitment := signer.Commit(sessionId)
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
	groupCommitment := frost.BinoncePublic{}
	for {
		evt := <-ch
		switch evt.Kind {
		case common.KindEventToBeSigned:
			var evtToSign nostr.Event
			if err := easyjson.Unmarshal([]byte(evt.Content), &evtToSign); err != nil {
				return fmt.Errorf("failed to decode event to be signed: %w", err)
			}
			if !evtToSign.CheckID() {
				return fmt.Errorf("event to be signed has a broken id")
			}
			msg, _ = hex.DecodeString(evtToSign.ID)
		case common.KindGroupCommit:
			if err := groupCommitment.DecodeHex(evt.Content); err != nil {
				return fmt.Errorf("failed to decode received commitment: %w", err)
			}
		}

		if len(msg) == 32 && groupCommitment[0] != nil {
			break
		}
	}

	// step-4 (send): sign and shard our partial signature
	partialSig, err := signer.Sign(msg, groupCommitment)
	if err != nil {
		panic(err)
	}

	sendToCoordinator(&nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindPartialSignature,
		Content:   partialSig.Hex(),
		Tags:      nostr.Tags{{"e", sessionId}, {"p", cfg.PublicKey.X.String()}},
	})
	log.Debug().Msgf("[signer] signed %x for %x", msg, *cfg.PublicKey.X.Bytes())

	return nil
}
