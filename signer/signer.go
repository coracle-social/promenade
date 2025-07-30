package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/mailru/easyjson"
	"github.com/puzpuzpuz/xsync/v3"
)

// signing sessions are indexed by the id of the first event that triggered them
var sessions = xsync.NewMapOf[nostr.ID, chan nostr.Event]()

var lambdaRegistry = make(frost.LambdaRegistry)

var signerEndedEarly = fmt.Errorf("signer ended early")

func runSigner(ctx context.Context) error {
	ourPubkey, _ := kr.GetPublicKey(ctx)

	filter := nostr.Filter{
		Kinds: []nostr.Kind{common.KindConfiguration, common.KindGroupCommit, common.KindEventToBeSigned},
		Tags: nostr.TagMap{
			"p": []string{ourPubkey.Hex()},
		},
	}

	dfs := make([]nostr.DirectedFilter, 0, 2)

	ngroups := 0
	for shardEvt := range store.QueryEvents(nostr.Filter{Kinds: []nostr.Kind{common.KindStoredShard}}, 500) {
		coordinator := shardEvt.Tags.Find("coordinator")
		coordinatorPubKey, err := nostr.PubKeyFromHex(coordinator[2])
		if err != nil {
			panic(fmt.Errorf("coordinator with invalid pubkey %v was stored: %w", coordinator, err))
		}

		idx := slices.IndexFunc(dfs, func(df nostr.DirectedFilter) bool {
			return df.Relay == nostr.NormalizeURL(coordinator[1]) && df.Filter.Authors[0] == coordinatorPubKey
		})
		if idx == -1 {
			// use the pubkey the coordinator had at the time of shard creation
			filter.Authors = []nostr.PubKey{coordinatorPubKey}

			dfs = append(dfs, nostr.DirectedFilter{
				Relay:  nostr.NormalizeURL(coordinator[1]),
				Filter: filter,
			})
		}

		ngroups++
	}

	mainEventStream := pool.BatchedSubscribeMany(ctx, dfs, nostr.SubscriptionOptions{
		Label: "prom-sign-req",
	})

	log.Info().Msgf("[signer] started waiting to sign requests from %d key groups", ngroups)
	for ie := range mainEventStream {
		evt := ie.Event

		switch evt.Kind {
		case common.KindConfiguration:
			ch := make(chan nostr.Event)

			go func() {
				err := startSession(ctx, ie.Relay, ch)
				if err != nil {
					log.Warn().Err(err).Msg("[signer] failed to start session")
				}
			}()

			ch <- evt
		case common.KindGroupCommit, common.KindEventToBeSigned:
			eTag := evt.Tags.Find("e")
			if eTag == nil {
				return fmt.Errorf("coordinator sent a buggy event without \"e\": %s", evt)
			}

			id, err := nostr.IDFromHex(eTag[1])
			if err != nil {
				return fmt.Errorf("coordinator sent an event with an invalid \"e\": %s", evt)
			}

			if ch, ok := sessions.Load(id); ok {
				ch <- evt
			}
		}
	}

	return signerEndedEarly
}

func startSession(ctx context.Context, relay *nostr.Relay, ch chan nostr.Event) error {
	sendToCoordinator := func(evt *nostr.Event) {
		if err := kr.SignEvent(ctx, evt); err != nil {
			log.Warn().Msgf("failed to sign %d event to %s: %s", evt.Kind, relay.URL, err)
			return
		}

		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		if err := relay.Publish(ctx, *evt); err != nil {
			log.Warn().Msgf("failed to publish %d event to %s: %s", evt.Kind, relay.URL, err)
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

	log.Info().Msgf("[signer] sign session started for %x", *cfg.PublicKey.X.Bytes())

	var res nostr.Event
	var ok bool
	for pk := range store.QueryEvents(nostr.Filter{Authors: []nostr.PubKey{*cfg.PublicKey.X.Bytes()}}, 100) {
		res = pk
		ok = true
	}
	if !ok {
		return fmt.Errorf("[signer] couldn't find a shard for %x", *cfg.PublicKey.X.Bytes())
	}

	sessionId := evt.ID
	sessions.Store(sessionId, ch)

	shard := frost.KeyShard{}
	if err := shard.DecodeHex(res.Content); err != nil {
		return fmt.Errorf("failed to decode our shard: %w", err)
	}

	signer, err := cfg.Signer(shard, lambdaRegistry)
	if err != nil {
		panic(err)
	}

	// step-2 (send): send our pre-commit to coordinator
	ourCommitment := signer.Commit(sessionId.Hex() /* use the event id as the session id */)
	commitments := make([]frost.Commitment, 0, cfg.Threshold)
	commitments = append(commitments, ourCommitment)
	sendToCoordinator(&nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindCommit,
		Content:   ourCommitment.Hex(),
		Tags:      nostr.Tags{{"e", sessionId.Hex()}, {"p", cfg.PublicKey.X.String()}},
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

			// prevent someone with the bunker url from breaking everything
			if slices.Contains(common.ForbiddenKinds, evtToSign.Kind) {
				return fmt.Errorf("event has a forbidden kind")
			}
			if evtToSign.Kind == nostr.KindClientAuthentication {
				if tag := evtToSign.Tags.Find("challenge"); tag != nil && strings.HasPrefix(tag[1], "frostbunker:") {
					return fmt.Errorf("can't sign a frost bunker coordinator AUTH")
				}
				if tag := evtToSign.Tags.Find("relay"); tag != nil && nostr.NormalizeURL(tag[1]) == relay.URL {
					return fmt.Errorf("can't sign an AUTH for this same coordinator")
				}
			}
			// ~

			msg = evtToSign.ID[:]
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
		Tags:      nostr.Tags{{"e", sessionId.Hex()}, {"p", cfg.PublicKey.X.String()}},
	})
	log.Info().Msgf("[signer] signed %x for %x", msg[:], *cfg.PublicKey.X.Bytes())

	return nil
}
