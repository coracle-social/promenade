package main

import (
	"context"
	"slices"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip11"
	"fiatjaf.com/nostr/nip13"
	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
)

func runAcceptor(ctx context.Context, relayURLs []string, pow uint64, restartSigner func()) {
	ourPubkey, _ := kr.GetPublicKey(ctx)

	// update our 10002 list if necessary
	var latest *nostr.Event
	for ie := range pool.FetchMany(ctx, common.IndexRelays, nostr.Filter{
		Kinds:   []nostr.Kind{10002},
		Authors: []nostr.PubKey{ourPubkey},
	}, nostr.SubscriptionOptions{}) {
		if latest == nil || latest.CreatedAt < ie.CreatedAt {
			latest = &ie.Event
		}
	}

	var ourInbox []string
	if latest != nil {
		ourInbox = make([]string, 0, 4)
		for tag := range latest.Tags.FindAll("r") {
			if len(tag) == 2 || tag[2] == "read" {
				ourInbox = append(ourInbox, tag[1])
			}
		}
	}

	if !slices.Equal(ourInbox, relayURLs) {
		tags := make(nostr.Tags, len(relayURLs))
		for i, url := range relayURLs {
			tags[i] = nostr.Tag{"r", url, "read"}
		}

		rlEvt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      10002,
			Tags:      tags,
		}
		kr.SignEvent(ctx, &rlEvt)
		log.Debug().Msgf("[acceptor] updating our relay list to %v (from %v)", relayURLs, ourInbox)
		pool.PublishMany(ctx, common.IndexRelays, rlEvt)
		ourInbox = relayURLs
	}

	// listen for incoming shards
	log.Debug().Msgf("[acceptor] listening for new shards at %v", ourInbox)
	for shardEvt := range pool.SubscribeMany(ctx, ourInbox, nostr.Filter{
		Kinds: []nostr.Kind{common.KindShard},
		Tags: nostr.TagMap{
			"p": []string{ourPubkey.Hex()},
		},
		Since: nostr.Now(),
	}, nostr.SubscriptionOptions{}) {
		go handleShard(ctx, shardEvt.Event, pow, restartSigner)
	}
}

func handleShard(ctx context.Context, shardEvt nostr.Event, pow uint64, restartSigner func()) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()

	ourPubkey, _ := kr.GetPublicKey(ctx)
	log.Info().Str("user", shardEvt.PubKey.Hex()).Msgf("[acceptor] got shard")

	// check proof-of-work
	if work := nip13.CommittedDifficulty(shardEvt); work < int(pow) {
		log.Warn().Uint64("need", pow).Int("got", work).Msgf("[acceptor] not enough work")
		return
	}

	// get metadata and check validity
	shard := frost.KeyShard{}

	plaintextShard, err := kr.Decrypt(ctx, shardEvt.Content, shardEvt.PubKey)
	if err != nil {
		log.Warn().Err(err).Msg("[acceptor] failed to decrypt shard")
		return
	}
	if err := shard.DecodeHex(plaintextShard); err != nil {
		log.Warn().Err(err).Msgf("[acceptor] got broken shard")
		return
	}
	coordinator := shardEvt.Tags.Find("coordinator")
	if coordinator == nil || !nostr.IsValidRelayURL(coordinator[1]) {
		log.Warn().Str("url", coordinator[1]).Msg("[acceptor] got broken coordinator url")
		return
	}

	// TOFU the coordinator's pubkey
	info, err := nip11.Fetch(ctx, coordinator[1])
	if err != nil {
		log.Warn().Err(err).Str("relay", coordinator[1]).Msgf("[acceptor] error on nip11 request")
		return
	}
	// surreptitiously inject it into the event that we will save
	idx := slices.IndexFunc(shardEvt.Tags, func(tag nostr.Tag) bool { return tag[0] == "coordinator" })
	shardEvt.Tags[idx] = append(shardEvt.Tags[idx], info.PubKey.Hex())

	// listen to coordinator for their ack
	coordinatorAckEvents := pool.SubscribeMany(ctx, []string{coordinator[1]}, nostr.Filter{
		Kinds: []nostr.Kind{common.KindShardACK},
		Tags: nostr.TagMap{
			"P": []string{shardEvt.PubKey.Hex()},
			"p": []string{ourPubkey.Hex()},
		},
	}, nostr.SubscriptionOptions{})
	if coordinatorAckEvents == nil {
		log.Warn().Str("relay", coordinator[1]).Msg("[acceptor] can't subscribe to coordinator")
		return
	}

	// now that we are already listening for the coordinator ack, we can reply to user with our different ack
	ackEvt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindShardACK,
		Tags: nostr.Tags{
			{"p", shardEvt.PubKey.Hex()},
			{"e", shardEvt.ID.Hex()},
		},
	}
	kr.SignEvent(ctx, &ackEvt)

	// first we need their read relays
	theirInbox := make([]string, 0, 5)
	for evt := range pool.FetchMany(ctx, common.IndexRelays, nostr.Filter{
		Kinds:   []nostr.Kind{10002},
		Authors: []nostr.PubKey{shardEvt.PubKey},
	}, nostr.SubscriptionOptions{}) {
		for tag := range evt.Tags.FindAll("r") {
			if len(tag) == 2 || tag[2] == "read" {
				theirInbox = append(theirInbox, tag[1])
			}
		}
	}
	success := false
	errs := make(map[string]string, len(theirInbox))
	log.Debug().Msgf("[acceptor] sending ack to %v", theirInbox)
	for res := range pool.PublishMany(ctx, theirInbox, ackEvt) {
		if res.Error == nil {
			success = true
		} else {
			errs[res.RelayURL] = res.Error.Error()
		}
	}
	if !success {
		log.Warn().Interface("errors", errs).Str("user", shardEvt.PubKey.Hex()).
			Msg("[acceptor] failed to send ack back")
		return
	}

	// we should be all set now, just needing an ack from the coordinator
	_, gotAny := <-coordinatorAckEvents
	if !gotAny {
		log.Warn().AnErr("ctx-err", ctx.Err()).Str("user", shardEvt.PubKey.Hex()).
			Msg("[acceptor] failed to get ack from coordinator")
		return
	}
	log.Info().Str("user", shardEvt.PubKey.Hex()).Str("coordinator", coordinator[1]).
		Msgf("[acceptor] got ack from coordinator")

	// append to our data store (delete previous entries for the same pubkey)
	results := store.QueryEvents(nostr.Filter{
		Kinds:   []nostr.Kind{common.KindStoredShard},
		Authors: []nostr.PubKey{shardEvt.PubKey},
	}, 100)

	// store now just to prevent losing data in between
	storedShard := nostr.Event{
		Kind:   common.KindStoredShard,
		PubKey: shardEvt.PubKey,
		Tags: append(
			shardEvt.Tags,
			nostr.Tag{""},
		),
		Content: plaintextShard,
	}
	storedShard.ID = storedShard.GetID()
	if err := store.SaveEvent(storedShard); err != nil {
		panic(err)
	}

	// and only now delete the old stuff
	for oldShardEvt := range results {
		if err := store.DeleteEvent(oldShardEvt.ID); err != nil {
			panic(err)
		}
	}

	log.Info().Str("user", shardEvt.PubKey.Hex()).Msgf("[acceptor] shard registered")

	// restart signer process
	restartSigner()
}
