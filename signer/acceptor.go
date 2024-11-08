package main

import (
	"context"
	"slices"
	"time"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/nbd-wtf/go-nostr/nip13"
)

func runAcceptor(ctx context.Context, relayURL string, pow uint64, restartSigner func()) {
	ourPubkey, _ := kr.GetPublicKey(ctx)

	// update our 10002 list if necessary
	ourInbox := make([]string, 0, 1)
	for evt := range pool.SubManyEose(ctx, common.IndexRelays, nostr.Filters{
		{Kinds: []int{10002}, Authors: []string{ourPubkey}},
	}) {
		for _, tag := range evt.Tags.All([]string{"r", ""}) {
			if len(tag) == 2 || tag[2] == "read" {
				ourInbox = append(ourInbox, tag[1])
			}
		}
	}
	if len(ourInbox) != 1 || ourInbox[0] != relayURL {
		rlEvt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      10002,
			Tags:      nostr.Tags{{"r", relayURL, "read"}},
		}
		kr.SignEvent(ctx, &rlEvt)
		log.Debug().Msgf("[acceptor] updating our relay list to %s", relayURL)
		pool.PublishMany(ctx, common.IndexRelays, rlEvt)
		ourInbox = []string{relayURL}
	}

	// listen for incoming shards
	log.Debug().Msgf("[acceptor] listening for new shards at %s", ourInbox[0])
	now := nostr.Now()
	for shardEvt := range pool.SubMany(ctx, ourInbox, nostr.Filters{
		{
			Kinds: []int{common.KindShard},
			Tags: nostr.TagMap{
				"p": []string{ourPubkey},
			},
			Since: &now,
		},
	}) {
		go handleShard(ctx, shardEvt.Event, pow, restartSigner)
	}
}

func handleShard(ctx context.Context, shardEvt *nostr.Event, pow uint64, restartSigner func()) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute*2)
	defer cancel()

	ourPubkey, _ := kr.GetPublicKey(ctx)
	log.Info().Str("user", shardEvt.PubKey).Msgf("[acceptor] got shard")

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
	coordinator := shardEvt.Tags.GetFirst([]string{"coordinator", ""})
	if coordinator == nil || !nostr.IsValidRelayURL((*coordinator)[1]) {
		log.Warn().Str("url", (*coordinator)[1]).Msg("[acceptor] got broken coordinator url")
		return
	}

	// TOFU the coordinator's pubkey
	info, err := nip11.Fetch(ctx, (*coordinator)[1])
	if err != nil {
		log.Warn().Err(err).Str("relay", (*coordinator)[1]).Msgf("[acceptor] error on nip11 request")
		return
	} else if !nostr.IsValidPublicKey(info.PubKey) {
		log.Warn().Str("relay", (*coordinator)[1]).Str("pubkey", info.PubKey).Msg("[acceptor] coordinator has invalid pubkey")
		return
	}
	// surreptitiously inject it into the event that we will save
	idx := slices.IndexFunc(shardEvt.Tags, func(tag nostr.Tag) bool { return tag[0] == "coordinator" })
	shardEvt.Tags[idx] = append(shardEvt.Tags[idx], info.PubKey)

	// listen to coordinator for their ack
	coordinatorAckEvents := pool.SubMany(ctx, []string{(*coordinator)[1]}, nostr.Filters{
		{
			Kinds: []int{common.KindShardACK},
			Tags: nostr.TagMap{
				"P": []string{shardEvt.PubKey},
				"p": []string{ourPubkey},
			},
		},
	})
	if coordinatorAckEvents == nil {
		log.Warn().Str("relay", (*coordinator)[1]).Msg("[acceptor] can't subscribe to coordinator")
		return
	}

	// now that we are already listening for the coordinator ack, we can reply to user with our different ack
	ackEvt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindShardACK,
		Tags: nostr.Tags{
			{"p", shardEvt.PubKey},
			{"e", shardEvt.ID},
		},
	}
	kr.SignEvent(ctx, &ackEvt)

	// first we need their read relays
	theirInbox := make([]string, 0, 5)
	for evt := range pool.SubManyEose(ctx, common.IndexRelays, nostr.Filters{
		{
			Kinds:   []int{10002},
			Authors: []string{shardEvt.PubKey},
		},
	}) {
		for _, tag := range evt.Tags.All([]string{"r", ""}) {
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
		log.Warn().Interface("errors", errs).Str("user", shardEvt.PubKey).
			Msg("[acceptor] failed to send ack back")
		return
	}

	// we should be all set now, just needing an ack from the coordinator
	coordinatorAck := <-coordinatorAckEvents
	if coordinatorAck.Event == nil {
		log.Warn().AnErr("ctx-err", ctx.Err()).Str("user", shardEvt.PubKey).
			Msg("[acceptor] failed to get ack from coordinator")
		return
	}
	log.Info().Str("user", shardEvt.PubKey).Str("coordinator", (*coordinator)[1]).
		Msgf("[acceptor] got ack from coordinator")

	// append to our data store (delete previous entries for the same pubkey)
	results, err := eventsdb.QuerySync(ctx, nostr.Filter{Kinds: []int{common.KindStoredShard}, Authors: []string{shardEvt.PubKey}})
	if err != nil {
		panic(err)
	}
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
	if err := eventsdb.SaveEvent(ctx, &storedShard); err != nil {
		panic(err)
	}

	// and only now delete the old stuff
	for _, oldShardEvt := range results {
		eventsdb.DeleteEvent(ctx, oldShardEvt)
	}

	log.Info().Str("user", shardEvt.PubKey).Msgf("[acceptor] shard registered")

	// restart signer process
	restartSigner()
}
