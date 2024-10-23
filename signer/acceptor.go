package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
	"github.com/nbd-wtf/go-nostr/nip13"
)

func runAcceptor(ctx context.Context, relayURL string, acceptMax uint64, restartSigner func()) {
	kr, _ := keyer.NewPlainKeySigner(data.SecretKey)
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
		fmt.Fprintf(os.Stderr, "[acceptor] updating our relay list to %s\n", relayURL)
		pool.PublishMany(ctx, common.IndexRelays, rlEvt)
		ourInbox = []string{relayURL}
	}

	// listen for incoming shards
	fmt.Fprintf(os.Stderr, "[acceptor] listening for new shards at %s\n", ourInbox[0])
	acceptedTotal := 0
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
		fmt.Fprintf(os.Stderr, "[acceptor] got shard from %s: %s\n", shardEvt.PubKey, shardEvt.ID)

		// check proof-of-work
		if work := nip13.CommittedDifficulty(shardEvt.Event); work < 20 {
			fmt.Fprintf(os.Stderr, "[acceptor] not enough work: need 20, got %d\n", work)
			continue
		}

		// get metadata and check validity
		shard := frost.KeyShard{}

		plaintextShard, err := kr.Decrypt(ctx, shardEvt.Content, shardEvt.PubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[acceptor] failed to decrypt shard: %s\n", err)
			continue
		}
		if err := shard.DecodeHex(plaintextShard); err != nil {
			fmt.Fprintf(os.Stderr, "[acceptor] got broken shard: %s\n", err)
			continue
		}
		coordinator := shardEvt.Tags.GetFirst([]string{"coordinator", ""})
		if coordinator == nil || !nostr.IsValidRelayURL((*coordinator)[1]) {
			fmt.Fprintf(os.Stderr, "[acceptor] got broken coordinator url '%s'\n", (*coordinator)[1])
			continue
		}

		// reply with an ack
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
		fmt.Fprintf(os.Stderr, "[acceptor] sending ack to %v\n", theirInbox)
		for res := range pool.PublishMany(ctx, theirInbox, ackEvt) {
			if res.Error == nil {
				success = true
			} else {
				errs[res.RelayURL] = res.Error.Error()
			}
		}
		if !success {
			fmt.Fprintf(os.Stderr, "[acceptor] failed to send ack back to %s: %v\n", shardEvt.PubKey, errs)
			continue
		}

		// append to our data store (delete previous entries for the same pubkey)
		data.KeyGroups = slices.DeleteFunc(data.KeyGroups, func(kg KeyGroup) bool {
			return kg.AggregatePublicKey == shardEvt.PubKey
		})
		data.KeyGroups = append(data.KeyGroups, KeyGroup{
			Coordinator:           (*coordinator)[1],
			EncodedSecretKeyShard: plaintextShard,
			AggregatePublicKey:    shardEvt.PubKey,
		})
		if err := storeData(data); err != nil {
			panic(err)
		}

		// if we get too many registrations, stop accepting
		acceptedTotal++
		if acceptedTotal == int(acceptMax) {
			fmt.Fprintf(os.Stderr, "[acceptor] reached max accepted groups (%d), restart to accept more or use a different --accept-max value\n", acceptMax)
			return
		}

		// wait a while just because
		time.Sleep(time.Second * 30)

		// restart signer process
		restartSigner()
	}
}
