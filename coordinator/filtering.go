package main

import (
	"context"
	"slices"

	"fiatjaf.com/promenade/common"
	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
)

func veryPrivateFiltering(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
	if len(filter.Kinds) == 1 && filter.Kinds[0] == nostr.KindNostrConnect {
		// nip-46 listeners are allowed
		return false, ""
	}

	requester := khatru.GetAuthed(ctx)
	if requester == "" {
		return true, "auth-required: signers must authenticate"
	}

	// aside from these, we only allow signers to subscribe to events addressed to themselves
	// which will be the frost signing flow events and the initial shard ack event
	pTags, _ := filter.Tags["p"]
	if len(pTags) != 1 || pTags[0] != requester {
		return true, "needs a single 'p' tag equal to your own pubkey"
	}

	if len(filter.Kinds) == 3 &&
		slices.Contains(filter.Kinds, common.KindConfiguration) ||
		slices.Contains(filter.Kinds, common.KindGroupCommit) ||
		slices.Contains(filter.Kinds, common.KindEventToBeSigned) {
		// ok, this is the signing flow
		res, err := eventsdb.QuerySync(ctx, nostr.Filter{
			Tags:  nostr.TagMap{"p": []string{requester}},
			Kinds: []int{common.KindAccountRegistration},
			Limit: 1,
		})
		if err != nil {
			return true, "error: failed to query"
		}
		if len(res) == 0 {
			return true, "restricted: you are not a signer"
		}
		return false, ""
	} else if len(filter.Kinds) == 1 && filter.Kinds[0] == common.KindShardACK {
		// also ok, this is the initial ack flow
		return false, ""
	} else {
		return true, "filter is missing required kinds"
	}
}

func keepTrackOfWhoIsListening(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
	signer := khatru.GetAuthed(ctx)
	if signer == "" {
		return false, ""
	}

	conn := khatru.GetConnection(ctx)

	log.Info().Str("pubkey", signer).Msg("signer online")
	onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
		return oldValue + 1, false
	})

	go func() {
		<-conn.Context.Done()
		log.Info().Str("pubkey", signer).Msg("signer offline")
		onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
			return oldValue - 1, oldValue == 1
		})
	}()

	return false, ""
}
