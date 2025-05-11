package main

import (
	"context"
	"slices"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/promenade/common"
)

func handleRequest(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
	if len(filter.Kinds) == 1 && filter.Kinds[0] == nostr.KindNostrConnect {
		// nip-46 listeners are allowed
		return false, ""
	}

	// we must disallow anyone to read anything except for their own frost configs
	requester, isAuthed := khatru.GetAuthed(ctx)
	if !isAuthed {
		return true, "auth-required: signers must authenticate"
	}

	// people using their master secret key are allowed to read their own registration event
	if len(filter.Kinds) == 1 && filter.Kinds[0] == common.KindAccountRegistration {
		if len(filter.Authors) == 1 && requester == filter.Authors[0] {
			return false, ""
		} else {
			return true, "restricted: you can only read your own account registration"
		}
	}

	// aside from these, we only allow signers to subscribe to events addressed to themselves
	// which will be the frost signing flow events and the initial shard ack event
	pTags, _ := filter.Tags["p"]
	if len(pTags) != 1 || pTags[0] != requester.Hex() {
		return true, "restricted: needs a single 'p' tag equal to your own pubkey"
	}

	if len(filter.Kinds) == 3 &&
		slices.Contains(filter.Kinds, common.KindConfiguration) ||
		slices.Contains(filter.Kinds, common.KindGroupCommit) ||
		slices.Contains(filter.Kinds, common.KindEventToBeSigned) {
		// ok, this is the signing flow
		for range db.QueryEvents(nostr.Filter{
			Tags:  nostr.TagMap{"p": []string{requester.Hex()}},
			Kinds: []nostr.Kind{common.KindAccountRegistration},
			Limit: 1,
		}, 1) {
			// found something, that means this is a valid signer and the request can be fulfilled
			keepTrackOfWhoIsListening(ctx, requester)

			return false, ""
		}

		// otherwise disallow
		return true, "restricted: you are not a signer"
	} else if len(filter.Kinds) == 1 && filter.Kinds[0] == common.KindShardACK {
		// also ok, this is the initial ack flow
		return false, ""
	} else {
		return true, "filter is missing required kinds"
	}
}

func keepTrackOfWhoIsListening(ctx context.Context, signer nostr.PubKey) {
	conn := khatru.GetConnection(ctx)

	log.Info().Str("pubkey", signer.Hex()).Msg("signer online")
	onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
		return oldValue + 1, false
	})

	go func() {
		<-conn.Context.Done()
		log.Info().Str("pubkey", signer.Hex()).Msg("signer offline")
		onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
			return oldValue - 1, oldValue == 1
		})
	}()
}
