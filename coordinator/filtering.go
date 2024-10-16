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

	// aside from nip-46 stuff, we only allow signers to subscribe to events addressed to themselves
	// which will be the frost signing flow events
	pTags, _ := filter.Tags["p"]
	if len(pTags) != 1 || pTags[0] != requester {
		return true, "needs a single 'p' tag equal to your own pubkey"
	}

	if !slices.Contains(filter.Kinds, common.KindConfiguration) ||
		!slices.Contains(filter.Kinds, common.KindCommit) ||
		!slices.Contains(filter.Kinds, common.KindEventToBeSigned) {
		return true, "filter is missing required kinds"
	}

	if !internal.checkSignerExistence(requester) {
		return true, "restricted: you are not a signer"
	}

	return false, ""
}

func keepTrackOfWhoIsListening(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
	signer := khatru.GetAuthed(ctx)
	conn := khatru.GetConnection(ctx)

	onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
		return oldValue + 1, false
	})

	go func() {
		<-conn.Context.Done()
		onlineSigners.Compute(signer, func(oldValue int, loaded bool) (newValue int, delete bool) {
			return oldValue - 1, oldValue == 1
		})
	}()

	return false, ""
}
