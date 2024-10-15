package main

import (
	"context"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

var nip46Signer = nip46.NewDynamicSigner(
	func(handlerPubkey string) (string, error) {
		group, err := internal.getGroupByHandlerPubkey(handlerPubkey)
		if err != nil {
			return "", err
		}
		return group.Handler, nil
	},
	func(handlerPubkey string) (nostr.Keyer, error) {
		group, err := internal.getGroupByHandlerPubkey(handlerPubkey)
		if err != nil {
			return nil, err
		}

		kuc := &GroupContext{group: group}
		kuc, _ = groupContextsByHandlerPubKey.LoadOrStore(handlerPubkey, kuc)
		groupContextsByAggregatedPubKey.Store(group.Pubkey, kuc)
		return kuc, nil
	},
	nil,
	func(from, secret string) bool { return false },
	func(event nostr.Event) {
		log.Debug().Str("id", event.ID).Str("pubkey", event.PubKey).Msg("event signed")
	},
	nil,
)

func handleNIP46Request(ctx context.Context, event *nostr.Event) {
	if event.Kind != nostr.KindNostrConnect {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	req, resp, eventResponse, err := nip46Signer.HandleRequest(ctx, event)
	if err != nil {
		log.Error().Err(err).Stringer("request", req).Msg("failed to handle request")
		return
	}

	log.Debug().Stringer("request", req).Stringer("response", resp).Msg("returning response")
	relay.BroadcastEvent(&eventResponse)
}
