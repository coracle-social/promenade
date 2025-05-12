package main

import (
	"context"
	"fmt"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip46"
	"fiatjaf.com/promenade/common"
)

var nip46Signer = &nip46.DynamicSigner{
	GetHandlerSecretKey: func(handlerPubkey nostr.PubKey) (nostr.SecretKey, error) {
		res := make([]nostr.Event, 0, 1)
		for evt := range db.QueryEvents(nostr.Filter{Tags: nostr.TagMap{"h": []string{handlerPubkey.Hex()}}}, 100) {
			res = append(res, evt)
		}

		if len(res) != 1 {
			return [32]byte{}, fmt.Errorf("invalid result from 'h' query")
		}

		handlerSecret := res[0].Tags.Find("handlersecret")
		return nostr.SecretKeyFromHex(handlerSecret[1])
	},
	GetUserKeyer: func(handlerPubkey nostr.PubKey) (nostr.Keyer, error) {
		res := make([]nostr.Event, 0, 1)
		for evt := range db.QueryEvents(nostr.Filter{Tags: nostr.TagMap{"h": []string{handlerPubkey.Hex()}}}, 100) {
			res = append(res, evt)
		}
		if len(res) != 1 {
			return nil, fmt.Errorf("invalid result from 'h' query")
		}

		ar := common.AccountRegistration{}
		if err := ar.Decode(res[0]); err != nil {
			return nil, err
		}

		kuc, _ := groupContextsByHandlerPubKey.LoadOrCompute(handlerPubkey, func() *GroupContext {
			return &GroupContext{ar}
		})
		return kuc, nil
	},
	AuthorizeEncryption: func(from nostr.PubKey, secret string) bool { return false },
	OnEventSigned: func(event nostr.Event) {
		log.Info().Str("id", event.ID.Hex()).Str("pubkey", event.PubKey.Hex()).Msg("event signed")
	},
}

func handleNIP46Request(ctx context.Context, event nostr.Event) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	req, resp, eventResponse, err := nip46Signer.HandleRequest(ctx, event)
	if err != nil {
		log.Error().Err(err).Stringer("request", req).Msg("failed to handle request")
		return
	}

	log.Info().Stringer("request", req).Stringer("response", resp).Msg("returning response")
	relay.BroadcastEvent(eventResponse)
}
