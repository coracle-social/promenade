package main

import (
	"context"
	"fmt"
	"time"

	"fiatjaf.com/promenade/common"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

var nip46Signer = nip46.NewDynamicSigner(
	func(handlerPubkey string) (string, error) {
		res, err := eventsdb.QuerySync(context.TODO(), nostr.Filter{
			Tags: nostr.TagMap{"h": []string{handlerPubkey}},
		})
		if err != nil {
			return "", err
		}
		if len(res) != 1 {
			return "", fmt.Errorf("invalid result from 'h' query")
		}

		handlerSecret := res[0].Tags.GetFirst([]string{"h"})
		return (*handlerSecret)[1], nil
	},
	func(handlerPubkey string) (nostr.Keyer, error) {
		res, err := eventsdb.QuerySync(context.TODO(), nostr.Filter{
			Tags: nostr.TagMap{"h": []string{handlerPubkey}},
		})
		if err != nil {
			return nil, err
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
