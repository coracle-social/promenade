package main

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip46"
	"fiatjaf.com/promenade/common"
)

const ACCOUNT = "account"

var nip46Signer = &nip46.DynamicSigner{
	GetHandlerSecretKey: func(ctx context.Context, handlerPubkey nostr.PubKey) (context.Context, nostr.SecretKey, error) {
		next, done := iter.Pull(db.QueryEvents(nostr.Filter{
			Tags: nostr.TagMap{
				"h": []string{
					handlerPubkey.Hex(),
				},
			},
			Limit: 1,
		}, 1))
		evt, ok := next()
		done()

		if !ok {
			return ctx, [32]byte{}, fmt.Errorf("no result from 'h' query")
		}

		handlerSecret := evt.Tags.Find("handlersecret")
		sk, err := nostr.SecretKeyFromHex(handlerSecret[1])
		if err != nil {
			return ctx, [32]byte{}, fmt.Errorf("invalid handlersecret: %w", err)
		}

		ar := common.AccountRegistration{}
		if err := ar.Decode(evt); err != nil {
			return ctx, [32]byte{}, fmt.Errorf("event is an invalid account registration: %w", err)
		}

		ctx = context.WithValue(ctx,
			ACCOUNT,
			ar,
		)
		return ctx, sk, err
	},
	OnConnect: func(ctx context.Context, from nostr.PubKey, secret string) error {
		val := ctx.Value(ACCOUNT)
		if val == nil {
			return fmt.Errorf("no account loaded")
		}
		ar := val.(common.AccountRegistration)

		// associate `secret` and `from` for querying later -- using a fake event
		record := nostr.Event{
			Kind:    common.KindClientSecretAssociation, // just an internal gimmick
			PubKey:  from,
			Content: secret,
			Tags: nostr.Tags{
				nostr.Tag{"p", ar.PubKey.Hex()},
			},
			CreatedAt: nostr.Now(),
		}
		record.ID = record.GetID()
		return db.ReplaceEvent(record) // only keep the latest association for this pubkey
	},
	GetUserKeyer: func(ctx context.Context, handlerPubkey nostr.PubKey) (context.Context, nostr.Keyer, error) {
		val := ctx.Value(ACCOUNT)
		if val == nil {
			return ctx, nil, fmt.Errorf("no account loaded")
		}
		ar := val.(common.AccountRegistration)

		kuc, _ := groupContextsByHandlerPubKey.LoadOrCompute(handlerPubkey, func() *GroupContext {
			return &GroupContext{ar}
		})

		return ctx, kuc, nil
	},
	AuthorizeSigning: func(ctx context.Context, event nostr.Event, from nostr.PubKey) bool {
		val := ctx.Value(ACCOUNT)
		if val == nil {
			return false
		}
		ar := val.(common.AccountRegistration)

		// prevent someone with a bunker url from gaining access to other bunkers or overwriting them
		//   or doing other harmful things
		// (the signers should be doing these same checks but we do them here too just in case)
		if slices.Contains(common.ForbiddenKinds, event.Kind) {
			return false
		}
		if event.Kind == nostr.KindClientAuthentication {
			if tag := event.Tags.Find("challenge"); tag != nil && strings.HasPrefix(tag[1], "frostbunker:") {
				return false
			}
		}
		// ~

		// get previously associated secret
		next, done := iter.Pull(db.QueryEvents(nostr.Filter{
			Kinds:   []nostr.Kind{common.KindClientSecretAssociation},
			Authors: []nostr.PubKey{from},
			Tags: nostr.TagMap{
				"p": []string{ar.PubKey.Hex()},
			},
			Limit: 1,
		}, 1))
		evt, ok := next()
		done()
		if !ok {
			log.Warn().Str("client", from.Hex()).Str("user", ar.PubKey.Hex()).
				Msg("no secret associated")
			return false
		}
		secret := evt.Content

		for _, profile := range ar.Profiles {
			if profile.Secret == secret {
				if profile.Restrictions == nil {
					// everything is allowed
					return true
				}

				untilCheck := true
				if profile.Restrictions.Until > 0 {
					untilCheck = profile.Restrictions.Until > nostr.Now() /* real-time expiration is ok */ &&
						profile.Restrictions.Until > event.CreatedAt /* event-based expiration is ok */
				}

				kindCheck := true
				if len(profile.Restrictions.Kinds) > 0 {
					kindCheck = slices.Contains(profile.Restrictions.Kinds, event.Kind)
				}

				if untilCheck && kindCheck {
					return true
				} else {
					return false
				}
			}
		}

		return false
	},
	AuthorizeEncryption: func(ctx context.Context, from nostr.PubKey) bool { return false },
	OnEventSigned: func(event nostr.Event) {
		log.Info().Str("id", event.ID.Hex()).Str("pubkey", event.PubKey.Hex()).Msg("event signed")
	},
}

func handleNIP46Request(ctx context.Context, event nostr.Event) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	req, resp, eventResponse, err := nip46Signer.HandleRequest(ctx, event)
	if err != nil {
		log.Warn().Err(err).Stringer("request", req).Msg("failed to handle request")
		useIPFailedAttemptsRateLimit(khatru.GetIP(ctx))
		return
	}

	useClientSuccessAttemptsRateLimit(event.PubKey)

	log.Info().Stringer("request", req).Stringer("response", resp).Msg("returning response")
	relay.BroadcastEvent(eventResponse)
}
