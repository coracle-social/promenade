package main

import (
	"context"
	"fmt"
	"slices"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/fiatjaf/khatru"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/puzpuzpuz/xsync/v3"
)

var userContexts = xsync.NewMapOf[string, *KeyUserContext]()

func veryPrivateFiltering(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
	if len(filter.Kinds) == 1 && filter.Kinds[0] == nostr.KindNostrConnect {
		// nip-46 listeners are allowed
		return false, ""
	}

	requester := khatru.GetAuthed(ctx)
	if requester == "" {
		return true, "auth-required: everything is private"
	}

	// otherwise assume this is a musig2 signer
	pTags, _ := filter.Tags["p"]
	if len(pTags) == 0 {
		return true, "restricted: must have a 'p' tag at least"
	}

	for _, p := range pTags {
		// every request 'p' tag must be associated with the ms2 signer pubkey
		session, ok := userContexts.Load(p)
		if !ok {
			return true, "restricted: unknown 'p' tag '" + p + "'"
		}

		if !slices.Contains(session.signers, requester) {
			return true, "restricted: you are not authorized for '" + p + "'"
		}
	}

	return false, ""
}

func preliminaryElimination(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
	targetUser := event.Tags.GetFirst([]string{"p", ""})
	if targetUser == nil {
		return true, "missing 'p' tag"
	}
	p := (*targetUser)[1]
	kuc, ok := userContexts.Load(p)
	if !ok {
		return true, "unknown public key " + p
	}

	if event.Kind == nostr.KindNostrConnect {
		return false, ""
	} else if event.Kind == common.PartialSharedKeyKind {
		return false, ""
	} else if event.Kind == common.NonceKind {
		e := event.Tags.GetFirst([]string{"e", ""})
		if e == nil {
			return true, "missing 'e' tag"
		}

		targetEvent := (*e)[1]
		if targetEvent != kuc.currentEventBeingSigned {
			return true, "wrong 'e' signed"
		}

		return false, ""
	} else if event.Kind == common.PartialSigKind {
		e := event.Tags.GetFirst([]string{"e", ""})
		if e == nil {
			return true, "missing 'e' tag"
		}

		targetEvent := (*e)[1]
		if targetEvent != kuc.currentEventBeingSigned {
			return true, "wrong 'e' signed"
		}

		return false, ""
	}

	return true, "unsupported event"
}

func handleNIP46Request(ctx context.Context, event *nostr.Event) {
	if event.Kind != nostr.KindNostrConnect {
		return
	}

	p := event.Tags.GetFirst([]string{"p", ""})
	targetPubkey := (*p)[1]
	session, _ := userContexts.Load(targetPubkey)

	req, err := session.ParseRequest(event)
	if err != nil {
		log.Warn().Err(err).Str("from", event.PubKey).Str("to", targetPubkey).
			Msg("failed to parse request")
		return
	}

	var result string
	var resultErr error

	switch req.Method {
	case "connect":
		result = "ack"
	case "get_public_key":
		result = targetPubkey
	case "sign_event":
		if len(req.Params) != 1 {
			resultErr = fmt.Errorf("wrong number of arguments to 'sign_event'")
			break
		}
		evt := nostr.Event{}
		if err := easyjson.Unmarshal([]byte(req.Params[0]), &evt); err != nil {
			resultErr = fmt.Errorf("failed to decode event/2: %w", err)
			break
		}

		if err := session.Sign(&evt); err != nil {
			resultErr = fmt.Errorf("failed to sign event: %w", err)
			break
		}
		jrevt, _ := easyjson.Marshal(evt)
		result = string(jrevt)
	}

	_, eventResponse, err := session.MakeResponse(req.ID, event.PubKey, result, resultErr)
	if err != nil {
		log.Warn().Err(err).Msg("failed to make response")
		return
	}

	if err := session.Sign(&eventResponse); err != nil {
		log.Warn().Err(err).Msg("failed to sign response")
		return
	}

	relay.BroadcastEvent(&eventResponse)
}
