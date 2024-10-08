package main

import (
	"context"
	"encoding/hex"
	"slices"

	"fiatjaf.com/promenade/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
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
		return true, "auth-required: everything is private"
	}

	// aside from nip-46 stuff, only allow our registered signers to connect
	if !slices.Contains(s.RegisteredSigners, requester) {
		return true, "restricted: only registered signers can connect"
	}

	// disallow forbidden kinds
	if slices.Contains(filter.Kinds, common.PartialSharedKeyKind) ||
		slices.Contains(filter.Kinds, common.PartialSigKind) {
		// these things cannot be listened for even by the signers
		return true, "restricted: this is confidential"
	}

	// check if there is a 'p' in the tags
	pTags, _ := filter.Tags["p"]
	if len(pTags) == 0 {
		// if not, assume this is a musig2 signer waiting to hear about new accounts to be created
	}

	// otherwise assume this is a musig2 signer asking for events related to a sign event flow
	for _, p := range pTags {
		// every request 'p' tag must be associated with the ms2 signer pubkey
		session, ok := userContexts.Load(p)
		if !ok {
			return true, "restricted: unknown 'p' tag '" + p + "'"
		}
		if !slices.ContainsFunc(session.signers, func(pk *btcec.PublicKey) bool {
			return hex.EncodeToString(pk.SerializeCompressed()[1:]) == requester
		}) {
			return true, "restricted: you are not authorized for '" + p + "'"
		}
	}

	return false, ""
}

func preliminaryElimination(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
	if event.Kind == nostr.KindNostrConnect {
		return false, ""
	}

	if event.Kind == common.PartialPubkeyKind {
		if pubkeyBytes, _ := hex.DecodeString(event.Content); len(pubkeyBytes) != 33 {
			return true, "invalid: invalid pubkey length"
		} else if _, err := btcec.ParsePubKey(pubkeyBytes); err != nil {
			return true, "invalid: " + err.Error()
		}
		return false, ""
	}

	targetUser := event.Tags.GetFirst([]string{"p", ""})
	if targetUser == nil {
		return true, "missing 'p' tag"
	}
	p := (*targetUser)[1]
	kuc, ok := userContexts.Load(p)
	if !ok {
		return true, "unknown aggregated public key " + p
	}

	if !slices.ContainsFunc(kuc.signers, func(pk *btcec.PublicKey) bool {
		return hex.EncodeToString(pk.SerializeCompressed()[1:]) == event.PubKey
	}) {
		return true, "can't act on this 'p'"
	}

	switch event.Kind {
	case common.PartialSharedKeyKind:
		if pubkeyBytes, _ := hex.DecodeString(event.Content); len(pubkeyBytes) != 33 {
			return true, "invalid: invalid pubkey length"
		} else if _, err := btcec.ParsePubKey(pubkeyBytes); err != nil {
			return true, "invalid: " + err.Error()
		}
		return false, ""
	case common.NonceKind:
		e := event.Tags.GetFirst([]string{"e", ""})
		if e == nil {
			return true, "invalid: missing 'e' tag"
		}
		targetEvent := (*e)[1]
		if targetEvent != kuc.currentEventBeingSigned {
			return true, "invalid: wrong 'e' signed"
		}
		if nonceBytes, _ := hex.DecodeString(event.Content); len(nonceBytes) != musig2.PubNonceSize {
			return true, "invalid: invalid nonce size"
		}
		return false, ""
	case common.PartialSigKind:
		e := event.Tags.GetFirst([]string{"e", ""})
		if e == nil {
			return true, "invalid: missing 'e' tag"
		}
		targetEvent := (*e)[1]
		if targetEvent != kuc.currentEventBeingSigned {
			return true, "invalid: wrong 'e' signed"
		}
		return false, ""
	}

	// blocking everything else here makes it so other users can't trigger signers to do stuff
	// for example, no one can create the events that only this relay can create like the account creation event
	// but still signers should ensure they check that the events they receive originate from the relay pubkey
	return true, "blocked: unsupported event"
}
