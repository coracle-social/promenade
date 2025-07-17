package main

import (
	"context"

	"fiatjaf.com/nostr"
	"fiatjaf.com/promenade/common"
)

func filterOutEverythingExceptWhatWeWant(ctx context.Context, event nostr.Event) (reject bool, msg string) {
	if event.Kind.IsEphemeral() {
		// allow all ephemeral
		return false, ""
	}
	if event.Kind == common.KindAccountRegistration {
		ar := common.AccountRegistration{}
		if err := ar.Decode(event); err != nil {
			return true, "error: account registration event is malformed: " + err.Error()
		}

		return false, ""
	}
	return true, "blocked: this event is not accepted"
}

func handleCreate(ctx context.Context, evt nostr.Event) {
	if evt.Kind != common.KindAccountRegistration {
		return
	}

	ar := common.AccountRegistration{}
	if err := ar.Decode(evt); err != nil {
		log.Warn().Err(err).Stringer("event", evt).Msg("event is not a valid account registration")
		return
	}

	signers := make([]nostr.PubKey, len(ar.Signers))
	for i, signer := range ar.Signers {
		signers[i] = signer.PeerPubKey
	}
	log.Info().Str("pubkey", ar.PubKey.Hex()).Any("signers", signers).Msg("account registered")

	// let signers know we have this registered here
	for _, signer := range ar.Signers {
		ackEvt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      common.KindShardACK,
			Tags: nostr.Tags{
				nostr.Tag{"P", ar.PubKey.Hex()},
				nostr.Tag{"p", signer.PeerPubKey.Hex()},
			},
		}
		ackEvt.Sign(s.SecretKey)
		relay.BroadcastEvent(ackEvt)
	}
}
