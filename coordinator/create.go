package main

import (
	"context"

	"fiatjaf.com/promenade/common"
	"github.com/nbd-wtf/go-nostr"
)

func filterOutEverythingExceptWhatWeWant(ctx context.Context, evt *nostr.Event) (reject bool, msg string) {
	if nostr.IsEphemeralKind(evt.Kind) {
		return false, ""
	}
	if evt.Kind == common.KindAccountRegistration {
		ar := common.AccountRegistration{}
		if err := ar.Decode(evt); err != nil {
			return true, "error: account registration event is malformed: " + err.Error()
		}

		return false, ""
	}
	return true, "blocked: this event is not accepted"
}

func handleCreate(ctx context.Context, evt *nostr.Event) {
	if evt.Kind != common.KindAccountRegistration {
		return
	}

	ar := common.AccountRegistration{}
	if err := ar.Decode(evt); err != nil {
		log.Warn().Err(err).Stringer("event", evt).Msg("event is not an account registration")
		return
	}

	signers := make([]string, len(ar.Signers))
	for i, signer := range ar.Signers {
		signers[i] = signer.PeerPubKey
	}
	log.Info().Str("pubkey", ar.PubKey).Strs("signers", signers).Msg("account registered")

	// let signers know we have this registered here
	for _, signer := range ar.Signers {
		ackEvt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      common.KindShardACK,
			Tags: nostr.Tags{
				nostr.Tag{"P", ar.PubKey},
				nostr.Tag{"p", signer.PeerPubKey},
			},
		}
		ackEvt.Sign(s.PrivateKey)
		relay.BroadcastEvent(&ackEvt)
	}
}
