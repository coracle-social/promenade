package main

import (
	"context"

	"fiatjaf.com/promenade/common"
	"github.com/nbd-wtf/go-nostr"
)

func filterOutEverythingExceptWhatWeWant(ctx context.Context, evt *nostr.Event) (reject bool, msg string) {
	if evt.IsEphemeral() {
		return false, ""
	}
	if evt.Kind == common.KindAccountRegistration {
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
}
