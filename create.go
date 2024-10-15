package main

import (
	"context"

	"fiatjaf.com/promenade/common"
	"github.com/nbd-wtf/go-nostr"
)

func handleCreate(ctx context.Context, evt *nostr.Event) {
	if evt.Kind != common.KindAccountRegistration {
		return
	}

	ar := common.AccountRegistration{}
	if err := ar.Decode(evt); err != nil {
		log.Warn().Err(err).Stringer("event", evt).Msg("event is not an account registration")
		return
	}

	g := Group{
		Handler:   nostr.GeneratePrivateKey(),
		Pubkey:    ar.PubKey,
		Threshold: uint32(ar.Threshold),
		Signers:   make([]*EncodedSigner, len(ar.Signers)),
	}

	for s, signer := range ar.Signers {
		es := &EncodedSigner{
			Pubkey:   signer.PeerPubKey,
			Pubshard: signer.Shard.Encode(),
		}
		g.Signers[s] = es
	}

	handlerPubkey, err := nostr.GetPublicKey(g.Handler)
	if err != nil {
		log.Warn().Err(err).Stringer("event", evt).Msg("please try again")
		return
	}

	if err := internal.saveGroup(&g); err != nil {
		log.Warn().Err(err).Stringer("event", evt).Msg("failed to store")
		return
	}

	log.Debug().Str("handler", handlerPubkey).Msg("registered")
}
