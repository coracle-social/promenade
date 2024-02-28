package main

import (
	"context"
	"fmt"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

var mainSession *nip46.Session

func handleNIP46Request(ctx context.Context, event *nostr.Event) {
	if event.Kind != nostr.KindNostrConnect {
		return
	}

	p := event.Tags.GetFirst([]string{"p", ""})
	targetPubkey := (*p)[1]

	var result string
	var resultErr error
	var nip46Session *nip46.Session
	var signEvent func(*nostr.Event) error

	if targetPubkey == s.PublicKey {
		// this session is used only for account creation
		nip46Session = mainSession
		signEvent = func(e *nostr.Event) error { return e.Sign(s.PrivateKey) }
		return
	} else {
		kuc, _ := userContexts.Load(targetPubkey)

		// this requires a shared key for decrypting and encrypting messages.
		// we must ask our signers for their partial ecdh things if we don't have that already
		if n46, ok := kuc.nip46.Load(event.PubKey); ok {
			callback := make(chan *nip46.Session)
			kuc.ecdhPending.Store(event.PubKey, &PendingECDH{
				callback:          callback,
				partialSharedKeys: make([]*btcec.PublicKey, len(kuc.signers)),
				received:          make(map[string]struct{}),
			})

			connectEvt := &nostr.Event{
				CreatedAt: nostr.Now(),
				Kind:      common.ConnectionKind,
				Tags: nostr.Tags{
					nostr.Tag{"p", targetPubkey},
					nostr.Tag{"peer", event.PubKey},
				},
			}
			connectEvt.Sign(s.PrivateKey)
			relay.BroadcastEvent(connectEvt)

			// and we wait for the result
			nip46Session = <-callback
		} else {
			nip46Session = n46
		}
		signEvent = func(e *nostr.Event) error { return kuc.Sign(e) }
	}

	req, err := nip46Session.ParseRequest(event)
	if err != nil {
		log.Warn().Err(err).Str("from", event.PubKey).Str("to", targetPubkey).
			Msg("failed to parse request")
		return
	}

	switch req.Method {
	case "connect":
		result = "ack"
	case "create_account":
		if nip46Session == mainSession {
			// to create an account we must notify our registered signers and then get their partial public keys
			if len(req.Params) < 3 {
				resultErr = fmt.Errorf("missing params")
			} else if nameWasUsed(req.Params[0]) {
				resultErr = fmt.Errorf("name already used")
			} else if req.Params[1] != s.Domain {
				resultErr = fmt.Errorf("unsupported domain " + req.Params[1])
			} else {
				pkuc := &PendingKeyUserContext{
					name:              req.Params[0],
					signerMainKeys:    s.RegisteredSigners,
					partialPublicKeys: make([][]byte, len(s.RegisteredSigners)),
				}
				// the id of the pending thing is the id of the event we will use to signal this creation
				creationEvt := &nostr.Event{
					CreatedAt: nostr.Now(),
					Kind:      common.AccountCreationKind,
					Tags:      nostr.Tags{},
				}
				creationEvt.Sign(s.PrivateKey)
				pendingCreation.Store(creationEvt.ID, pkuc)
				relay.BroadcastEvent(creationEvt)

				// now we wait until the account is create before we return the public key to the caller
				aggpk := <-pkuc.callback
				result = aggpk
			}
		} else {
			resultErr = fmt.Errorf("can't create accounts here")
		}
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

		if err := signEvent(&evt); err != nil {
			resultErr = fmt.Errorf("failed to sign event: %w", err)
			break
		}
		jrevt, _ := easyjson.Marshal(evt)
		result = string(jrevt)
	}

	_, eventResponse, err := nip46Session.MakeResponse(req.ID, event.PubKey, result, resultErr)
	if err != nil {
		log.Warn().Err(err).Msg("failed to make response")
		return
	}

	if err := signEvent(&eventResponse); err != nil {
		log.Warn().Err(err).Msg("failed to sign response")
		return
	}

	relay.BroadcastEvent(&eventResponse)
}
