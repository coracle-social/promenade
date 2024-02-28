package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"time"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var (
	pending  = make(map[string]*Pending)
	sessions = make(map[string]*Session)
)

var run = &cli.Command{
	Name:        "run",
	Usage:       "starts the signer daemon",
	Description: "",
	Action: func(ctx context.Context, c *cli.Command) error {
		bg := ctx

		dfs := make([]nostr.DirectedFilters, len(data.RelayAgreements))
		for i, relay := range data.RelayAgreements {
			dfs[i] = nostr.DirectedFilters{
				Relay: relay.URL,
				Filters: nostr.Filters{
					{
						Kinds: []int{
							common.AccountCreationKind,
							common.PartialPubkeyKind,
						},
					},
				},
			}
		}

		mainEventStream := pool.BatchedSubMany(bg, dfs)

		for _, account := range data.Accounts {
			go listenForSessionSpecificEvents(bg, mainEventStream, account)
		}

		for ie := range mainEventStream {
			func() {
				ctx, cancel := context.WithTimeout(bg, time.Second*10)
				defer cancel()

				switch ie.Kind {
				case common.AccountCreationKind:
					// generate a key and send it
					key := nostr.GeneratePrivateKey()
					partialPubkeyEvt := nostr.Event{
						CreatedAt: nostr.Now(),
						Kind:      common.PartialPubkeyKind,
						Content:   key,
						Tags: nostr.Tags{
							{"e", ie.ID},
						},
					}
					partialPubkeyEvt.Sign(data.SecretKey)
					ie.Relay.Publish(ctx, partialPubkeyEvt)

					// this comes with the number of signers
					tag := ie.Tags.GetFirst([]string{"signers", ""})
					if tag == nil {
						return
					}
					mainSignersPubkeys := make(map[string]bool)
					for _, item := range (*tag)[1:] {
						if !nostr.IsValidPublicKey(item) {
							return
						}
						mainSignersPubkeys[item] = false
					}

					// initialize it locally
					pending[ie.ID] = &Pending{
						ourSecretKey:       key,
						mainSignersPubkeys: mainSignersPubkeys,
						receivedPubkeys:    make([]string, 0, len(mainSignersPubkeys)),
					}
				case common.PartialPubkeyKind:
					// pubkeys from other people involved in the same signing
					// account thing we are
					e := ie.Tags.GetFirst([]string{"e", ""})
					if e == nil {
						return
					}
					originalEvent := (*e)[1]

					pendingCreation := pending[originalEvent]
					if wasReceivedAlready, exists := pendingCreation.mainSignersPubkeys[ie.PubKey]; !exists || wasReceivedAlready {
						return
					}

					pendingCreation.mainSignersPubkeys[ie.PubKey] = true
					pendingCreation.receivedPubkeys = append(pendingCreation.receivedPubkeys, ie.Content)
					if len(pendingCreation.receivedPubkeys) == len(pendingCreation.mainSignersPubkeys) {
						// we've received all pubkeys,
						// we can now record this and open a session
						slices.Sort(pendingCreation.receivedPubkeys)
						account := Account{
							Relay:            ie.Relay.URL,
							PartialSecretKey: pendingCreation.ourSecretKey,
							Signers:          pendingCreation.receivedPubkeys,
						}

						data.Accounts = append(data.Accounts, account)
						if err := storeData(data); err != nil {
							return
						}

						delete(pending, originalEvent)

						session := makeSession(account)
						aggpk := session.aggpk()
						sessions[aggpk] = session

						// when opening a session we must also subscribe to the correct filter
						go listenForSessionSpecificEvents(bg, mainEventStream, account)
					}

				case common.ConnectionKind:
					p := ie.Tags.GetFirst([]string{"p", ""})
					aggpk := (*p)[1]
					session, ok := sessions[aggpk]
					if !ok {
						return
					}

					external := ie.Tags.GetFirst([]string{"peer", ""})
					if external == nil {
						return
					}
					externalPubkey := (*external)[1]

					// at this point we must share our ECDH partial for  the given connection
					// so the server can decrypt the message
					pe, err := getPartialECDH(session.account.Signers, session.account.PartialSecretKey, externalPubkey)
					if err != nil {
						return
					}

					ecdhEvt := nostr.Event{
						CreatedAt: nostr.Now(),
						Kind:      common.PartialSharedKeyKind,
						Content:   pe,
						Tags: nostr.Tags{
							{"p", aggpk},
							{"peer", externalPubkey},
						},
					}
					ecdhEvt.Sign(session.account.PartialSecretKey)
					ie.Relay.Publish(ctx, ecdhEvt)
				case common.EventToPartiallySignKind:
					p := ie.Tags.GetFirst([]string{"p", ""})
					aggpk := (*p)[1]
					session, ok := sessions[aggpk]
					if !ok {
						return
					}

					// start a new signing session for the given event id
					targetEvent := &nostr.Event{}
					err := easyjson.Unmarshal([]byte(ie.Content), targetEvent)
					if err != nil || targetEvent.ID != targetEvent.GetID() {
						fmt.Fprintf(os.Stderr, "got invalid event to sign")
						return
					}
					sessions[aggpk].eventBeingSigned = targetEvent.ID

					// send our nonce
					nonce := session.signSession.PublicNonce()
					nonceEvt := nostr.Event{
						CreatedAt: nostr.Now(),
						Kind:      common.NonceKind,
						Content:   hex.EncodeToString(nonce[:]),
						Tags: nostr.Tags{
							{"e", targetEvent.ID},
							{"p", aggpk},
						},
					}
					nonceEvt.Sign(session.account.PartialSecretKey)
					ie.Relay.Publish(ctx, nonceEvt)
				case common.NonceKind:
					p := ie.Tags.GetFirst([]string{"p", ""})
					aggpk := (*p)[1]
					session, ok := sessions[aggpk]
					if !ok {
						return
					}

					var nonce [musig2.PubNonceSize]byte
					if _, err := hex.Decode(nonce[:], []byte(ie.Content)); err != nil {
						log.Warn().Str("src", ie.PubKey).Err(err).Msg("invalid nonce")
						return
					}

					e := ie.Tags.GetFirst([]string{"e", ""})
					if e == nil {
						return
					}
					target := (*e)[1]
					if session.eventBeingSigned != target {
						return
					}

					if _, ok := session.noncesReceived[ie.PubKey]; ok {
						return
					} else {
						session.noncesReceived[ie.PubKey] = struct{}{}
						ok, _ := session.signSession.RegisterPubNonce(nonce)
						if ok {
							// we have all the nonces -- we can now share our partial signature
							var msg [32]byte
							hex.Decode(msg[:], []byte(session.eventBeingSigned))
							ps, err := session.signSession.Sign(msg)
							if err != nil {
								log.Warn().Err(err).Msg("failed to generate partial signature")
								return
							}
							psb := ps.S.Bytes()

							psEvt := nostr.Event{
								CreatedAt: nostr.Now(),
								Kind:      common.PartialSigKind,
								Content:   hex.EncodeToString(psb[:]),
								Tags: nostr.Tags{
									{"e", session.eventBeingSigned},
									{"p", aggpk},
								},
							}
							ie.Relay.Publish(ctx, psEvt)
						}
					}
				}
			}()
		}

		return nil
	},
}
