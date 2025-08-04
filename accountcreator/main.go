package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"slices"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/keyer"
	"fiatjaf.com/nostr/nip13"
	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/urfave/cli/v3"
)

var (
	dir                    string
	pool                   = nostr.NewPool(nostr.PoolOptions{})
	hardcodedAckReadRelays = []string{"wss://relay.primal.net", "wss://pyramid.fiatjaf.com", "wss://relay.damus.io", "wss://nostr-pub.wellorder.net"}
)

func main() {
	err := app.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialization error: %s\n", err)
		os.Exit(1)
	}
}

var app = &cli.Command{
	Name:        "accountcreator",
	Description: "debugging tool for creating accounts in the frost coordinator",
	Commands: []*cli.Command{
		create,
	},
}

var create = &cli.Command{
	Name:  "create",
	Usage: "takes a secret key and splitting parameters, negotiates registration with signers, then registers with the coordinator",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "sec",
			Usage: "our secret key that will be split",
		},
		&cli.StringFlag{
			Name:  "coordinator",
			Usage: "relay we chose to act as our coordinator",
		},
		&cli.StringSliceFlag{
			Name:  "signer",
			Usage: "permanent pubkeys of the signers we've chosen",
		},
		&cli.UintFlag{
			Name:  "threshold",
			Usage: "minimum number of signers required (must be lower than or equal to the total number of signers)",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		fmt.Fprintf(os.Stderr, ". preparing stuff\n")

		signerPubkeys := make([]nostr.PubKey, 0, 6)
		for _, pkh := range c.StringSlice("signer") {
			pk, err := nostr.PubKeyFromHex(pkh)
			if err != nil {
				return fmt.Errorf("invalid pubkey '%s': %w", pkh, err)
			}
			signerPubkeys = append(signerPubkeys, pk)
		}
		threshold := int(c.Uint("threshold"))
		coordinator := nostr.NormalizeURL(c.String("coordinator"))

		if threshold == 0 || threshold > len(signerPubkeys) {
			return fmt.Errorf("invalid threshold")
		}

		if !nostr.IsValidRelayURL(coordinator) {
			return fmt.Errorf("coordinator URL '%s' is invalid", coordinator)
		}

		ar := common.AccountRegistration{
			Threshold:     threshold,
			Signers:       make([]common.Signer, len(signerPubkeys)),
			HandlerSecret: nostr.Generate(),
		}

		sec, err := nostr.SecretKeyFromHex(c.String("sec"))
		if err != nil {
			return fmt.Errorf("invalid sec")
		}
		secret := new(btcec.ModNScalar)
		secret.SetBytes((*[32]byte)(&sec))
		kr := keyer.NewPlainKeySigner(sec)
		pub, _ := kr.GetPublicKey(ctx)

		fmt.Fprintf(os.Stderr, ". grabbing their inbox relays\n")

		inboxes := make(map[nostr.PubKey][]string, len(signerPubkeys)+1)
		for evt := range pool.FetchMany(ctx, common.IndexRelays, nostr.Filter{
			Kinds:   []nostr.Kind{10002},
			Authors: append(signerPubkeys, pub),
		}, nostr.SubscriptionOptions{}) {
			inbox := make([]string, 0, len(evt.Tags))
			for tag := range evt.Tags.FindAll("r") {
				if len(tag) == 2 || tag[2] == "read" {
					inbox = append(inbox, tag[1])
				}
			}
			inboxes[evt.PubKey] = inbox
		}

		fmt.Fprintf(os.Stderr, ". sharding key\n")

		shards, agg, _ := frost.TrustedKeyDeal(secret, ar.Threshold, len(ar.Signers))
		if *agg.X.Bytes() != pub {
			return fmt.Errorf("the split went wrong")
		}

		// gather replies from the shards we're sending right now
		fmt.Fprintf(os.Stderr, ". listening for responses\n")
		acks := make([]nostr.PubKey, 0, len(signerPubkeys))
		ourReadRelays, _ := inboxes[pub]
		if len(ourReadRelays) == 0 {
			return fmt.Errorf("we need some read relays first")
		}
		ack := make(chan struct{})

		shardsSentEventId := make(map[nostr.ID]struct{})

		go func() {
			for evt := range pool.SubscribeMany(ctx, append(ourReadRelays, hardcodedAckReadRelays...), nostr.Filter{
				Kinds: []nostr.Kind{common.KindShardACK},
				Tags: nostr.TagMap{
					"p": []string{pub.Hex()},
				},
			}, nostr.SubscriptionOptions{}) {
				eTag := evt.Tags.Find("e")
				if eTag == nil {
					continue
				}
				id, err := nostr.IDFromHex(eTag[1])
				if err != nil {
					continue
				}

				if _, isShardSent := shardsSentEventId[id]; !isShardSent {
					continue
				}

				if slices.Contains(signerPubkeys, evt.PubKey) && !slices.Contains(acks, evt.PubKey) {
					acks = append(acks, evt.PubKey)
					if len(acks) == len(signerPubkeys) {
						ack <- struct{}{}
					}
				}
			}
		}()

		// send one shard to each signer
		for s, shard := range shards {
			signer := signerPubkeys[s]
			fmt.Fprintf(os.Stderr, ". sending shard to %s\n", signer)

			ar.Signers[s].PeerPubKey = signer
			ar.Signers[s].Shard = shard.PublicKeyShard

			relays, _ := inboxes[signer]
			if len(relays) == 0 {
				return fmt.Errorf("signer %s doesn't have inbox relays", signer)
			}

			ciphertext, err := kr.Encrypt(ctx, shard.Hex(), signer)
			if err != nil {
				return fmt.Errorf("failed to encrypt to %s: %w", signer, err)
			}
			shardEvt := nostr.Event{
				CreatedAt: nostr.Now(),
				Kind:      common.KindShard,
				Content:   ciphertext,
				Tags: nostr.Tags{
					{"p", signer.Hex()},
					{"coordinator", coordinator},
					append(nostr.Tag{"reply"}, hardcodedAckReadRelays...),
				},
				PubKey: pub,
			}
			fmt.Fprintf(os.Stderr, ". doing work\n")
			tag, err := nip13.DoWork(ctx, shardEvt, 22)
			if err != nil {
				return fmt.Errorf("failed to add work to shard event: %w", err)
			}
			shardEvt.Tags = append(shardEvt.Tags, tag)
			shardEvt.Sign(sec)
			shardsSentEventId[shardEvt.ID] = struct{}{}
			ok := false
			errs := make([]error, len(relays))
			for res := range pool.PublishMany(ctx, relays, shardEvt) {
				if res.Error == nil {
					ok = true
				} else {
					errs[slices.Index(relays, res.RelayURL)] = res.Error
				}
			}
			if !ok {
				return fmt.Errorf("failed to send shard to %s: %v", signer, errs)
			}
		}

		// in the meantime create the root profile
		secretRand := make([]byte, 10)
		if _, err := rand.Read(secretRand); err != nil {
			panic(err)
		}

		ar.Profiles = append(ar.Profiles, common.AccountProfile{
			Name:         "__root__",
			Restrictions: nil, // full authorization
			Secret:       strings.ToLower(base32.StdEncoding.EncodeToString(secretRand)),
		})

		// wait until all the signers have answered
		fmt.Fprintf(os.Stderr, ". waiting for acks from all signers\n")
		<-ack

		// notify the coordinator
		fmt.Fprintf(os.Stderr, ". registering on coordinator %s\n", coordinator)
		evt := ar.Encode()
		evt.Sign(sec)
		for res := range pool.PublishMany(ctx, []string{coordinator}, evt) {
			if res.Error != nil {
				return fmt.Errorf("failed to notify the coordinator: %w", res.Error)
			} else {
				fmt.Fprintf(os.Stderr, ". done\n")
			}
		}

		fmt.Printf("bunker://%s?relay=%s&secret=%s\n",
			ar.HandlerSecret.Public().Hex(), coordinator, ar.Profiles[0].Secret)

		return nil
	},
}
