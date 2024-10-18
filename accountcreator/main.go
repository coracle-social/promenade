package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"slices"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
	"github.com/nbd-wtf/go-nostr/nip13"
	"github.com/urfave/cli/v3"
)

var (
	dir  string
	pool = nostr.NewSimplePool(context.Background())
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

		signerPubkeys := c.StringSlice("signer")
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
			HandlerSecret: nostr.GeneratePrivateKey(),
		}

		sec := c.String("sec")
		secret := new(btcec.ModNScalar)
		secbytes, err := hex.DecodeString(sec)
		if err != nil {
			return fmt.Errorf("invalid sec")
		}
		secret.SetByteSlice(secbytes)
		kr, _ := keyer.NewPlainKeySigner(sec)
		pub, _ := kr.GetPublicKey(ctx)

		fmt.Fprintf(os.Stderr, ". grabbing their inbox relays\n")

		inboxes := make(map[string][]string, len(signerPubkeys)+1)
		for evt := range pool.SubManyEose(ctx, common.IndexRelays, nostr.Filters{
			{Kinds: []int{10002}, Authors: append(signerPubkeys, pub)},
		}) {
			inbox := make([]string, 0, len(evt.Tags))
			for _, tag := range evt.Tags.All([]string{"r", ""}) {
				if len(tag) == 2 || tag[2] == "read" {
					inbox = append(inbox, tag[1])
				}
			}
			inboxes[evt.PubKey] = inbox
		}

		fmt.Fprintf(os.Stderr, ". sharding key\n")

		shards, agg, _ := frost.TrustedKeyDeal(secret, ar.Threshold, len(ar.Signers))
		if agg.X.String() != pub {
			return fmt.Errorf("the split went wrong")
		}

		// gather replies from the shards we're sending right now
		fmt.Fprintf(os.Stderr, ". listening for responses\n")
		acks := make([]string, 0, len(signerPubkeys))
		ourReadRelays, _ := inboxes[pub]
		if len(ourReadRelays) == 0 {
			return fmt.Errorf("we need some read relays first")
		}
		ack := make(chan struct{})
		go func() {
			for evt := range pool.SubMany(ctx, ourReadRelays, nostr.Filters{
				{
					Kinds: []int{common.KindShardACK},
					Tags: nostr.TagMap{
						"p": []string{pub},
					},
				},
			}) {
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

			if !nostr.IsValidPublicKey(signer) {
				return fmt.Errorf("invalid key %s", signer)
			}
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
					{"p", signer},
					{"coordinator", coordinator},
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

			ok := false
			for res := range pool.PublishMany(ctx, relays, shardEvt) {
				if res.Error == nil {
					ok = true
				}
			}
			if !ok {
				return fmt.Errorf("failed to send shard to %s", signer)
			}
		}

		// wait until all the signers have answered
		fmt.Fprintf(os.Stderr, ". waiting for acks from all signers\n")
		<-ack

		// notify the coordinator
		fmt.Fprintf(os.Stderr, ". registering on coordinator\n")
		evt := ar.Encode()
		evt.Sign(sec)
		for res := range pool.PublishMany(ctx, []string{c.String("coordinator")}, evt) {
			if res.Error != nil {
				return fmt.Errorf("failed to notify the coordinator: %w", err)
			}
		}

		fmt.Printf("bunker://%s?relay=%s\n", ar.HandlerPubKey(), coordinator)

		return nil
	},
}
