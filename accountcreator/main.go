package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/urfave/cli/v3"
)

var (
	dir  string
	pool *nostr.SimplePool
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
		shardkey,
	},
}

var shardkey = &cli.Command{
	Name:  "shardkey",
	Usage: "takes a secret key and splitting parameters, outputs a nostr event for account registration",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "sec",
		},
		&cli.StringSliceFlag{
			Name: "signer",
		},
		&cli.UintFlag{
			Name: "threshold",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		signerPubkeys := c.StringSlice("signer")
		threshold := int(c.Uint("threshold"))

		if threshold == 0 || threshold > len(signerPubkeys) {
			return fmt.Errorf("invalid threshold")
		}

		ar := common.AccountRegistration{
			Threshold:     threshold,
			Signers:       make([]common.Signer, len(signerPubkeys)),
			HandlerSecret: nostr.GeneratePrivateKey(),
		}
		ar.HandlerPublic, _ = nostr.GetPublicKey(ar.HandlerSecret)

		for s, signer := range signerPubkeys {
			if !nostr.IsValidPublicKey(signer) {
				return fmt.Errorf("invalid key %s", signer)
			}

			ar.Signers[s].PeerPubKey = signer
		}

		sec := c.String("sec")
		secret := new(btcec.ModNScalar)
		secbytes, err := hex.DecodeString(sec)
		if err != nil {
			return fmt.Errorf("invalid sec")
		}
		secret.SetByteSlice(secbytes)

		shards, agg, _ := frost.TrustedKeyDeal(secret, ar.Threshold, len(ar.Signers))
		for s, shard := range shards {
			ar.Signers[s].Shard = shard.PublicKeyShard

			fmt.Println("SHARD", ar.Signers[s].PeerPubKey, "=>", shard.Hex())
		}

		pubkey, _ := nostr.GetPublicKey(sec)
		if agg.X.String() != pubkey {
			return fmt.Errorf("something went wrong")
		}

		evt := ar.Encode()
		evt.Sign(sec)

		fmt.Println(evt)
		return nil
	},
}
