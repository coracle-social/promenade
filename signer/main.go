package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/badger"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
	"github.com/urfave/cli/v3"
)

var (
	kr       nostr.Keyer
	dir      string
	pool     *nostr.SimplePool
	eventsdb eventstore.RelayWrapper
)

func main() {
	err := app.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialization error: %s\n", err)
		os.Exit(1)
	}
}

var app = &cli.Command{
	Name: "signer",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "sec",
			Usage:    "secret key we will use",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "db",
			Usage: "path to the eventstore directory",
			Value: "./db",
		},
		&cli.StringFlag{
			Name:  "accept-relay",
			Usage: "specify a relay URL to use to receive key shards from users that may want to use you as a signer",
		},
		&cli.UintFlag{
			Name:  "accept-max",
			Usage: "just to prevent spam, limit the number of accepted groups to this -- upon restart we will accept up to this number again",
			Value: 30,
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		var err error

		pool = nostr.NewSimplePool(context.Background(),
			nostr.WithAuthHandler(
				func(ctx context.Context, ie nostr.RelayEvent) error {
					return kr.SignEvent(ctx, ie.Event)
				},
			),
		)

		store := &badger.BadgerBackend{Path: c.String("db")}
		err = store.Init()
		if err != nil {
			return fmt.Errorf("failed to open db at %s: %w", c.String("db"), err)
		}
		eventsdb = eventstore.RelayWrapper{Store: store}

		kr, err = keyer.New(ctx, pool, c.String("sec"), nil)
		if err != nil {
			return fmt.Errorf("invalid secret key: %w", err)
		}
		publicKey, _ := kr.GetPublicKey(ctx)
		fmt.Fprintf(os.Stderr, "[] running as %s\n", publicKey)

		signerCtx, cancelSigner := context.WithCancel(ctx)

		restartSigner := func() {
			fmt.Fprintf(os.Stderr, "[signer] restarting signer...\n")
			cancelSigner()
			signerCtx, cancelSigner = context.WithCancel(ctx)
			go runSigner(signerCtx)
		}

		if relay := c.String("accept-relay"); relay != "" {
			go runAcceptor(ctx, relay, c.Uint("accept-max"), restartSigner)
		}

		runSigner(signerCtx)
		return nil
	},
}
