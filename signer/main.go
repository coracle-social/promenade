package main

import (
	"context"
	"fmt"
	"os"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/badger"
	"fiatjaf.com/nostr/keyer"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v3"
)

var (
	kr    nostr.Keyer
	dir   string
	log   = zerolog.New(os.Stderr).Output(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	pool  *nostr.Pool
	store eventstore.Store
)

func main() {
	err := app.Run(context.Background(), os.Args)
	if err != nil {
		log.Debug().Msgf("initialization error: %s", err)
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
		&cli.UintFlag{
			Name:  "min-pow",
			Usage: "how much proof-of-work to require in order to accept a shard",
			Value: 20,
		},
		&cli.StringSliceFlag{
			Name:  "accept-relay",
			Usage: "specify one or more relay URLs to receive key shards from users that may want to use you as a signer",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		var err error

		pool = nostr.NewPool(nostr.PoolOptions{
			AuthHandler: kr.SignEvent,
		})

		store = &badger.BadgerBackend{Path: c.String("db")}
		err = store.Init()
		if err != nil {
			return fmt.Errorf("failed to open db at %s: %w", c.String("db"), err)
		}

		kr, err = keyer.New(ctx, pool, c.String("sec"), nil)
		if err != nil {
			return fmt.Errorf("invalid secret key: %w", err)
		}
		publicKey, _ := kr.GetPublicKey(ctx)
		log.Debug().Msgf("[] running as %s", publicKey)

		signerCtx, cancelSigner := context.WithCancel(ctx)

		restartSigner := func() {
			log.Info().Msg("[signer] restarting signer...")
			cancelSigner()
			signerCtx, cancelSigner = context.WithCancel(ctx)
			go runSigner(signerCtx)
		}

		if relays := c.StringSlice("accept-relay"); len(relays) > 0 {
			go runAcceptor(ctx, relays, c.Uint("min-pow"), restartSigner)
		} else {
			log.Warn().Msg("not accepting new key shards because --accept-relay wasn't set")
		}

		runSigner(signerCtx)
		return nil
	},
}
