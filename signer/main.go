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
		log.Error().Err(err).Msgf("initialization error")
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
			Name:  "shards-db",
			Usage: "path to the eventstore directory",
			Value: "./shards",
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
		store = &badger.BadgerBackend{Path: c.String("shards-db")}
		err := store.Init()
		if err != nil {
			return fmt.Errorf("failed to open db at %s: %w", c.String("shards-db"), err)
		}

		kr, err = keyer.New(ctx, pool, c.String("sec"), nil)
		if err != nil {
			return fmt.Errorf("invalid secret key: %w", err)
		}

		pool = nostr.NewPool(nostr.PoolOptions{
			AuthHandler: kr.SignEvent,
		})

		publicKey, _ := kr.GetPublicKey(ctx)
		log.Info().Msgf("[] running as %s", publicKey)

		signerCtx, cancelSigner := context.WithCancelCause(ctx)

		restartSigner := func() {
			log.Info().Msg("[signer] restarting signer...")
			cancelSigner(fmt.Errorf("restarted"))
			signerCtx, cancelSigner = context.WithCancelCause(ctx)
			go func() {
				err = runSigner(signerCtx)
			}()
		}

		acceptorDone := make(chan struct{})
		if relays := c.StringSlice("accept-relay"); len(relays) > 0 {
			go func() {
				runAcceptor(ctx, relays, c.Uint("min-pow"), restartSigner)
				close(acceptorDone)
			}()
		} else {
			close(acceptorDone)
			log.Warn().Msg("not accepting new key shards because --accept-relay wasn't set")
		}

		err = runSigner(signerCtx)
		<-acceptorDone
		return err
	},
}
