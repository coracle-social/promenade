package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nbd-wtf/go-nostr"
	"github.com/urfave/cli/v3"
)

var (
	dir  string
	pool *nostr.SimplePool
	data Data
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
			Name:        "dir",
			Aliases:     []string{"d"},
			Usage:       "path to the directory that stores things",
			Destination: &dir,
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
		if err := lockDir(); err != nil {
			return fmt.Errorf("can't run two instances of signer at the same directory '%s': %w", dir, err)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		go func() {
			<-ctx.Done()
			unlockDir()
		}()

		data, err := readData(dir)
		if err != nil {
			return err
		}

		publicKey, _ := nostr.GetPublicKey(data.SecretKey)
		fmt.Fprintf(os.Stderr, "[] running as %s\n", publicKey)

		pool = nostr.NewSimplePool(context.Background(),
			nostr.WithAuthHandler(
				func(ctx context.Context, ie nostr.RelayEvent) error {
					return ie.Event.Sign(data.SecretKey)
				},
			),
		)

		signerCtx, cancelSigner := context.WithCancel(ctx)
		go runSigner(signerCtx)

		restartSigner := func() {
			fmt.Fprintf(os.Stderr, "[signer] restarting signer...\n")
			cancelSigner()
			signerCtx, cancelSigner = context.WithCancel(ctx)
			go runSigner(signerCtx)
		}

		if relay := c.String("accept-relay"); relay != "" {
			go runAcceptor(ctx, relay, c.Uint("accept-max"), restartSigner)
		}

		<-ctx.Done()

		return nil
	},
}
