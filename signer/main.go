package main

import (
	"context"
	"fmt"
	"os"

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
	Name: "promd",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "dir",
			Aliases: []string{"d"},
			Usage:   "path to the directory that stores things",
		},
	},
	Before: func(ctx context.Context, c *cli.Command) error {
		data, err := readData(c.String("dir"))
		if err != nil {
			return err
		}

		publicKey, _ := nostr.GetPublicKey(data.SecretKey)
		fmt.Fprintf(os.Stderr, "running as %s\n", publicKey)

		pool = nostr.NewSimplePool(context.Background(),
			nostr.WithAuthHandler(
				func(ctx context.Context, ie nostr.RelayEvent) error {
					return ie.Event.Sign(data.SecretKey)
				},
			),
		)

		return nil
	},
	Commands: []*cli.Command{
		run,
	},
	DefaultCommand: "run",
}
