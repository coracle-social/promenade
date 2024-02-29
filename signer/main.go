package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
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
		dir = c.String("dir")
		if dir == "" {
			var err error
			dir, err = homedir.Expand("~/.config/promd")
			if err != nil {
				return fmt.Errorf("can't get ~/.config/promd directory: %w", err)
			}
		}

		if bdata, err := os.ReadFile(filepath.Join(dir, "data.json")); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read data.json: %w", err)
		} else if err := json.Unmarshal(bdata, &data); err != nil && len(bdata) != 0 {
			return fmt.Errorf("error parsing data.json ('%s'): %w", string(bdata), err)
		} else if len(bdata) == 0 {
			os.MkdirAll(dir, 0777)
			randkey := make([]byte, 32)
			rand.Read(randkey)

			data = Data{
				SecretKey: hex.EncodeToString(randkey),
				Accounts:  make([]Account, 0),
				RelayAgreements: []RelayAgreement{
					{
						URL:                  "ws://localhost:6363",
						AcceptingNewAccounts: true,
					},
				},
			}
			if err := storeData(data); err != nil {
				return err
			}
		}

		pool = nostr.NewSimplePool(context.Background(), nostr.WithAuthHandler(func(authEvent *nostr.Event) error {
			return authEvent.Sign(data.SecretKey)
		}))

		publicKey, _ := nostr.GetPublicKey(data.SecretKey)
		fmt.Fprintf(os.Stderr, "running as %s\n", publicKey)

		return nil
	},
	Commands: []*cli.Command{
		run,
	},
	DefaultCommand: "run",
}

func storeData(data Data) error {
	jdata, _ := json.MarshalIndent(data, "", "  ")

	if err := os.WriteFile(filepath.Join(dir, "data.json"), jdata, 0644); err != nil {
		return err
	}

	return nil
}
