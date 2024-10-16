package main

import (
	"context"
	"fmt"
	"os"
	"slices"

	"fiatjaf.com/promenade/common"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"
	"github.com/urfave/cli/v3"
)

var run = &cli.Command{
	Name:        "run",
	Usage:       "starts the signer daemon",
	Description: "",
	Action: func(ctx context.Context, c *cli.Command) error {
		bg := ctx

		ourPubkey, _ := nostr.GetPublicKey(data.SecretKey)

		filter := nostr.Filter{
			Kinds: []int{common.KindCommit, common.KindConfiguration, common.KindEventToBeSigned},
			Tags: nostr.TagMap{
				"p": []string{ourPubkey},
			},
		}

		dfs := make([]nostr.DirectedFilters, 0, 2)
		for i, kg := range data.KeyGroups {
			idx := slices.IndexFunc(dfs, func(df nostr.DirectedFilters) bool {
				return df.Relay == nostr.NormalizeURL(kg.Coordinator)
			})
			if idx == -1 {
				info, err := nip11.Fetch(bg, kg.Coordinator)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error on nip11 request to %s on group %d: %s\n", kg.Coordinator, i, err)
					continue
				} else if !nostr.IsValidPublicKey(info.PubKey) {
					fmt.Fprintf(os.Stderr, "coordinator %s has invalid pubkey %s on group %d\n", kg.Coordinator, info.PubKey, i)
					continue
				}
				filter.Authors = []string{info.PubKey}
				dfs = append(dfs, nostr.DirectedFilters{
					Relay:   nostr.NormalizeURL(kg.Coordinator),
					Filters: nostr.Filters{filter},
				})
			}
		}

		mainEventStream := pool.BatchedSubMany(bg, dfs)

		for ie := range mainEventStream {
			evt := ie.Event
			switch evt.Kind {
			case common.KindConfiguration:
				ch := make(chan *nostr.Event)

				go func() {
					err := startSession(ctx, ie.Relay, ch)
					if err != nil {
						fmt.Fprintf(os.Stderr, "failed to start session: %s", err)
					}
				}()

				ch <- evt
			case common.KindCommit, common.KindEventToBeSigned:
				handleInSession(evt)
			}
		}

		return nil
	},
}
