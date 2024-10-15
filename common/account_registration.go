package common

import (
	"fmt"
	"strconv"

	"fiatjaf.com/promenade/frost"
	"github.com/nbd-wtf/go-nostr"
)

type AccountRegistration struct {
	// aggregated pubkey
	PubKey string

	Threshold int
	Signers   []Signer // len() == MaxSigners

	Event *nostr.Event
}

type Signer struct {
	// Permanent public key of the signer, unrelated to FROST
	PeerPubKey string

	Shard frost.PublicKeyShard
}

func (a *AccountRegistration) Decode(evt *nostr.Event) error {
	if evt.Kind != KindAccountRegistration {
		return fmt.Errorf("wrong kind %d, expected %d", evt.Kind, KindAccountRegistration)
	}

	a.PubKey = evt.PubKey

	if tag := evt.Tags.GetFirst([]string{"threshold", ""}); tag != nil && nostr.IsValidPublicKey((*tag)[1]) {
		var err error
		a.Threshold, err = strconv.Atoi((*tag)[1])
		if err != nil || a.Threshold < 0 || a.Threshold > 10 {
			return fmt.Errorf("'threshold' ('%s') is not a valid number", (*tag)[1])
		}
	} else {
		return fmt.Errorf("missing 'threshold' tag")
	}

	signers := make([]Signer, 0, a.Threshold*2)
	for _, tag := range evt.Tags.All([]string{"signer"}) {
		if len(tag) != 3 {
			return fmt.Errorf("invalid signer tag length: 3 expected, got %d", len(tag))
		}
		if !nostr.IsValidPublicKey(tag[1]) {
			return fmt.Errorf("invalid tag: %v", tag)
		}

		signer := Signer{
			PeerPubKey: tag[1],
		}
		if err := signer.Shard.DecodeHex(tag[2]); err != nil {
			return fmt.Errorf("invalid encoded shard '%s': %w", tag[2], err)
		}

		signers = append(signers, signer)
	}

	if len(signers) < a.Threshold {
		return fmt.Errorf("missing signers")
	}

	return nil
}

func (a AccountRegistration) Encode() nostr.Event {
	tags := make(nostr.Tags, 2, 2+len(a.Signers))
	tags[1] = nostr.Tag{"threshold", strconv.Itoa(a.Threshold)}
	for _, signer := range a.Signers {
		tags = append(tags, nostr.Tag{"signer", signer.PeerPubKey, signer.Shard.Hex()})
	}

	return nostr.Event{
		Kind:      KindAccountRegistration,
		CreatedAt: nostr.Now(),
		Tags:      tags,
		PubKey:    a.PubKey,
	}
}
