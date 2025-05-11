package common

import (
	"fmt"
	"strconv"

	"fiatjaf.com/nostr"
	"fiatjaf.com/promenade/frost"
)

type AccountRegistration struct {
	// aggregated pubkey
	PubKey nostr.PubKey

	// this is the keypair the coordinator will use to handle signing requests from clients
	HandlerSecret nostr.SecretKey

	Threshold int
	Signers   []Signer // len() == MaxSigners

	Event *nostr.Event
}

type Signer struct {
	// Permanent public key of the signer, unrelated to FROST
	PeerPubKey nostr.PubKey

	Shard frost.PublicKeyShard
}

func (a *AccountRegistration) Decode(evt nostr.Event) error {
	if evt.Kind != KindAccountRegistration {
		return fmt.Errorf("wrong kind %d, expected %d", evt.Kind, KindAccountRegistration)
	}

	// the account creation must be signed by the same key that is being split it
	a.PubKey = evt.PubKey

	// the handler secret key is also created by the client and the coordinator is
	//   merely informed about it
	if tag := evt.Tags.Find("handlersecret"); tag == nil {
		return fmt.Errorf("missing 'handlersecret' tag")
	} else {
		var err error
		a.HandlerSecret, err = nostr.SecretKeyFromHex(tag[1])
		if err != nil {
			return fmt.Errorf("invalid 'handlersecret': %w", err)
		}

		handlerPubKey := nostr.GetPublicKey(a.HandlerSecret)
		if tag := evt.Tags.Find("h"); tag == nil {
			return fmt.Errorf("missing 'h' tag")
		} else if handlerPubKey.Hex() != tag[1] {
			return fmt.Errorf("'h' tag pubkey doesn't match 'handlersecret'")
		}
	}

	if tag := evt.Tags.Find("threshold"); tag == nil {
		return fmt.Errorf("missing 'threshold' tag")
	} else {
		var err error
		a.Threshold, err = strconv.Atoi(tag[1])
		if err != nil || a.Threshold <= 0 || a.Threshold > 20 {
			return fmt.Errorf("'threshold' ('%s') is not a valid number", tag[1])
		}
	}

	// each signer is a different 'p' tag
	a.Signers = make([]Signer, 0, a.Threshold*2)
	for tag := range evt.Tags.FindAll("p") {
		if len(tag) != 3 {
			return fmt.Errorf("invalid signer tag length: 3 expected, got %d", len(tag))
		}
		pk, err := nostr.PubKeyFromHex(tag[1])
		if err != nil {
			return fmt.Errorf("invalid tag: %v", tag)
		}

		signer := Signer{
			PeerPubKey: pk,
		}
		if err := signer.Shard.DecodeHex(tag[2]); err != nil {
			return fmt.Errorf("invalid encoded shard '%s': %w", tag[2], err)
		}

		a.Signers = append(a.Signers, signer)
	}

	if len(a.Signers) < a.Threshold {
		return fmt.Errorf("missing signers")
	}

	return nil
}

func (a AccountRegistration) Encode() nostr.Event {
	tags := make(nostr.Tags, 3, 3+len(a.Signers))
	tags[0] = nostr.Tag{"threshold", strconv.Itoa(a.Threshold)}
	tags[1] = nostr.Tag{"handlersecret", a.HandlerSecret.Hex()}
	tags[2] = nostr.Tag{"h", a.HandlerSecret.Public().Hex()}
	for _, signer := range a.Signers {
		tags = append(tags, nostr.Tag{"p", signer.PeerPubKey.Hex(), signer.Shard.Hex()})
	}

	return nostr.Event{
		Kind:      KindAccountRegistration,
		CreatedAt: nostr.Now(),
		Tags:      tags,
		PubKey:    a.PubKey,
	}
}
