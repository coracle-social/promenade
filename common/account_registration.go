package common

import (
	"encoding/json"
	"fmt"
	"strconv"

	"fiatjaf.com/nostr"
	"fiatjaf.com/promenade/frost"
)

// this is the type represented by the event kind 16430
// each coordinator relay may keep one of these for each registered user
type AccountRegistration struct {
	// aggregated pubkey
	PubKey nostr.PubKey

	// this is the keypair the coordinator will use to handle signing requests from clients
	HandlerSecret nostr.SecretKey

	Threshold int
	Signers   []Signer // len() == MaxSigners

	Profiles []AccountProfile

	Event *nostr.Event
}

// this represents a different profile inside an account -- each profile has a unique "secret" and policies
type AccountProfile struct {
	Name string

	// included in the event as encoded json -- nil if it's an empty string and all is allowed
	Restrictions *ProfileRestrictions

	// given by base64encode(sha256(handlersecret + this_profile_name + encoded_restrictions))
	Secret string
}

type ProfileRestrictions struct {
	OnlyKinds []nostr.Kind    `json:"k"`
	ExpiresAt nostr.Timestamp `json:"u"`
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

	// profiles
	for tag := range evt.Tags.FindAll("profile") {
		if len(tag) != 4 {
			return fmt.Errorf("invalid profile tag length: 4 expected, got %d", len(tag))
		}

		profile := AccountProfile{
			Name:   tag[1],
			Secret: tag[2],
		}

		if tag[3] == "" {
			// no restrictions
		} else {
			// parse restrictions
			profile.Restrictions = &ProfileRestrictions{}
			err := json.Unmarshal([]byte(tag[3]), profile.Restrictions)
			if err != nil {
				return fmt.Errorf("invalid restrictions")
			}
		}

		a.Profiles = append(a.Profiles, profile)
	}
	if len(a.Profiles) == 0 {
		return fmt.Errorf("must have at least one profile")
	}

	return nil
}

func (a AccountRegistration) Encode() nostr.Event {
	tags := make(nostr.Tags, 3, 3+len(a.Signers)+len(a.Profiles))
	tags[0] = nostr.Tag{"threshold", strconv.Itoa(a.Threshold)}
	tags[1] = nostr.Tag{"handlersecret", a.HandlerSecret.Hex()}
	tags[2] = nostr.Tag{"h", a.HandlerSecret.Public().Hex()}
	for _, signer := range a.Signers {
		tags = append(tags, nostr.Tag{"p", signer.PeerPubKey.Hex(), signer.Shard.Hex()})
	}
	for _, profile := range a.Profiles {
		restrictionsJSON := []byte{}
		if profile.Restrictions != nil {
			restrictionsJSON, _ = json.Marshal(profile.Restrictions)
		}
		tags = append(tags, nostr.Tag{"profile", profile.Name, profile.Secret, string(restrictionsJSON)})
	}

	return nostr.Event{
		Kind:      KindAccountRegistration,
		CreatedAt: nostr.Now(),
		Tags:      tags,
		PubKey:    a.PubKey,
	}
}
