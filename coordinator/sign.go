package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sync"

	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/puzpuzpuz/xsync/v3"
)

var (
	onlineSigners                = xsync.NewMapOf[string, int]()
	groupContextsByHandlerPubKey = xsync.NewMapOf[string, *GroupContext]()
	signingSessions              = xsync.NewMapOf[string, Session]()
	lambdaRegistry               = make(frost.LambdaRegistry)
	lambdaRegistryLock           = sync.Mutex{}
)

type GroupContext struct {
	common.AccountRegistration
}

type Session struct {
	chosenSigners map[string]common.Signer
	ch            chan *nostr.Event
}

func (kuc *GroupContext) GetPublicKey(ctx context.Context) (string, error) {
	return kuc.PubKey, nil
}

func (kuc *GroupContext) SignEvent(ctx context.Context, event *nostr.Event) error {
	ipk, _ := hex.DecodeString("02" + kuc.PubKey)
	pubkey, _ := btcec.ParseJacobian(ipk)

	// signers that are online and that we have chosen to participate in this round
	chosenSigners := make(map[string]common.Signer, kuc.Threshold)

	cfg := &frost.Configuration{
		Threshold:    int(kuc.Threshold),
		MaxSigners:   len(kuc.Signers),
		PublicKey:    &pubkey,
		Participants: make([]int, len(kuc.Signers)),
	}
	for s, signer := range kuc.Signers {
		cfg.Participants[s] = signer.Shard.ID

		if len(chosenSigners) < cfg.Threshold {
			if _, isOnline := onlineSigners.Load(signer.PeerPubKey); isOnline {
				chosenSigners[signer.PeerPubKey] = signer
			}
		}
	}

	// fail if we don't have enough online signers
	if len(chosenSigners) < cfg.Threshold {
		return fmt.Errorf("not enough signers online: have %d, needed %d", len(chosenSigners), cfg.Threshold)
	}

	// step-1 (send): initialize each participant.
	//
	// this should cause the signers to reply with their nonces commits and then with their signatures.
	confEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindConfiguration,
		Content:   cfg.Hex(),
		Tags:      make(nostr.Tags, len(chosenSigners)),
	}
	i := 0
	for _, signer := range chosenSigners {
		confEvt.Tags[i] = nostr.Tag{"p", signer.PeerPubKey}
		i++
	}
	confEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(confEvt)

	// each signing session is identified by this initial event's id
	sessionId := confEvt.ID
	ch := make(chan *nostr.Event)
	signingSessions.Store(sessionId, Session{
		ch:            ch,
		chosenSigners: chosenSigners,
	})

	// step-2 (receive): get all pre-commit nonces from signers
	commitments := make(map[string]frost.Commitment, len(chosenSigners))
	for _, signer := range chosenSigners {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout receiving commit")
		case evt := <-ch:
			if evt.Kind != common.KindCommit {
				return fmt.Errorf("got a kind %d instead of %d (commit) from %s",
					evt.Kind, common.KindCommit, evt.PubKey)
			}

			commit := frost.Commitment{}
			if err := commit.DecodeHex(evt.Content); err != nil {
				return fmt.Errorf("failed to decode commit: %w", err)
			}
			commitments[signer.PeerPubKey] = commit
		}
	}

	// prepare event to be signed so we have our msg hash
	event.PubKey = hex.EncodeToString(cfg.PublicKey.X.Bytes()[:])
	msg := sha256.Sum256(event.Serialize())
	event.ID = hex.EncodeToString(msg[:])

	// prepare aggregated group commitment and finalNonce
	groupCommitment, bindingCoefficient, finalNonce := cfg.ComputeGroupCommitment(
		slices.Collect(maps.Values(commitments)), msg[:])

	// step-3 (send): group commits and send the result to signers
	groupCommitEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindGroupCommit,
		Content:   groupCommitment.Hex(),
		Tags:      make(nostr.Tags, 1+len(chosenSigners)),
	}
	groupCommitEvt.Tags[0] = nostr.Tag{"e", sessionId}
	i = 0
	for _, signer := range chosenSigners {
		groupCommitEvt.Tags[1+i] = nostr.Tag{"p", signer.PeerPubKey}
		i++
	}
	groupCommitEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(groupCommitEvt)

	// step-4 (send): send event to be signed
	jevt, _ := easyjson.Marshal(event)
	evtEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindEventToBeSigned,
		Content:   string(jevt),
		Tags:      make(nostr.Tags, 1+len(chosenSigners)),
	}
	evtEvt.Tags[0] = nostr.Tag{"e", sessionId}
	i = 0
	for _, signer := range chosenSigners {
		evtEvt.Tags[1+i] = nostr.Tag{"p", signer.PeerPubKey}
		i++
	}
	evtEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(evtEvt)

	// step-5 (receive): get partial signature from each participant
	partialSigs := make([]frost.PartialSignature, len(chosenSigners))
	i = 0
	for range chosenSigners {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout receiving partial signature")
		case evt := <-ch:
			if evt.Kind != common.KindPartialSignature {
				return fmt.Errorf("got a kind %d instead of %d (partial sig) from %s",
					evt.Kind, common.KindPartialSignature, evt.PubKey)
			}

			partialSig := frost.PartialSignature{}
			if err := partialSig.DecodeHex(evt.Content); err != nil {
				return fmt.Errorf("failed to decode partial signature from %s", evt.PubKey)
			}

			lambdaRegistryLock.Lock()
			if err := cfg.VerifyPartialSignature(
				chosenSigners[evt.PubKey].Shard,
				commitments[evt.PubKey].BinoncePublic,
				bindingCoefficient,
				finalNonce,
				partialSig,
				msg[:],
				lambdaRegistry,
			); err != nil {
				lambdaRegistryLock.Unlock()
				return fmt.Errorf("partial signature from %s isn't good: %w", evt.PubKey, err)
			}
			lambdaRegistryLock.Unlock()

			partialSigs[i] = partialSig
			i++
		}
	}

	// aggregate signature
	sig, err := cfg.AggregateSignatures(finalNonce, partialSigs)
	if err != nil {
		return fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	event.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

func (kuc *GroupContext) Encrypt(
	ctx context.Context,
	plaintext string,
	recipientPublicKey string,
) (base64ciphertext string, err error) {
	return "", fmt.Errorf("not implemented")
}

func (kuc *GroupContext) Decrypt(
	ctx context.Context,
	base64ciphertext string,
	senderPublicKey string,
) (plaintext string, err error) {
	return "", fmt.Errorf("not implemented")
}

func handleSignerStuff(ctx context.Context, evt *nostr.Event) {
	if !slices.Contains([]int{common.KindCommit, common.KindPartialSignature}, evt.Kind) {
		return
	}

	eTag := evt.Tags.GetFirst([]string{"e", ""})
	if eTag == nil {
		return
	}

	sessionId := (*eTag)[1]

	if session, ok := signingSessions.Load(sessionId); ok {
		if _, ok := session.chosenSigners[evt.PubKey]; ok {
			session.ch <- evt
		}
	}
}
