package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/mailru/easyjson"
	"github.com/puzpuzpuz/xsync/v3"
)

var (
	onlineSigners                = xsync.NewMapOf[nostr.PubKey, int]()
	groupContextsByHandlerPubKey = xsync.NewMapOf[nostr.PubKey, *GroupContext]()
	signingSessions              = xsync.NewMapOf[nostr.ID, *Session]()
	lambdaRegistry               = make(frost.LambdaRegistry)
	lambdaRegistryLock           = sync.Mutex{}
)

type GroupContext struct {
	common.AccountRegistration
}

type Session struct {
	chosenSigners map[nostr.PubKey]common.Signer
	ch            chan nostr.Event
	status        string
}

func (kuc *GroupContext) GetPublicKey(ctx context.Context) (nostr.PubKey, error) {
	return kuc.PubKey, nil
}

func (kuc *GroupContext) SignEvent(ctx context.Context, event *nostr.Event) (err error) {
	ipk, _ := hex.DecodeString("02" + kuc.PubKey.Hex())
	pubkey, _ := btcec.ParseJacobian(ipk)

	// signers that are online and that we have chosen to participate in this round
	chosenSigners := make(map[nostr.PubKey]common.Signer, kuc.Threshold)

	cfg := &frost.Configuration{
		Threshold:    int(kuc.Threshold),
		MaxSigners:   len(kuc.Signers),
		PublicKey:    &pubkey,
		Participants: make([]int, 0, kuc.Threshold),
	}
	for _, signer := range kuc.Signers {
		if len(chosenSigners) < cfg.Threshold {
			if _, isOnline := onlineSigners.Load(signer.PeerPubKey); isOnline {
				chosenSigners[signer.PeerPubKey] = signer
				cfg.Participants = append(cfg.Participants, signer.Shard.ID)
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
	confEvt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindConfiguration,
		Content:   cfg.Hex(),
		Tags:      make(nostr.Tags, 0, len(chosenSigners)),
	}
	for _, signer := range chosenSigners {
		confEvt.Tags = append(confEvt.Tags, nostr.Tag{"p", signer.PeerPubKey.Hex()})
	}
	confEvt.Sign(s.SecretKey)
	relay.BroadcastEvent(confEvt)

	// each signing session is identified by this initial event's id
	sessionId := confEvt.ID
	ch := make(chan nostr.Event)
	session := &Session{
		ch:            ch,
		chosenSigners: chosenSigners,
		status:        "initializing",
	}
	signingSessions.Store(sessionId, session)

	defer func() {
		// set status to error
		if err != nil {
			session.status = err.Error()
		}

		// keep signing sessions for 5 minutes for debugging then delete them
		go func() {
			time.Sleep(time.Minute * 5)
			signingSessions.Delete(sessionId)
		}()
	}()

	log = log.With().Str("session", sessionId.Hex()).Str("user", cfg.PublicKey.X.String()).Logger()

	log.Info().
		Any("signers", slices.Collect(maps.Keys(chosenSigners))).
		Msg("starting signing session")

	// step-2 (receive): get all pre-commit nonces from signers
	session.status = "nonces"
	commitments := make(map[nostr.PubKey]frost.Commitment, len(chosenSigners))
	missing := make(map[nostr.PubKey]struct{}, len(chosenSigners))
	for pubkey := range chosenSigners {
		missing[pubkey] = struct{}{}
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout receiving commits, missing: %v", slices.Collect(maps.Keys(missing)))
		case evt := <-ch:
			if evt.Kind != common.KindCommit {
				return fmt.Errorf("got a kind %d instead of %d (commit) from %s",
					evt.Kind, common.KindCommit, evt.PubKey)
			}

			if _, ok := chosenSigners[evt.PubKey]; !ok {
				log.Warn().Str("pubkey", evt.PubKey.Hex()).Str("session", sessionId.Hex()).
					Msg("got commit from unrelated signer")
				continue
			}

			commit := frost.Commitment{}
			if err := commit.DecodeHex(evt.Content); err != nil {
				return fmt.Errorf("failed to decode commit: %w", err)
			}
			commitments[evt.PubKey] = commit

			delete(missing, evt.PubKey)
		}

		if len(commitments) == len(chosenSigners) {
			break
		}
	}

	// prepare event to be signed so we have our msg hash
	session.status = "prepare"
	event.PubKey = *cfg.PublicKey.X.Bytes()
	msg := sha256.Sum256(event.Serialize())
	event.ID = msg

	// prepare aggregated group commitment and finalNonce
	session.status = "commit"
	groupCommitment, bindingCoefficient, finalNonce := cfg.ComputeGroupCommitment(
		slices.Collect(maps.Values(commitments)), msg[:])

	// step-3 (send): group commits and send the result to signers
	groupCommitEvt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindGroupCommit,
		Content:   groupCommitment.Hex(),
		Tags:      make(nostr.Tags, 0, 1+len(chosenSigners)),
	}
	groupCommitEvt.Tags = append(groupCommitEvt.Tags, nostr.Tag{"e", sessionId.Hex()})
	for _, signer := range chosenSigners {
		groupCommitEvt.Tags = append(groupCommitEvt.Tags, nostr.Tag{"p", signer.PeerPubKey.Hex()})
	}
	groupCommitEvt.Sign(s.SecretKey)
	relay.BroadcastEvent(groupCommitEvt)

	// step-4 (send): send event to be signed
	session.status = "event"
	jevt, _ := easyjson.Marshal(event)
	evtEvt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindEventToBeSigned,
		Content:   string(jevt),
		Tags:      make(nostr.Tags, 0, 1+len(chosenSigners)),
	}
	evtEvt.Tags = append(evtEvt.Tags, nostr.Tag{"e", sessionId.Hex()})
	for _, signer := range chosenSigners {
		evtEvt.Tags = append(evtEvt.Tags, nostr.Tag{"p", signer.PeerPubKey.Hex()})
	}
	evtEvt.Sign(s.SecretKey)
	relay.BroadcastEvent(evtEvt)

	// step-5 (receive): get partial signature from each participant
	session.status = "partialsigs"
	partialSigs := make([]frost.PartialSignature, 0, len(chosenSigners))
	missing = make(map[nostr.PubKey]struct{}, len(chosenSigners))
	for pubkey := range chosenSigners {
		missing[pubkey] = struct{}{}
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout receiving partial signatures, missing: %v", slices.Collect(maps.Keys(missing)))
		case evt := <-ch:
			if evt.Kind != common.KindPartialSignature {
				return fmt.Errorf("got a kind %d instead of %d (partial sig) from %s",
					evt.Kind, common.KindPartialSignature, evt.PubKey)
			}

			if _, ok := chosenSigners[evt.PubKey]; !ok {
				log.Warn().Str("pubkey", evt.PubKey.Hex()).Str("session", sessionId.Hex()).
					Msg("got partial signature from unrelated signer")
				continue
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
				return fmt.Errorf("partial signature from signer %s isn't good: %w", evt.PubKey, err)
			}
			partialSigs = append(partialSigs, partialSig)

			log.Info().
				Int("count", len(partialSigs)).Int("need", len(chosenSigners)).
				Msg("got good partial signature")

			if len(partialSigs) == len(chosenSigners) {
				lambdaRegistryLock.Unlock()
				goto aggregate
			}

			// reuse this lock to protect our signature counting
			lambdaRegistryLock.Unlock()
		}
	}

aggregate:
	// aggregate signature
	session.status = "aggregating"
	log.Info().Msg("aggregating")
	sig, err := cfg.AggregateSignatures(finalNonce, partialSigs)
	if err != nil {
		return fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	event.Sig = [64]byte(sig.Serialize())
	session.status = "done"
	return nil
}

func (kuc *GroupContext) Encrypt(
	ctx context.Context,
	plaintext string,
	recipientPublicKey nostr.PubKey,
) (base64ciphertext string, err error) {
	return "", fmt.Errorf("not implemented")
}

func (kuc *GroupContext) Decrypt(
	ctx context.Context,
	base64ciphertext string,
	senderPublicKey nostr.PubKey,
) (plaintext string, err error) {
	return "", fmt.Errorf("not implemented")
}

func handleSignerStuff(ctx context.Context, evt nostr.Event) {
	eTag := evt.Tags.Find("e")
	if eTag == nil {
		return
	}
	sessionId, err := nostr.IDFromHex(eTag[1])
	if err != nil {
		return
	}

	if session, ok := signingSessions.Load(sessionId); ok {
		if _, ok := session.chosenSigners[evt.PubKey]; ok {
			session.ch <- evt
		}
	}
}
