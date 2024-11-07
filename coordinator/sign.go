package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

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
)

type GroupContext struct {
	common.AccountRegistration
}

type Session struct {
	chosenSigners []string
	ch            chan *nostr.Event
}

func (kuc *GroupContext) GetPublicKey(ctx context.Context) (string, error) {
	return kuc.PubKey, nil
}

func (kuc *GroupContext) SignEvent(ctx context.Context, event *nostr.Event) error {
	ipk, _ := hex.DecodeString("02" + kuc.PubKey)
	pubkey, _ := btcec.ParseJacobian(ipk)

	// signers that are online and that we have chosen to participate in this round
	chosenSigners := make([]string, 0, kuc.Threshold)

	cfg := &frost.Configuration{
		Threshold:             int(kuc.Threshold),
		MaxSigners:            len(kuc.Signers),
		PublicKey:             &pubkey,
		SignerPublicKeyShards: make([]frost.PublicKeyShard, len(kuc.Signers)),
	}
	for s, signer := range kuc.Signers {
		cfg.SignerPublicKeyShards[s] = signer.Shard

		if len(chosenSigners) < cfg.Threshold {
			if _, isOnline := onlineSigners.Load(signer.PeerPubKey); isOnline {
				chosenSigners = append(chosenSigners, signer.PeerPubKey)
			}
		}
	}

	// fail if we don't have enough online signers
	if len(chosenSigners) < cfg.Threshold {
		return fmt.Errorf("not enough signers online: have %d, needed %d", len(chosenSigners), cfg.Threshold)
	}

	if err := cfg.Init(); err != nil {
		return fmt.Errorf("fail to initialize config: %w", err)
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
	for s, signer := range chosenSigners {
		confEvt.Tags[s] = nostr.Tag{"p", signer}
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
	commitments := make([]frost.Commitment, len(chosenSigners))
	for s := range chosenSigners {
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
			commitments[s] = commit
		}
	}

	// step-3 (send): send all commits back to everybody (including themselves for simplicity).
	for _, commit := range commitments {
		commitEvt := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      common.KindCommit,
			Content:   commit.Hex(),
			Tags:      make(nostr.Tags, 1+len(chosenSigners)),
		}

		commitEvt.Tags[0] = nostr.Tag{"e", sessionId}
		for s, signer := range chosenSigners {
			commitEvt.Tags[1+s] = nostr.Tag{"p", signer}
		}

		commitEvt.Sign(s.PrivateKey)
		relay.BroadcastEvent(commitEvt)
	}

	// step-4 (send): send event to be signed
	event.PubKey = hex.EncodeToString(cfg.PublicKey.X.Bytes()[:])
	msg := sha256.Sum256(event.Serialize())
	event.ID = hex.EncodeToString(msg[:])
	jevt, _ := easyjson.Marshal(event)
	evtEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.KindEventToBeSigned,
		Content:   string(jevt),
		Tags:      make(nostr.Tags, 1+len(chosenSigners)),
	}
	evtEvt.Tags[0] = nostr.Tag{"e", sessionId}
	for s, signer := range chosenSigners {
		evtEvt.Tags[1+s] = nostr.Tag{"p", signer}
	}
	evtEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(evtEvt)

	// step-5 (receive): get partial signature from each participant
	partialSigs := make([]frost.PartialSignature, len(chosenSigners))
	for s := range chosenSigners {
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
			partialSigs[s] = partialSig
		}
	}

	// aggregate signature
	sig, err := cfg.AggregateSignatures(, partialSigs)
	if err != nil {
		return fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	// check the signature and if any of the participants did something wrong
	if ok := sig.Verify(msg[:], btcec.NewPublicKey(&cfg.PublicKey.X, &cfg.PublicKey.Y)); !ok {
		for s, partialSig := range partialSigs {
			if err := cfg.VerifyPartialSignature(partialSig, msg[:], commitments); err != nil {
				return fmt.Errorf("signer %s failed: %w", chosenSigners[s], err)
			}
		}
		return fmt.Errorf("signature %x is bad for unknown reasons", sig.Serialize())
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
		if slices.Contains(session.chosenSigners, evt.PubKey) {
			session.ch <- evt
		}
	}
}
