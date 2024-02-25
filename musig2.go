package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

type KeyUserContext struct {
	m2s     *musig2.Context
	signers []string

	nip46.Session

	signSession             *musig2.Session
	lock                    sync.Mutex
	currentEventBeingSigned string
	noncesReceived          map[string]struct{}
	partialSigsReceived     map[string]struct{}
	callback                chan string
}

func (kuc *KeyUserContext) Sign(event *nostr.Event) error {
	// preparation steps
	event.PubKey = hex.EncodeToString(kuc.m2s.PubKey().SerializeCompressed()[1:])
	h := sha256.Sum256(event.Serialize())
	event.ID = hex.EncodeToString(h[:])
	jevt, _ := easyjson.Marshal(event)

	// start a signing Session
	kuc.signSession, _ = kuc.m2s.NewSession()
	kuc.currentEventBeingSigned = event.ID
	kuc.noncesReceived = make(map[string]struct{})
	kuc.partialSigsReceived = make(map[string]struct{})
	kuc.callback = make(chan string)

	defer func() {
		kuc.lock.Lock()
		defer kuc.lock.Unlock()
		kuc.signSession = nil
		kuc.currentEventBeingSigned = ""
		kuc.noncesReceived = nil
		kuc.partialSigsReceived = nil
		close(kuc.callback)
		kuc.callback = nil
	}()

	// this should cause the signers to reply with their nonces
	// and then with their signatures
	reqEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.EventToPartiallySignKind,
		Content:   string(jevt),
		Tags: nostr.Tags{
			{"e", event.ID},
			{"p", event.PubKey},
		},
	}
	reqEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(reqEvt)

	// we send our nonce too
	nonce := kuc.signSession.PublicNonce()
	nonceEvt := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      common.NonceKind,
		Content:   hex.EncodeToString(nonce[:]),
		Tags: nostr.Tags{
			{"e", event.ID},
			{"p", event.PubKey},
		},
	}
	nonceEvt.Sign(s.PrivateKey)
	relay.BroadcastEvent(nonceEvt)

	// now we wait until the coordination flow has a response for us
	select {
	case signature := <-kuc.callback:
		event.Sig = signature
		// event will be modified with the signature: done
		return nil
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("took too long to sign")
	}
}

func handlePartialSharedKey(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.PartialSharedKeyKind {
		return
	}
}

func handleNonce(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.NonceKind {
		return
	}

	p := event.Tags.GetFirst([]string{"p", ""})
	targetPubkey := (*p)[1]
	kuc, _ := userContexts.Load(targetPubkey)

	var nonce [musig2.PubNonceSize]byte
	if _, err := hex.Decode(nonce[:], []byte(event.Content)); err != nil {
		log.Warn().Str("src", event.PubKey).Err(err).Msg("invalid nonce")
		return
	}

	kuc.lock.Lock()
	defer kuc.lock.Unlock()
	_, alreadyReceived := kuc.noncesReceived[event.PubKey]
	if alreadyReceived {
		log.Warn().Str("src", event.PubKey).Msg("dup nonce received")
		return
	} else {
		kuc.noncesReceived[event.PubKey] = struct{}{}
	}

	ok, _ := kuc.signSession.RegisterPubNonce(nonce)
	if ok {
		// we have all the nonces -- we can now share our partial signature
		var msg [32]byte
		hex.Decode(msg[:], []byte(kuc.currentEventBeingSigned))
		ps, err := kuc.signSession.Sign(msg)
		if err != nil {
			log.Warn().Err(err).Msg("failed to generate partial signature")
			return
		}
		psb := ps.S.Bytes()

		psEvt := &nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      common.PartialSigKind,
			Content:   hex.EncodeToString(psb[:]),
			Tags: nostr.Tags{
				{"e", kuc.currentEventBeingSigned},
				{"p", event.PubKey},
			},
		}
		relay.BroadcastEvent(psEvt)
	}
}

func handlePartialSig(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.PartialSigKind {
		return
	}

	p := event.Tags.GetFirst([]string{"p", ""})
	targetPubkey := (*p)[1]
	kuc, _ := userContexts.Load(targetPubkey)

	var psb [32]byte
	if _, err := hex.Decode(psb[:], []byte(event.Content)); err != nil {
		log.Warn().Str("src", event.PubKey).Err(err).Msg("invalid partial sig")
		return
	}
	ps := &musig2.PartialSignature{}
	ps.S = &btcec.ModNScalar{}
	if overflows := ps.S.SetBytes(&psb); overflows == 1 {
		log.Warn().Str("src", event.PubKey).Msg("partial sig overflow")
		return
	}

	kuc.lock.Lock()
	defer kuc.lock.Unlock()
	_, alreadyReceived := kuc.noncesReceived[event.PubKey]
	if alreadyReceived {
		log.Warn().Str("src", event.PubKey).Msg("dup nonce received")
		return
	} else {
		kuc.noncesReceived[event.PubKey] = struct{}{}
	}

	ok, _ := kuc.signSession.CombineSig(ps)
	if ok {
		// this means we have all partial signatures
		// now we can get the final signature
		ss := kuc.signSession.FinalSig()
		ssb := ss.Serialize()

		// and finally return it
		kuc.callback <- hex.EncodeToString(ssb)
	}
}
