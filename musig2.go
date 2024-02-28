package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/mailru/easyjson"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
	"github.com/puzpuzpuz/xsync/v3"
)

var (
	userContexts    = xsync.NewMapOf[string, *KeyUserContext]()
	pendingCreation = xsync.NewMapOf[string, *PendingKeyUserContext]()
)

type KeyUserContext struct {
	name string

	m2s     *musig2.Context
	signers []*btcec.PublicKey

	nip46       *xsync.MapOf[string, *nip46.Session]
	ecdhPending *xsync.MapOf[string, *PendingECDH]

	signSession             *musig2.Session
	lock                    sync.Mutex
	currentEventBeingSigned string
	noncesReceived          map[string]struct{}
	partialSigsReceived     map[string]struct{}
	callback                chan string
}

type PendingECDH struct {
	partialSharedKeys []*btcec.PublicKey
	lock              sync.Mutex
	received          map[string]struct{}
	callback          chan *nip46.Session
}

type PendingKeyUserContext struct {
	signerMainKeys    []string
	partialPublicKeys [][]byte

	name     string      // name chosen when the account was being created
	callback chan string // this will be called with the resulting pubkey
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

func handlePartialPublicKey(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.PartialPubkeyKind {
		return
	}

	e := event.Tags.GetFirst([]string{"e", ""})
	if e == nil {
		return
	}
	originalEvent := (*e)[1]

	pkuc, ok := pendingCreation.Load(originalEvent)
	if !ok {
		return
	}

	idx := slices.Index(pkuc.signerMainKeys, event.PubKey)
	if idx == -1 {
		return
	}

	pubkeyBytes, _ := hex.DecodeString(event.Content)
	pkuc.partialPublicKeys[idx] = pubkeyBytes

	if slices.ContainsFunc(pkuc.partialPublicKeys, func(b []byte) bool { return len(b) == 0 }) {
		// still missing some partial keys, end here
		return
	}

	// we've got all partial keys, so remove the pending stuff
	pendingCreation.Delete(originalEvent)

	// and create a new key user context aka account
	signers := make([]*btcec.PublicKey, len(pkuc.partialPublicKeys), len(pkuc.partialPublicKeys)+1)
	for i, pkb := range pkuc.partialPublicKeys {
		signers[i], _ = btcec.ParsePubKey(pkb)
	}

	privateKeyBytes, _ := hex.DecodeString(s.PrivateKey)
	priv, pub := btcec.PrivKeyFromBytes(privateKeyBytes)
	signers = append(signers, pub)
	m2s, err := musig2.NewContext(priv, false, musig2.WithKnownSigners(signers))
	if err != nil {
		return
	}
	kuc := &KeyUserContext{
		m2s:     m2s,
		signers: signers,
		name:    pkuc.name,
		nip46:   xsync.NewMapOf[string, *nip46.Session](),
	}
	aggregatedPublicKey, _ := kuc.m2s.CombinedKey()
	aggpk := hex.EncodeToString(aggregatedPublicKey.SerializeCompressed())

	userContexts.Store(aggpk, kuc)

	pkuc.callback <- aggpk
	close(pkuc.callback)

	// TODO: store
}

func handlePartialSharedKey(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.PartialSharedKeyKind {
		return
	}

	kuc := getKeyUserSession(event)

	peer := event.Tags.GetFirst([]string{"peer", ""})
	peerPubkey := (*peer)[1]
	ep, ok := kuc.ecdhPending.Load(peerPubkey)
	if !ok {
		return
	}

	pubkeyBytes, _ := hex.DecodeString(event.Content)
	partialPubkey, _ := btcec.ParsePubKey(pubkeyBytes)

	ep.lock.Lock()
	defer ep.lock.Unlock()

	if _, ok := ep.received[event.PubKey]; ok {
		return
	} else {
		ep.received[event.PubKey] = struct{}{}
		ep.partialSharedKeys = append(ep.partialSharedKeys, partialPubkey)
	}

	// if we have received everything, resolve this ecdh session
	// see signer/helpers.go for the full rationale, but here we just add these points
	result := &btcec.JacobianPoint{}
	for _, psk := range ep.partialSharedKeys {
		this := &btcec.JacobianPoint{}
		psk.AsJacobian(this)
		btcec.AddNonConst(result, this, result)
	}
	kuc.ecdhPending.Delete(peerPubkey)

	shared := btcec.NewPublicKey(&result.X, &result.Y)
	n46 := &nip46.Session{
		SharedKey: shared.SerializeCompressed(),
	}
	kuc.nip46.Store(peerPubkey, n46)

	ep.callback <- n46
	close(ep.callback)

	// TODO: store
}

func handleNonce(ctx context.Context, event *nostr.Event) {
	if event.Kind != common.NonceKind {
		return
	}

	kuc := getKeyUserSession(event)

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

	kuc := getKeyUserSession(event)

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
