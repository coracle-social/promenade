package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"fiatjaf.com/promenade/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

type Data struct {
	SecretKey       string           `json:"secret_key"`
	RelayAgreements []RelayAgreement `json:"relay_agreement"`
	Accounts        []Account        `json:"accounts"`
}

type Account struct {
	PartialSecretKey string   `json:"partial_secret_key"`
	Signers          []string `json:"signers"`
	Relay            string   `json:"relay"`
}

type RelayAgreement struct {
	URL                  string `json:"url"`
	AcceptingNewAccounts bool   `json:"accepting_new_accounts"`
}

type Pending struct {
	ourSecretKey       string
	mainSignersPubkeys map[string]bool
	receivedPubkeys    []string
}

type Session struct {
	account          Account
	eventBeingSigned string
	noncesReceived   map[string]struct{}
	m2s              *musig2.Context
	signSession      *musig2.Session
}

func (s Session) aggpk() string {
	aggregatedPublicKey, _ := s.m2s.CombinedKey()
	return hex.EncodeToString(aggregatedPublicKey.SerializeCompressed())
}

func makeSession(account Account) *Session {
	bseckey, _ := hex.DecodeString(account.PartialSecretKey)
	seckey, _ := btcec.PrivKeyFromBytes(bseckey)
	signers := make([]*secp256k1.PublicKey, len(account.Signers))
	for i, pkhex := range account.Signers {
		bpubkey, _ := hex.DecodeString(pkhex)
		signers[i], _ = btcec.ParsePubKey(bpubkey)
	}
	m2s, _ := musig2.NewContext(seckey, true,
		musig2.WithKnownSigners(signers))

	return &Session{
		account: account,
		m2s:     m2s,
	}
}

func listenForSessionSpecificEvents(ctx context.Context, eventStream chan<- nostr.IncomingEvent, account Account) {
	session := makeSession(account)
	aggpk := session.aggpk()
	sessions[aggpk] = session

	relay, err := pool.EnsureRelay(account.Relay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to relay %s to listen for specific events: %s\n", account.Relay, err)
		return
	}

	sub, err := relay.Subscribe(ctx, nostr.Filters{
		{
			Kinds: []int{
				common.ConnectionKind,
				common.EventToPartiallySignKind,
				common.NonceKind,
			},
			Tags: nostr.TagMap{"p": []string{aggpk}},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to subscribe to relay %s to listen for specific events: %s\n", account.Relay, err)
		return
	}
	// then forward these events to the main loop
	for evt := range sub.Events {
		eventStream <- nostr.IncomingEvent{Relay: relay, Event: evt}
	}
}

// =======
var (
	KeyAggTagList  = []byte("KeyAgg list")
	KeyAggTagCoeff = []byte("KeyAgg coefficient")
)

// from Ruben Somsen's explanation:
// To calculate the MuSig key, you calculate:
// mu = hash(A1,A2)
// m1 = hash(mu,A1)
// m2 = hash(mu,A2)
// A1' = m1*A1
// A2' = m2*A2
// And the final aggregated key M = A1'+A2'
//
// This means the private key m corresponding to pubkey M is:
// m = m1*a1 + m2*a2
//
// So to perform ECDH you'd need to do:
// (m1*a1)*B + (m2*a2)*B == m*B
func getPartialECDH(pubkeys []string, privateKey string, externalPubkey string) (string, error) {
	// keys = A1, A2, ...
	keys := make([]*secp256k1.PublicKey, 0, len(pubkeys))
	for i, k := range pubkeys {
		b, _ := hex.DecodeString(k)
		pk, _ := btcec.ParsePubKey(b)
		keys[i] = pk
	}

	// a1
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	_, An := btcec.PrivKeyFromBytes(privateKeyBytes)
	an := &btcec.ModNScalar{}
	an.SetByteSlice(privateKeyBytes)

	// mu = hash(A1,A2)
	keyAggBuf := make([]byte, 33*len(keys))
	keyBytes := bytes.NewBuffer(keyAggBuf[0:0])
	for _, key := range keys {
		keyBytes.Write(key.SerializeCompressed())
	}
	mu := chainhash.TaggedHash(KeyAggTagList, keyBytes.Bytes())

	// m1 = hash(mu,A1)
	// m2 = hash(mu,A2) etc
	var coefficientBytes [65]byte
	copy(coefficientBytes[:], mu[:])
	copy(coefficientBytes[32:], An.SerializeCompressed())
	mnHash := chainhash.TaggedHash(KeyAggTagCoeff, coefficientBytes[:])
	mn := &btcec.ModNScalar{}
	mn.SetBytes((*[32]byte)(mnHash))

	// a1' = (m1*a1)
	mn_an := mn.Mul(an)

	// (m1*a1)*B
	result := &btcec.JacobianPoint{}
	epkb, err := hex.DecodeString(externalPubkey)
	if err != nil {
		return "", err
	}
	ej, err := btcec.ParseJacobian(epkb)
	if err != nil {
		return "", err
	}
	btcec.ScalarMultNonConst(mn_an, &ej, result)

	pkResult := btcec.NewPublicKey(&result.X, &result.Y)
	return hex.EncodeToString(pkResult.SerializeCompressed()), nil
}
