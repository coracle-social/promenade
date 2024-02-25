package main

import (
	"encoding/hex"

	"git.fiatjaf.com/multi-nip46/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

type Pending struct {
	ourSecretKey       string
	mainSignersPubkeys map[string]bool
	receivedPubkeys    []string
}

type Session struct {
	eventBeingSigned string
	signers          []string
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
		m2s: m2s,
	}
}

func defaultFiltersForAccount(aggregatedPublicKey string) nostr.Filters {
	return nostr.Filters{
		{
			Kinds: []int{
				common.EventToPartiallySignKind,
				common.NonceKind,
			},
			Tags: nostr.TagMap{"p": []string{aggregatedPublicKey}},
		},
	}
}
