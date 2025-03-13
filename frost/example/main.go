package main

import (
	"context"
	"crypto/rand"
	"fmt"

	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
)

type ParticipantError struct {
	cfg *frost.Configuration

	index  int
	reason string
}

func (pe ParticipantError) Error() string {
	part := pe.cfg.Participants[pe.index]
	return fmt.Sprintf("participant %d (id %d) failed: %s", pe.index, part, pe.reason)
}

func main() {
	message := make([]byte, 32)
	secretKey := make([]byte, 32)

	rand.Read(message)
	rand.Read(secretKey)

	threshold := 4
	totalSigners := 7

	// key generation
	secret := new(btcec.ModNScalar)
	secret.SetByteSlice(secretKey)

	shards, pubkey, _ := frost.TrustedKeyDeal(secret, threshold, totalSigners)

	fmt.Println("")
	signingFlow(
		context.Background(),
		threshold,
		shards,
		message,
		pubkey,
	)

	encryptionTarget := make([]byte, 32)
	rand.Read(encryptionTarget)

	fmt.Println("")
	ecdhFlow(
		context.Background(),
		threshold,
		shards,
		pubkey,
		encryptionTarget,
	)
}
