package main

import (
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
	pks := pe.cfg.SignerPublicKeyShards[pe.index]
	return fmt.Sprintf("participant %d (%x/%d) failed: %s", pe.index, btcec.NewPublicKey(&pks.PublicKey.X, &pks.PublicKey.Y).SerializeCompressed(), pks.ID, pe.reason)
}
