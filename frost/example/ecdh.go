package main

import (
	"context"
	"fmt"

	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
)

func ecdhFlow(
	_ context.Context,
	threshold int,
	shards []frost.KeyShard,
	pubkey *btcec.JacobianPoint,
	encryptionTarget []byte,
) {
	fmt.Println("-= ECDH =-")

	et := new(btcec.ModNScalar)
	et.SetByteSlice(encryptionTarget)
	targetPubKey := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(et, targetPubKey)
	targetPubKey.ToAffine()

	participants := make([]int, threshold)
	for i := range threshold {
		participants[i] = shards[i].ID
	}

	cfg := &frost.Configuration{
		Threshold:    threshold,
		MaxSigners:   len(shards),
		PublicKey:    pubkey,
		Participants: participants,
	}

	lambdaRegistry := make(frost.LambdaRegistry)
	ecdhShards := make([]*btcec.JacobianPoint, threshold)
	for i := range threshold {
		ecdhShards[i] = cfg.CreateECDHShare(shards[i], targetPubKey, lambdaRegistry)
	}

	ecdh, err := cfg.AggregateECDHShards(ecdhShards)
	if err != nil {
		panic(err)
	}

	expected := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(et, pubkey, expected)
	expected.ToAffine()

	fmt.Println("expected:")
	fmt.Println(expected.X, expected.Y)

	fmt.Println("got")
	fmt.Println(ecdh.X, ecdh.Y)
}
