package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	sec1 := make([]byte, 32)
	sec1[31] = 1
	sk1, pk1 := btcec.PrivKeyFromBytes(sec1)

	sec2 := make([]byte, 32)
	sec2[31] = 2
	sk2, pk2 := btcec.PrivKeyFromBytes(sec2)

	signers := []*secp256k1.PublicKey{pk1, pk2}

	ctx1, err1 := musig2.NewContext(sk1, true, musig2.WithKnownSigners(signers))
	ctx2, err2 := musig2.NewContext(sk2, true, musig2.WithKnownSigners(signers))

	if err := errors.Join(err1, err2); err != nil {
		log.Fatal(err)
		return
	}

	s1, err1 := ctx1.NewSession()
	s2, err2 := ctx2.NewSession()
	if err := errors.Join(err1, err2); err != nil {
		log.Fatal("failed to create session: ", err)
		return
	}

	_, err1 = s1.RegisterPubNonce(s2.PublicNonce())
	_, err2 = s2.RegisterPubNonce(s1.PublicNonce())
	if err := errors.Join(err1, err2); err != nil {
		log.Fatal("failed to register nonce: ", err)
		return
	}

	var msg [32]byte

	ps1, err1 := s1.Sign(msg)
	ps2, err2 := s2.Sign(msg)

	if err := errors.Join(err1, err2); err != nil {
		log.Fatal("error signing: ", err)
		return
	}

	_, err1 = s1.CombineSig(ps2)
	_, err2 = s2.CombineSig(ps1)
	if err := errors.Join(err1, err2); err != nil {
		log.Fatal("error combining: ", err)
		return
	}

	sig1 := s1.FinalSig()
	sig2 := s1.FinalSig()

	cpk, _ := ctx2.CombinedKey()
	fmt.Println(sig1.Verify(msg[:], cpk))
	fmt.Println(sig2.Verify(msg[:], cpk))
}
