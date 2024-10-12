package main

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func hexPoint(pt *btcec.JacobianPoint) string {
	v := make([]byte, 33)

	if pt.Y.IsOdd() {
		v[0] = secp256k1.PubKeyFormatCompressedOdd
	} else {
		v[0] = secp256k1.PubKeyFormatCompressedEven
	}

	pt.X.PutBytesUnchecked(v[1:])

	return hex.EncodeToString(v)
}
