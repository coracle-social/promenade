package frost

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func writePointTo(out []byte, pt *btcec.JacobianPoint) {
	if pt.Y.IsOdd() {
		out[0] = secp256k1.PubKeyFormatCompressedOdd
	} else {
		out[0] = secp256k1.PubKeyFormatCompressedEven
	}
	pt.X.PutBytesUnchecked(out[1:])
}

func stringOfScalar(s *btcec.ModNScalar) string {
	sx := s.String()
	sn, _ := new(big.Int).SetString(sx, 16)
	return sn.String()
}
