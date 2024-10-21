package frost

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

func TrustedKeyDeal(
	secret *btcec.ModNScalar,
	threshold, maxSigners int,
) ([]KeyShard, *btcec.JacobianPoint, []*btcec.JacobianPoint) {
	// negate this here before splitting the key if Y is odd because of bip-340
	pubkey := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secret, pubkey)
	if pubkey.Y.IsOdd() {
		secret.Negate()
		btcec.ScalarBaseMultNonConst(secret, pubkey)
	}
	pubkey.ToAffine()
	// ~

	if maxSigners < threshold || threshold <= 0 {
		panic("bad threshold")
	}

	polynomial, err := makePolynomial(secret, threshold)
	if err != nil {
		panic(err)
	}

	// evaluate the polynomial for each point x=1,...,n
	shards := make([]KeyShard, maxSigners)
	for i := 0; i < maxSigners; i++ {
		shards[i] = makeKeyShard(i+1, polynomial, pubkey)
	}

	commits := VSSCommit(polynomial)
	pubkey = commits[0]

	return shards, pubkey, commits
}
