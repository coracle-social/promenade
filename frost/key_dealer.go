package frost

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

func TrustedKeyDeal(
	secret *btcec.ModNScalar,
	threshold, maxSigners int,
) ([]KeyShare, *btcec.JacobianPoint, []*btcec.JacobianPoint) {
	// negate this here before splitting the key if Y is odd because of bip-340
	privateKey := btcec.PrivKeyFromScalar(secret)
	pubkey := new(btcec.JacobianPoint)
	privateKey.PubKey().AsJacobian(pubkey)
	if pubkey.Y.IsOdd() {
		secret.Negate()
	}
	// ~

	privateKeyShares, poly, err := shardReturnPolynomial(
		secret,
		threshold,
		maxSigners,
	)
	if err != nil {
		panic(err)
	}

	commits := VSSCommit(poly)
	pubkey = commits[0]

	return privateKeyShares, pubkey, commits
}

// TODO allow each receiver of a share to verify if they were handled a correct thing
