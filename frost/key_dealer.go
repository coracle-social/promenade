package frost

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

func TrustedDealerKeygen(
	secret *btcec.ModNScalar,
	threshold, maxSigners int,
) ([]*KeyShare, *btcec.JacobianPoint, []*btcec.JacobianPoint) {
	privateKeyShares, poly, err := shardReturnPolynomial(
		secret,
		threshold,
		maxSigners,
	)
	if err != nil {
		panic(err)
	}

	coms := VSSCommit(poly)

	shares := make([]*KeyShare, maxSigners)
	for i, k := range privateKeyShares {
		pubkey := &btcec.JacobianPoint{}
		btcec.ScalarBaseMultNonConst(k.Secret, pubkey)

		shares[i] = &KeyShare{
			Secret:    k.Secret,
			PublicKey: coms[0],
			PublicKeyShare: PublicKeyShare{
				PublicKey:     pubkey,
				VssCommitment: coms,
				ID:            k.ID,
			},
		}
	}

	return shares, coms[0], coms
}
