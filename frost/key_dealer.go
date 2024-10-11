package frost

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

func TrustedKeyDeal(
	secret *btcec.ModNScalar,
	threshold, maxSigners int,
) ([]KeyShare, *btcec.JacobianPoint, []*btcec.JacobianPoint) {
	privateKeyShares, poly, err := shardReturnPolynomial(
		secret,
		threshold,
		maxSigners,
	)
	if err != nil {
		panic(err)
	}

	coms := VSSCommit(poly)

	// shares := make([]KeyShare, maxSigners)
	// for i, k := range privateKeyShares {
	// 	pks := &btcec.JacobianPoint{}
	// 	btcec.ScalarBaseMultNonConst(k.Secret, pks)
	// 	pks.ToAffine()
	// 	fmt.Printf("%x => %x\n", k.Secret.Bytes(), *pks.X.Bytes())

	// 	shares[i] = KeyShare{
	// 		Secret:    k.Secret,
	// 		PublicKey: coms[0],
	// 		PublicKeyShare: PublicKeyShare{
	// 			PublicKey:     pks,
	// 			VssCommitment: coms,
	// 			ID:            k.ID,
	// 		},
	// 	}
	// }

	return privateKeyShares, coms[0], coms
}
