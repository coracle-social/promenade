package frost

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
)

func (c *Configuration) AggregateECDHShards(shards []*btcec.JacobianPoint) (*btcec.JacobianPoint, error) {
	res := new(btcec.JacobianPoint)
	for _, shard := range shards {
		if shard == nil || shard.X.IsZero() || shard.Y.IsZero() {
			return nil, errors.New("invalid ecdh shard (nil or zero scalar)")
		}
		btcec.AddNonConst(shard, res, res)
	}
	res.ToAffine()
	return res, nil
}

func (c *Configuration) CreateECDHShare(
	keyshard KeyShard,
	pubkey *btcec.JacobianPoint,
	lambdaRegistry LambdaRegistry,
) *btcec.JacobianPoint {
	res := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(keyshard.Secret, pubkey, res)

	btcec.ScalarMultNonConst(
		new(btcec.ModNScalar).
			Mul2(
				lambdaRegistry.getOrNew(c.Participants, keyshard.ID),
				keyshard.Secret,
			),
		pubkey,
		res,
	)

	res.ToAffine()
	return res
}
