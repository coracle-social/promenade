package frost

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

type KeyShard struct {
	Secret    *btcec.ModNScalar
	PublicKey *btcec.JacobianPoint
	PublicKeyShard
}

func (k KeyShard) Hex() string { return hex.EncodeToString(k.Encode()) }
func (k *KeyShard) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return err
	}
	return k.Decode(b)
}

func (k KeyShard) Encode() []byte {
	pks := k.PublicKeyShard.Encode()
	pkslen := len(pks)
	out := make([]byte, pkslen+32+33)
	copy(out, pks)
	k.Secret.PutBytesUnchecked(out[pkslen:])
	writePointTo(out[pkslen+32:], k.PublicKey)
	return out
}

func (k *KeyShard) Decode(in []byte) error {
	pkslen, err := k.PublicKeyShard.Decode(in)
	if err != nil {
		return fmt.Errorf("error decoding public key shard: %w", err)
	}

	k.Secret = new(btcec.ModNScalar)
	k.Secret.SetByteSlice(in[pkslen : pkslen+32])

	pk, err := btcec.ParsePubKey(in[pkslen+32:])
	if err != nil {
		return err
	}

	k.PublicKey = new(btcec.JacobianPoint)
	pk.AsJacobian(k.PublicKey)

	return nil
}
