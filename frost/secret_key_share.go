package frost

import "github.com/btcsuite/btcd/btcec/v2"

type KeyShard struct {
	Secret    *btcec.ModNScalar
	PublicKey *btcec.JacobianPoint
	PublicKeyShard
}

// // Encode serializes k into a compact byte string.
// func (k *KeyShard) Encode() []byte {
// 	pk := k.PublicKeyShard.Encode()
// 	eLen := k.PublicKeyShard.Group.ElementLength()
// 	sLen := k.PublicKeyShard.Group.ScalarLength()
// 	out := slices.Grow(pk, eLen+sLen)
// 	out = append(out, k.Secret.Encode()...)
// 	out = append(out, k.VerificationKey.Encode()...)
//
// 	return out
// }
//
// // Hex returns the hexadecimal representation of the byte encoding returned by Encode().
// func (k *KeyShard) Hex() string {
// 	return hex.EncodeToString(k.Encode())
// }
//
// // Decode deserializes the compact encoding obtained from Encode(), or returns an error.
// func (k *KeyShard) Decode(data []byte) error {
// 	g, pkLen, cLen, err := decodeKeyShardHeader(data)
// 	if err != nil {
// 		return fmt.Errorf(errFmt, errKeyShardDecodePrefix, err)
// 	}
//
// 	expectedLength := pkLen + g.ScalarLength() + g.ElementLength()
// 	if len(data) != expectedLength {
// 		return fmt.Errorf(errFmt, errKeyShardDecodePrefix, errEncodingInvalidLength)
// 	}
//
// 	pk := new(PublicKeyShard)
// 	if err = pk.decode(g, cLen, data[:pkLen]); err != nil {
// 		return fmt.Errorf(errFmt, errKeyShardDecodePrefix, err)
// 	}
//
// 	s := g.NewScalar()
// 	if err = s.Decode(data[pkLen : pkLen+g.ScalarLength()]); err != nil {
// 		return fmt.Errorf("%w: failed to decode secret key: %w", errKeyShardDecodePrefix, err)
// 	}
//
// 	e := g.NewElement()
// 	if err = e.Decode(data[pkLen+g.ScalarLength():]); err != nil {
// 		return fmt.Errorf("%w: failed to decode VerificationKey: %w", errKeyShardDecodePrefix, err)
// 	}
//
// 	k.populate(s, e, pk)
//
// 	return nil
// }
//
// // DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
// func (k *KeyShard) DecodeHex(h string) error {
// 	b, err := hex.DecodeString(h)
// 	if err != nil {
// 		return fmt.Errorf(errFmt, errKeyShardDecodePrefix, err)
// 	}
//
// 	return k.Decode(b)
// }
