package frost

import "github.com/btcsuite/btcd/btcec/v2"

type KeyShare struct {
	Secret    *btcec.ModNScalar
	PublicKey *btcec.JacobianPoint
	PublicKeyShare
}

// // Encode serializes k into a compact byte string.
// func (k *KeyShare) Encode() []byte {
// 	pk := k.PublicKeyShare.Encode()
// 	eLen := k.PublicKeyShare.Group.ElementLength()
// 	sLen := k.PublicKeyShare.Group.ScalarLength()
// 	out := slices.Grow(pk, eLen+sLen)
// 	out = append(out, k.Secret.Encode()...)
// 	out = append(out, k.VerificationKey.Encode()...)
//
// 	return out
// }
//
// // Hex returns the hexadecimal representation of the byte encoding returned by Encode().
// func (k *KeyShare) Hex() string {
// 	return hex.EncodeToString(k.Encode())
// }
//
// // Decode deserializes the compact encoding obtained from Encode(), or returns an error.
// func (k *KeyShare) Decode(data []byte) error {
// 	g, pkLen, cLen, err := decodeKeyShareHeader(data)
// 	if err != nil {
// 		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
// 	}
//
// 	expectedLength := pkLen + g.ScalarLength() + g.ElementLength()
// 	if len(data) != expectedLength {
// 		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, errEncodingInvalidLength)
// 	}
//
// 	pk := new(PublicKeyShare)
// 	if err = pk.decode(g, cLen, data[:pkLen]); err != nil {
// 		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
// 	}
//
// 	s := g.NewScalar()
// 	if err = s.Decode(data[pkLen : pkLen+g.ScalarLength()]); err != nil {
// 		return fmt.Errorf("%w: failed to decode secret key: %w", errKeyShareDecodePrefix, err)
// 	}
//
// 	e := g.NewElement()
// 	if err = e.Decode(data[pkLen+g.ScalarLength():]); err != nil {
// 		return fmt.Errorf("%w: failed to decode VerificationKey: %w", errKeyShareDecodePrefix, err)
// 	}
//
// 	k.populate(s, e, pk)
//
// 	return nil
// }
//
// // DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
// func (k *KeyShare) DecodeHex(h string) error {
// 	b, err := hex.DecodeString(h)
// 	if err != nil {
// 		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
// 	}
//
// 	return k.Decode(b)
// }
