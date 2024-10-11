package frost

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/bytemare/ecc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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

type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *btcec.JacobianPoint

	// The VssCommitment to the polynomial the key was created with.
	VssCommitment []*btcec.JacobianPoint

	// ID of the participant.
	ID int
}

func publicKeyShareLength(polyLen int) int {
	return 2 + 4 + 33 + polyLen*33
}

func (p *PublicKeyShare) Encode() []byte {
	out := make([]byte, 7+publicKeyShareLength(len(p.VssCommitment)))
	p.EncodeTo(out)
	return out
}

func (p *PublicKeyShare) EncodeTo(out []byte) int {
	binary.LittleEndian.PutUint16(out[0:2], uint16(p.ID))
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(p.VssCommitment)))

	if p.PublicKey.Y.IsOdd() {
		out[6] = secp256k1.PubKeyFormatCompressedOdd
	} else {
		out[6] = secp256k1.PubKeyFormatCompressedEven
	}
	p.PublicKey.X.PutBytesUnchecked(out[7:])

	for i, c := range p.VssCommitment {
		if c.Y.IsOdd() {
			out[6+i*33] = secp256k1.PubKeyFormatCompressedOdd
		} else {
			out[6+i*33] = secp256k1.PubKeyFormatCompressedEven
		}
		c.X.PutBytesUnchecked(out[7:])
	}

	return 7 + publicKeyShareLength(len(p.VssCommitment))
}

func (p *PublicKeyShare) decode(cLen int, data []byte) error {
	eLen := g.ElementLength()
	id := binary.LittleEndian.Uint16(data[1:3])

	pk := g.NewElement()
	if err := pk.Decode(data[7 : 7+eLen]); err != nil {
		return fmt.Errorf("%w: failed to decode public key: %w", errPublicKeyShareDecodePrefix, err)
	}

	i := 0
	commitment := make([]*ecc.Element, cLen)

	for j := 7 + eLen; j < len(data); j += eLen {
		c := g.NewElement()
		if err := c.Decode(data[j : j+eLen]); err != nil {
			return fmt.Errorf("%w: failed to decode commitment %d: %w", errPublicKeyShareDecodePrefix, i+1, err)
		}

		commitment[i] = c
		i++
	}

	p.Group = g
	p.ID = id
	p.PublicKey = pk
	p.VssCommitment = commitment

	return nil
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (p *PublicKeyShare) Decode(data []byte) error {
	g, expectedLength, cLen, err := decodeKeyShareHeader(data)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	if len(data) != expectedLength {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, errEncodingInvalidLength)
	}

	return p.decode(cLen, data)
}

// DecodeHex sets p to the decoding of the hex encoded representation returned by Hex().
func (p *PublicKeyShare) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	return p.Decode(b)
}
