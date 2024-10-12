package frost

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *btcec.JacobianPoint

	// The VssCommitment to the polynomial the key was created with.
	VssCommitment []*btcec.JacobianPoint

	// ID of the participant.
	ID int
}

func (c PublicKeyShare) Hex() string { return hex.EncodeToString(c.Encode()) }
func (c *PublicKeyShare) DecodeHex(x string) error {
	b, err := hex.DecodeString(x)
	if err != nil {
		return err
	}
	_, err = c.Decode(b)
	return err
}

func (p PublicKeyShare) Encode() []byte {
	out := make([]byte, 6+33+33*len(p.VssCommitment))

	binary.LittleEndian.PutUint16(out[0:2], uint16(p.ID))
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(p.VssCommitment)))

	writePointTo(out[6:], p.PublicKey)

	for i, c := range p.VssCommitment {
		if c.Y.IsOdd() {
			out[6+33+i*33] = secp256k1.PubKeyFormatCompressedOdd
		} else {
			out[6+33+i*33] = secp256k1.PubKeyFormatCompressedEven
		}
		c.X.PutBytesUnchecked(out[6+33+i*33+1:])
	}

	return out
}

func (p *PublicKeyShare) Decode(in []byte) (int, error) {
	if len(in) < 6+33 {
		return 0, fmt.Errorf("too small")
	}

	p.ID = int(binary.LittleEndian.Uint16(in[0:2]))
	p.VssCommitment = make([]*secp256k1.JacobianPoint, binary.LittleEndian.Uint32(in[2:6]))

	if pk, err := btcec.ParsePubKey(in[6 : 6+33]); err != nil {
		return 0, fmt.Errorf("failed to decode pubkey: %w", err)
	} else {
		p.PublicKey = new(btcec.JacobianPoint)
		pk.AsJacobian(p.PublicKey)
	}

	fullLength := 6 + 33 + len(p.VssCommitment)*33
	if len(in) < fullLength {
		return 0, fmt.Errorf("too small for vss commitments")
	}

	for i := range p.VssCommitment {
		pk, err := btcec.ParsePubKey(in[6+33+33*i : 6+33+33*i+33])
		if err != nil {
			return 0, fmt.Errorf("failed to decode vss commitment %d: %w", i, err)
		}
		p.VssCommitment[i] = new(btcec.JacobianPoint)
		pk.AsJacobian(p.VssCommitment[i])

	}

	return fullLength, nil
}
