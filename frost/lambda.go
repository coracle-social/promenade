package frost

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
)

// computeLambda derives the interpolating value for id in the polynomial made by the participant identifiers.
// This function is not public to protect its usage, as the following conditions MUST be met.
// - id is non-nil and != 0.
// - every scalar in participants is non-nil and != 0.
// - there are no duplicates in participants.
func computeLambda(id int, participants []int) *btcec.ModNScalar {
	sid := new(btcec.ModNScalar).SetInt(uint32(id))
	numerator := new(btcec.ModNScalar).SetInt(1)
	denominator := new(btcec.ModNScalar).SetInt(1)

	for _, part := range participants {
		if part == id {
			continue
		}

		spart := new(btcec.ModNScalar).SetInt(uint32(part))
		numerator.Mul(spart)
		denominator.Mul(new(btcec.ModNScalar).Set(spart).Add(new(btcec.ModNScalar).NegateVal(sid)))
	}

	return numerator.Mul(denominator.InverseNonConst())
}

// A Lambda is the interpolating value for a given id in the polynomial made by the participant identifiers.
type Lambda struct {
	// Value is the actual Lambda value.
	Value *btcec.ModNScalar `json:"value"`
}

type lambdaShadow Lambda

// LambdaRegistry holds a signers pre-computed Lambda values, indexed by the list of participants they are associated
// to. A sorted set of participants will yield the same Lambda.
type LambdaRegistry map[string]*Lambda

func lambdaRegistryKey(id int, participants []int) string {
	key := make([]byte, 2+2*len(participants))
	binary.BigEndian.PutUint16(key[0:2], uint16(id))
	for i, part := range participants {
		binary.BigEndian.PutUint16(key[2+i*2:2+(i+1)*2], uint16(part))
	}
	return hex.EncodeToString(key)
}

// New creates a new Lambda and for the participant list for the participant id, and registers it.
// This function assumes that:
// - id is non-nil and != 0.
// - every participant id is != 0.
// - there are no duplicates in participants.
func (l LambdaRegistry) new(id int, participants []int) *btcec.ModNScalar {
	lambda := computeLambda(id, participants)
	l.set(id, participants, lambda)
	return lambda
}

// Get returns the recorded Lambda for the list of participants, or nil if it wasn't found.
func (l LambdaRegistry) get(id int, participants []int) *btcec.ModNScalar {
	key := lambdaRegistryKey(id, participants)

	v := l[key]
	if v == nil {
		return nil
	}

	return v.Value
}

// GetOrNew returns the recorded Lambda for the list of participants, or created, records, and returns a new one if
// it wasn't found.
// This function assumes that:
// - id is non-nil and != 0.
// - every scalar in participants is non-nil and != 0.
// - there are no duplicates in participants.
func (l LambdaRegistry) getOrNew(participants []int, id int) *btcec.ModNScalar {
	lambda := l.get(id, participants)
	if lambda != nil {
		return lambda
	} else {
		return l.new(id, participants)
	}
}

// Set records Lambda for the given set of participants.
func (l LambdaRegistry) set(id int, participants []int, value *btcec.ModNScalar) {
	key := lambdaRegistryKey(id, participants)
	l[key] = &Lambda{
		Value: value,
	}
}
