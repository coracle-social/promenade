package frost

import (
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Polynomial over scalars, represented as a list of t+1 coefficients, where t is the threshold.
// The constant term is in the first position and the highest degree coefficient is in the last position.
// All operations on the polynomial's coefficient are done modulo the scalar's group order.
type Polynomial []*btcec.ModNScalar

func shardReturnPolynomial(
	secret *btcec.ModNScalar,
	threshold, maxParticipants int,
) ([]KeyShare, Polynomial, error) {
	if maxParticipants < threshold {
		return nil, nil, fmt.Errorf("wrong number of shares")
	}

	p, err := makePolynomial(secret, threshold)
	if err != nil {
		return nil, nil, err
	}

	pubkey := &btcec.JacobianPoint{}
	btcec.ScalarBaseMultNonConst(p[0], pubkey)
	pubkey.ToAffine()

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]KeyShare, maxParticipants)

	for i := 0; i < maxParticipants; i++ {
		secretKeyShares[i] = makeKeyShare(i+1, p, pubkey)
	}

	return secretKeyShares, p, nil
}

func makePolynomial(secret *btcec.ModNScalar, threshold int) (Polynomial, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("wrong threshold")
	}
	if secret.IsZero() {
		return nil, fmt.Errorf("secret key is zero")
	}

	p := make(Polynomial, threshold)

	i := 0

	p[0] = new(btcec.ModNScalar)
	p[0].Set(secret)
	i++

	for ; i < threshold; i++ {
		var random [32]byte
		rand.Read(random[:])
		p[i] = new(btcec.ModNScalar)
		p[i].SetBytes(&random)
	}

	return p, nil
}

// makePolynomialFromListFunc returns a Polynomial from the scalar returned by f applied on each element of the slice
func makePolynomialFromListFunc[S ~[]E, E any](s S, f func(E) *btcec.ModNScalar) Polynomial {
	polynomial := make(Polynomial, len(s))
	for i, v := range s {
		polynomial[i] = new(btcec.ModNScalar).Set(f(v))
	}
	return polynomial
}

func makeKeyShare(id int, p Polynomial, pubkey *btcec.JacobianPoint) KeyShare {
	ids := new(btcec.ModNScalar).SetInt(uint32(id))
	yi := p.Evaluate(ids)

	pksh := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(yi, pksh)
	pksh.ToAffine()

	return KeyShare{
		Secret:    yi,
		PublicKey: pubkey,
		PublicKeyShare: PublicKeyShare{
			PublicKey:     pksh,
			VssCommitment: nil,
			ID:            id,
		},
	}
}

// Evaluate evaluates the polynomial p at point x using Horner's method.
func (p Polynomial) Evaluate(x *btcec.ModNScalar) *btcec.ModNScalar {
	// since value is an accumulator and starts with 0, we can skip multiplying by x, and start from the end
	value := new(btcec.ModNScalar).Set(p[len(p)-1])
	for i := len(p) - 2; i >= 0; i-- {
		value = value.Mul(x).Add(p[i])
	}

	return value
}

// VssCommitment is the tuple defining a Verifiable Secret Sharing VssCommitment to a secret Polynomial.
type VssCommitment []*btcec.JacobianPoint

// Commit builds a Verifiable Secret Sharing vector VssCommitment to each of the coefficients
// (of threshold length which uniquely determines the polynomial).
func VSSCommit(polynomial Polynomial) VssCommitment {
	commits := make(VssCommitment, len(polynomial))
	for i, coeff := range polynomial {
		pt := &btcec.JacobianPoint{}
		btcec.ScalarBaseMultNonConst(coeff, pt)
		pt.ToAffine()
		commits[i] = pt
	}
	return commits
}
