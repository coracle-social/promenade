import type {AffinePoint} from '@noble/curves/abstract/curve'
import {secp256k1} from '@noble/curves/secp256k1'

const G = secp256k1.ProjectivePoint.BASE

export type KeyShard = {
  secret: bigint
  pubkey: AffinePoint<bigint>
  pubShard: PubShard
}

export type PubShard = {
  pubkey: AffinePoint<bigint>
  vssCommit: AffinePoint<bigint>[]
  id: number
}

type Polynomial = Array<bigint>

export function trustedKeyDeal(
  secret: bigint,
  threshold: number,
  maxSigners: number
): {
  shards: KeyShard[]
  pubkey: AffinePoint<bigint>
  commits: AffinePoint<bigint>[]
} {
  let pubkey = G.multiplyUnsafe(secret).toAffine()
  if ((pubkey.y & 1n) === 1n) {
    secret = secp256k1.CURVE.n - secret
    pubkey = G.multiplyUnsafe(secret).toAffine()
  }

  if (threshold > maxSigners || threshold <= 0) {
    throw new Error('invalid number of signers or threshold')
  }

  const polynomial = makePolynomial(secret, threshold)

  // evaluate the polynomial for each point x=1,...,n
  const shards: KeyShard[] = []
  for (let i = 0; i < maxSigners; i++) {
    const id = i + 1
    const yi = evaluatePolynomial(polynomial, BigInt(id))
    const pksh = G.multiplyUnsafe(yi).toAffine()

    shards.push({
      secret: yi,
      pubkey: pubkey,
      pubShard: {
        pubkey: pksh,
        vssCommit: [],
        id: id
      }
    })
  }

  const commits = vssCommit(polynomial)

  return {shards, pubkey, commits}
}

function makePolynomial(secret: bigint, threshold: number): Polynomial {
  const polynomial: Polynomial = []
  let i = 0

  polynomial[0] = secret
  i++

  for (; i < threshold; i++) {
    const b = secp256k1.utils.randomPrivateKey()
    polynomial[i] = secp256k1.utils.normPrivateKeyToScalar(b)
  }

  return polynomial
}

function vssCommit(polynomial: Polynomial): AffinePoint<bigint>[] {
  const commits: AffinePoint<bigint>[] = []
  for (let p = 0; p < polynomial.length; p++) {
    const coeff = polynomial[p]
    const pt = G.multiplyUnsafe(coeff)
    commits.push(pt.toAffine())
  }
  return commits
}

function evaluatePolynomial(polynomial: Polynomial, x: bigint): bigint {
  // since value is an accumulator and starts with 0, we can skip multiplying by x, and start from the end
  let value = polynomial[polynomial.length - 1]
  for (let i = polynomial.length - 2; i >= 0; i--) {
    value =
      (((value * x) % secp256k1.CURVE.n) + polynomial[i]) % secp256k1.CURVE.n
  }
  return value
}
