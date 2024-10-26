import type {AffinePoint} from '@noble/curves/abstract/curve'
import {bytesToHex, numberToBytesBE} from '@noble/curves/abstract/utils'
import type {KeyShard, PubShard} from './shardkey'

export function hexShard(shard: KeyShard): string {
  return bytesToHex(encodeShard(shard))
}

function encodeShard(shard: KeyShard): Uint8Array {
  const out = new Uint8Array(
    6 + 33 + 33 * shard.pubShard.vssCommit.length + 32 + 33
  )

  writePubShardTo(out, shard.pubShard)

  out.set(
    numberToBytesBE(shard.secret, 32),
    6 + 33 + shard.pubShard.vssCommit.length * 33
  )
  writePointTo(
    out,
    6 + 33 + shard.pubShard.vssCommit.length * 33 + 32,
    shard.pubkey
  )

  return out
}

export function hexPubShard(pubShard: PubShard): string {
  return bytesToHex(encodePubShard(pubShard))
}

function encodePubShard(pubShard: PubShard): Uint8Array {
  const out = new Uint8Array(6 + 33 + 33 * pubShard.vssCommit.length)
  writePubShardTo(out, pubShard)
  return out
}

function writePubShardTo(out: Uint8Array, pubShard: PubShard) {
  const dv = new DataView(out.buffer)

  dv.setUint16(0, pubShard.id, true)
  dv.setUint32(2, pubShard.vssCommit.length, true)

  writePointTo(out, 6, pubShard.pubkey)

  for (let i = 0; i < pubShard.vssCommit.length; i++) {
    const c = pubShard.vssCommit[i]
    writePointTo(out, 6 + 33 + i * 33, c)
  }
}

function writePointTo(
  out: Uint8Array,
  offset: number,
  pt: AffinePoint<bigint>
) {
  if ((pt.y & 1n) === 1n) {
    // odd
    out[offset] = 3
  } else {
    // event
    out[offset] = 2
  }

  const xBytes = numberToBytesBE(pt.x, 32)
  out.set(xBytes, offset + 1)
}
