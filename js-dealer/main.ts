import { bytesToHex } from "@noble/curves/abstract/utils";
import type { SimplePool } from "@nostr/tools/pool";
import type { SubCloser } from "@nostr/tools/abstract-pool";
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  type NostrEvent,
  type UnsignedEvent,
} from "@nostr/tools/pure";
import { encrypt, getConversationKey } from "@nostr/tools/nip44";

import { trustedKeyDeal } from "./shardkey.ts";
import { hexPubShard, hexShard } from "./encodeshard.ts";

export async function shardGetBunker(
  pool: SimplePool,
  sec: Uint8Array,
  pub: string,
  threshold: number,
  maxSigners: number,
  signers: string[],
  coordinatorURL: string,
  powTarget: number,
  inboxes: { [pubkey: string]: string[] },
  ourInbox: string[],
  minePow: (
    unsigned: UnsignedEvent,
    difficulty: number,
    onBetterHash: (pow: number) => void,
  ) => Promise<Omit<NostrEvent, "sig">>,
  onProgress: (pct: number) => void,
): Promise<NostrEvent> {
  const now = Math.ceil(Date.now() / 1000);

  const { shards } = trustedKeyDeal(
    BigInt("0x" + bytesToHex(sec)),
    threshold,
    maxSigners,
  );

  const progress: number[] = [];

  // send a shard to each signer
  let s = 0;
  const coordEvtTags: string[][] = [];
  const randomizer = Math.floor(Math.random() * signers.length);
  for (let p = 0; p < signers.length; p++) {
    if (s === shards.length) break;

    const signer = signers[(p + randomizer) % signers.length];
    console.log("[info] trying signer", signer);

    if (!inboxes[signer]) {
      console.log("[info] signer has no relays", signer);
      continue;
    }

    const shard = shards[s];
    const encoded = hexShard(shard);

    const convkey = getConversationKey(sec, signer);
    const ciphertext = encrypt(encoded, convkey);

    const unsignedShardEvt = await minePow(
      {
        pubkey: pub,
        created_at: now,
        kind: 26428,
        tags: [
          ["p", signer],
          ["coordinator", coordinatorURL],
        ],
        content: ciphertext,
      },
      powTarget,
      (pow: number) => {
        progress[s] = pow;
        onProgress(
          (progress.reduce(
            (acc, pow) =>
              acc +
              (pow * pow * pow) /
                (powTarget * powTarget * powTarget),
            0,
          ) /
            maxSigners) *
            100,
        );
      },
    );
    const shardEvt = finalizeEvent(unsignedShardEvt, sec);
    console.log("[info] mining complete", shardEvt);

    // wait for answer
    try {
      let sub: SubCloser;
      await new Promise((resolve, reject) => {
        sub = pool.subscribeMany(
          ourInbox,
          [
            {
              kinds: [26429],
              authors: [signer],
              "#p": [pub],
              "#e": [shardEvt.id],
            },
          ],
          {
            onevent: resolve,
          },
        );

        // send shard
        console.log(
          "[info] sending shard to",
          signer,
          "at",
          inboxes[signer],
        );
        pool.publish(inboxes[signer], shardEvt);

        setTimeout(reject, 7000);
      }).finally(sub!.close);
    } catch (err) {
      console.warn("failed to contact signer", signer, err);
      continue;
    }

    // this one worked, add it to the coordinator event
    coordEvtTags.push(["p", signer, hexPubShard(shard.pubShard)]);

    s++;
    console.log("[info] signer is good", signer);
  }

  // if we don't have enough signers stop here
  if (coordEvtTags.length < maxSigners) {
    throw "Failed to get enough signers.";
  }

  // now that we have sent all the shards inform the coordinator
  const handlerSecret = generateSecretKey();
  const handlerPublic = getPublicKey(handlerSecret);
  coordEvtTags.push(
    ["threshold", threshold.toString()],
    ["handlersecret", bytesToHex(handlerSecret)],
    ["h", handlerPublic],
  );
  const coordEvt = finalizeEvent(
    {
      created_at: now,
      kind: 16430,
      tags: coordEvtTags,
      content: "",
    },
    sec,
  );

  try {
    await pool.publish([coordinatorURL], coordEvt)[0];
    return coordEvt;
  } catch (err) {
    let message = String(err);
    if (!message.startsWith("error") && !message.startsWith("Error")) {
      message = "Error: " + message;
    }
    throw message;
  }
}
