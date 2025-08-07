import { bytesToHex } from "@noble/curves/abstract/utils";
import type { SimplePool } from "@nostr/tools/pool";
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
import { getSemaphore } from "@henrygd/semaphore";

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
  onSigner?: (pubkey: string, error: string | null) => void,
  hardcodedReadRelays: string[] = [
    "wss://relay.primal.net",
    "wss://pyramid.fiatjaf.com",
    "wss://relay.damus.io",
    "wss://nostr-pub.wellorder.net",
  ],
): Promise<NostrEvent> {
  const now = Math.ceil(Date.now() / 1000);

  const { shards } = trustedKeyDeal(
    BigInt("0x" + bytesToHex(sec)),
    threshold,
    maxSigners,
  );

  const progress: number[] = [];
  const maxFailures = signers.length - maxSigners;
  let failed = 0;

  // send a shard to each signer
  const coordEvtTags: string[][] = [];

  let itsUselessToContinue = false;
  const sem = getSemaphore(Symbol(), shards.length);
  const work = getSemaphore(Symbol(), 1);

  await Promise.all(signers.map(async (signer, p) => {
    console.log("[info] initializing signer", signer);
    await sem.acquire();

    if (itsUselessToContinue) {
      sem.release();
      return;
    }

    if (shards.length === 0) {
      // already distributed enough shards
      sem.release();
      return;
    }

    // get a shard we'll use
    const shard = shards.pop()!;

    console.log("[info] trying signer", signer);

    if (!inboxes[signer]) {
      console.log("[info] signer has no relays", signer);
      shards.push(shard); // return the shard
      sem.release();
      return;
    }

    const encoded = hexShard(shard);

    const convkey = getConversationKey(sec, signer);
    const ciphertext = encrypt(encoded, convkey);

    // this isn't async because we can't mine more than once pow at a time anyway
    await work.acquire();
    const unsignedShardEvt = await minePow(
      {
        pubkey: pub,
        created_at: now,
        kind: 26428,
        tags: [
          ["p", signer],
          ["coordinator", coordinatorURL],
          [
            "reply",
            ...hardcodedReadRelays,
          ],
        ],
        content: ciphertext,
      },
      powTarget,
      (pow: number) => {
        progress[p] = pow;
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
    work.release();
    const shardEvt = finalizeEvent(unsignedShardEvt, sec);
    console.log("[info] mining complete", signer, shardEvt);

    try {
      await new Promise<void>((resolve, reject) => {
        const subc = pool.subscribe(
          [...ourInbox, ...hardcodedReadRelays],
          {
            kinds: [26429],
            authors: [signer],
            "#p": [pub],
            "#e": [shardEvt.id],
          },
          {
            onevent: () => {
              resolve();
              subc?.close();
            },
          },
        );

        setTimeout(() => {
          reject("timeout: 7s");
          subc?.close();
        }, 7000);

        // send shard
        console.log("[info] sending shard to", signer, "at", inboxes[signer]);
        const signerRelays = inboxes[signer];
        Promise.any(pool.publish(signerRelays, shardEvt))
          .catch((errs: AggregateError) => {
            errs.errors.forEach((err, i) => {
              console.warn(signerRelays[i], err);
            });
            reject(`Failed to publish to all of [ ${signerRelays.join(" ")} ]`);
          });
      });
    } catch (err) {
      failed++;

      onSigner?.(signer, `failed to contact: ${err}`);
      if (failed > maxFailures) {
        itsUselessToContinue = true;
      }

      progress[p] = 0;

      shards.push(shard); // return the shard
      sem.release();
      return;
    }

    console.log("[info] signer is good", signer);

    // all was ok
    onSigner?.(signer, null);

    // this one worked, add it to the coordinator event
    coordEvtTags.push(["p", signer, hexPubShard(shard.pubShard)]);

    // when succeeding we purposefully don't release the semaphore so the loop doesn't end early
    //
    // -- but when we have gotten enough signers we must release this so any other attempts locked
    //    in the sem.acquire() line above can succeed and we can exit the loop
    if (coordEvtTags.length === maxSigners) {
      sem.release();
    }
  }));

  if (itsUselessToContinue) {
    throw new Error("Too many failures: failed to get enough signers.");
  }

  if (shards.length > 0) {
    throw "Failed to get enough signers!";
  }

  // if we don't have enough signers stop here
  if (coordEvtTags.length < maxSigners) {
    throw "Failed to get enough signers?";
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
