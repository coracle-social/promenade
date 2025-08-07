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
    const randomizer = Math.floor(Math.random() * signers.length);
    const done: Promise<void>[] = [];

    let itsUselessToContinue = false;
    const sem = getSemaphore(Symbol(), shards.length);

    for (let p = 0; p < signers.length; p++) {
        if (itsUselessToContinue) {
            throw new Error("Too many failures: failed to get enough signers.");
        }

        await sem.acquire();

        if (shards.length === 0) {
            // already distributed enough shards
            break;
        }

        // get a shard we'll use
        const shard = shards.pop()!;

        const signer = signers[(p + randomizer) % signers.length];
        console.log("[info] trying signer", signer);

        if (!inboxes[signer]) {
            console.log("[info] signer has no relays", signer);
            shards.push(shard); // return the shard
            sem.release();
            continue;
        }

        const encoded = hexShard(shard);

        const convkey = getConversationKey(sec, signer);
        const ciphertext = encrypt(encoded, convkey);

        // this isn't async because we can't mine more than once pow at a time anyway
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
        const shardEvt = finalizeEvent(unsignedShardEvt, sec);
        console.log("[info] mining complete", signer, shardEvt);

        const answer = new Promise<void>((resolve, reject) => {
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
        });

        // send shard
        console.log(
            "[info] sending shard to",
            signer,
            "at",
            inboxes[signer],
        );

        const signerRelays = inboxes[signer];
        const pubSuccess = Promise.any(pool.publish(signerRelays, shardEvt))
            .catch((errs: AggregateError) => {
                errs.errors.forEach((err, i) => {
                    console.warn(signerRelays[i], err);
                });
                throw `Failed to publish to all of [ ${
                    signerRelays.join(" ")
                } ]`;
            });

        const ack = Promise.all([pubSuccess, answer])
            .then(() => {
                console.log("[info] signer is good", signer);

                // all was ok
                onSigner?.(signer, null);

                // this one worked, add it to the coordinator event
                coordEvtTags.push(["p", signer, hexPubShard(shard.pubShard)]);

                // when succeeding we purposefully don't release the semaphore so the loop doesn't end early
            }).catch((err) => {
                failed++;

                onSigner?.(signer, `failed to contact: ${err}`);
                if (failed > maxFailures) {
                    itsUselessToContinue = true;
                    shards.push(shard); // return the shard
                }

                sem.release();
            });

        done.push(ack);
    }

    if (shards.length > 0) {
        throw "Failed to get enough signers!";
    }

    try {
        await Promise.all(done);
    } catch (_) {
        throw "Failed to get enough signers.";
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
