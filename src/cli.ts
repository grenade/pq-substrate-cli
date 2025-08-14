#!/usr/bin/env node
import { WebSocket } from "ws";
import type { RawData } from "ws";
import { createHash } from "node:crypto";
import { encodeAddress } from "@polkadot/util-crypto";
import { cryptoWaitReady } from "@polkadot/util-crypto";

/** ---------- CLI args ---------- */
const usage = `usage:
  decode-block-extrinsics <ws-url> <block-number-or-hash>

examples:
  decode-block-extrinsics wss://a.t.res.fm 129430
  decode-block-extrinsics wss://a.t.res.fm 0xd939e389d83c1bdd5414032d6b4c7529278cf9e7d19931e533fae899c6bbcc6c
`;

// slice off "node" and script, drop lone "--" that pnpm/tsx may inject
const args = process.argv.slice(2).filter((a) => a !== "--");

if (args.length !== 2) {
  console.error(usage);
  process.exit(1);
}

const [wsUrl, blockArg] = args;
const SS58_PREFIX = 189;
const RES_DECIMALS = 12;

/** ---------- JSON-RPC over WS ---------- */

type Json = any;

class Rpc {
  private ws!: WebSocket;
  private id = 1;
  private pending = new Map<
    number,
    { resolve: (v: any) => void; reject: (e: any) => void }
  >();

  constructor(private url: string) {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on("open", () => resolve());
      this.ws.on("error", (e: Error) => reject(e));
      this.ws.on("message", (data: RawData) => {
        let msg: any;
        try {
          msg = JSON.parse(data.toString());
        } catch {
          return;
        }
        if (msg && typeof msg.id === "number" && this.pending.has(msg.id)) {
          const p = this.pending.get(msg.id)!;
          this.pending.delete(msg.id);
          if ("error" in msg) p.reject(new Error(JSON.stringify(msg.error)));
          else p.resolve(msg.result);
        }
      });
    });
  }

  call(method: string, params: any[] = []): Promise<any> {
    const id = this.id++;
    const payload = { jsonrpc: "2.0", id, method, params };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
  }

  async close() {
    if (!this.ws) return;
    if (this.ws.readyState === this.ws.CLOSED) return;

    await new Promise<void>((resolve) => {
      const done = () => resolve();
      this.ws.once("close", done);
      try {
        this.ws.close(1000);
      } catch {
        // if close throws because it’s already closing/closed, just resolve
        this.ws.off("close", done);
        resolve();
      }
    });
  }
}

/** ---------- SCALE + SS58 helpers (metadata-free) ---------- */

function hexToU8a(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function readCompactInt(a: Uint8Array, o: number): [bigint, number] {
  const b0 = a[o];
  const mode = b0 & 0b11;
  if (mode === 0) {
    return [BigInt(b0 >> 2), 1];
  } else if (mode === 1) {
    const v = ((a[o] | (a[o + 1] << 8)) >>> 2) >>> 0;
    return [BigInt(v), 2];
  } else if (mode === 2) {
    const v =
      ((a[o] | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24)) >>> 2) >>>
      0;
    return [BigInt(v), 4];
  } else {
    const len = (b0 >> 2) + 4;
    let v = 0n;
    for (let i = 0; i < len; i++) v |= BigInt(a[o + 1 + i]) << (8n * BigInt(i));
    return [v, 1 + len];
  }
}

function readScaleBytes(a: Uint8Array, o: number): [Uint8Array, number] {
  const [len, lRead] = readCompactInt(a, o);
  const L = Number(len);
  const start = o + lRead;
  const end = start + L;
  return [a.slice(start, end), lRead + L];
}

type Era =
  | { type: "immortal" }
  | { type: "mortal"; period: number; phase: number };
function readEra(a: Uint8Array, o: number): [Era, number] {
  const first = a[o];
  if (first === 0x00) return [{ type: "immortal" }, 1];
  const second = a[o + 1];
  const encoded = first + (second << 8);
  const period = 2 ** (encoded & 0b111111);
  const quantizeFactor = Math.max(period >> 12, 1);
  const phase = (encoded >> 6) * quantizeFactor;
  return [{ type: "mortal", period, phase }, 2];
}

/** MultiAddress subset (only cases we need) */
type MultiAddress =
  | { type: "Id"; id: Uint8Array }
  | { type: "Index"; index: bigint }
  | { type: "Raw"; data: Uint8Array }
  | { type: "Address32"; data: Uint8Array }
  | { type: "Address20"; data: Uint8Array };

function readMultiAddress(a: Uint8Array, o: number): [MultiAddress, number] {
  const kind = a[o];
  if (kind === 0x00) {
    return [{ type: "Id", id: a.slice(o + 1, o + 33) }, 33];
  } else if (kind === 0x01) {
    const [v, r] = readCompactInt(a, o + 1);
    return [{ type: "Index", index: v }, 1 + r];
  } else if (kind === 0x02) {
    const [bytes, r] = readScaleBytes(a, o + 1);
    return [{ type: "Raw", data: bytes }, 1 + r];
  } else if (kind === 0x03) {
    return [{ type: "Address32", data: a.slice(o + 1, o + 33) }, 33];
  } else if (kind === 0x04) {
    return [{ type: "Address20", data: a.slice(o + 1, o + 21) }, 21];
  }
  throw new Error(`Unknown MultiAddress kind: 0x${kind.toString(16)}`);
}

/** SS58 (prefix 189 for this chain)
const SS58_PREFIX = 189;
function ss58Encode(accountId: Uint8Array, ss58Prefix = SS58_PREFIX): string {
  if (accountId.length !== 32) throw new Error("AccountId must be 32 bytes");
  const fmt = new Uint8Array([ss58Prefix]);
  const payload = new Uint8Array(fmt.length + accountId.length);
  payload.set(fmt, 0);
  payload.set(accountId, fmt.length);
  const checksum = ss58Checksum(payload);
  const full = new Uint8Array(payload.length + 2);
  full.set(payload, 0);
  full.set(checksum.slice(0, 2), payload.length);
  return base58Encode(full);
}
 */
function ss58Checksum(data: Uint8Array): Uint8Array {
  const pre = Buffer.from("53533538505245", "hex"); // "SS58PRE"
  const hash = createHash("blake2b512");
  hash.update(pre);
  hash.update(Buffer.from(data));
  return hash.digest().subarray(0, 64);
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(buf: Uint8Array): string {
  let x = BigInt("0x" + Buffer.from(buf).toString("hex"));
  const base = 58n;
  let out = "";
  while (x > 0n) {
    const mod = x % base;
    out = ALPHABET[Number(mod)] + out;
    x = x / base;
  }
  for (const b of buf) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

function toHuman(v: bigint, decimals = RES_DECIMALS): string {
  const s = v.toString().padStart(decimals + 1, "0");
  const head = s.slice(0, -decimals) || "0";
  const tail = s.slice(-decimals).replace(/0+$/, "");
  return tail.length ? `${head}.${tail}` : head;
}

/** ---------- Extrinsic parser ---------- */
type Parsed = {
  ok: boolean;
  rawLength: number;
  version: number;
  isSigned: boolean;
  callIndex: { pallet: number; call: number };
  sender?: string;
  recipient?: string;
  amountPlanck?: bigint;
  amountRES?: string;
  tipPlanck?: bigint;
  tipRES?: string;
  nonce?: bigint;
  error?: string;
};

function parseExtrinsic(hex: string): Parsed {
  try {
    const all = hexToU8a(hex);
    let off = 0;
    const [lenBig, lenBytes] = readCompactInt(all, off);
    const len = Number(lenBig);
    off += lenBytes;
    const x = all.slice(off, off + len);
    let i = 0;

    const version = x[i++];
    const isSigned = (version & 0x80) !== 0;
    const vers = version & 0x7f;
    if (vers !== 4 && vers !== 5)
      throw new Error(`Unsupported version ${vers}`);

    let sender: string | undefined;
    let tip: bigint | undefined;
    let nonce: bigint | undefined;

    if (isSigned) {
      const [signer, sRead] = readMultiAddress(x, i);
      i += sRead;
      if (signer.type === "Id") sender = encodeAddress(signer.id, SS58_PREFIX);

      const [_sig, sigRead] = readScaleBytes(x, i); // PQ-safe: signature as Bytes
      i += sigRead;

      const [_era, eraRead] = readEra(x, i);
      i += eraRead;

      const [_nonce, nRead] = readCompactInt(x, i);
      i += nRead;
      nonce = _nonce;

      const [_tip, tRead] = readCompactInt(x, i);
      i += tRead;
      tip = _tip;
    }

    const palletIndex = x[i++];
    const callIndex = x[i++];

    let recipient: string | undefined;
    let amountPlanck: bigint | undefined;

    // Try to decode as balances transfer{,_keep_alive}: dest, value
    try {
      const [dest, dRead] = readMultiAddress(x, i);
      i += dRead;
      if (dest.type === "Id") {
        recipient = encodeAddress(dest.id, SS58_PREFIX);
      } else {
        // Not a typical AccountId dest; throw to fall back
        throw new Error("Non-Id dest");
      }
      const [amt, aRead] = readCompactInt(x, i);
      i += aRead;
      amountPlanck = amt;
    } catch {
      // Not a balances transfer-like call; leave as undefined
    }

    const res: Parsed = {
      ok: true,
      rawLength: len,
      version,
      isSigned,
      callIndex: { pallet: palletIndex, call: callIndex },
      sender,
      recipient,
      amountPlanck,
      amountRES:
        amountPlanck !== undefined ? `${toHuman(amountPlanck)} RES` : undefined,
      tipPlanck: tip,
      tipRES: tip !== undefined ? `${toHuman(tip)} RES` : undefined,
      nonce,
    };
    return res;
  } catch (e: any) {
    return {
      ok: false,
      rawLength: 0,
      version: 0,
      isSigned: false,
      callIndex: { pallet: 0, call: 0 },
      error: e?.message ?? String(e),
    };
  }
}

/** ---------- Main ---------- */

(async () => {
  await cryptoWaitReady();
  const rpc = new Rpc(wsUrl);
  try {
    await rpc.connect();

    let blockHash: string;
    if (/^0x[0-9a-fA-F]{64}$/.test(blockArg)) {
      blockHash = blockArg;
    } else if (/^\d+$/.test(blockArg)) {
      const num = "0x" + BigInt(blockArg).toString(16);
      blockHash = await rpc.call("chain_getBlockHash", [num]);
    } else {
      throw new Error("Block must be a decimal number or 0x-hash");
    }

    const block = await rpc.call("chain_getBlock", [blockHash]);
    if (!block || !block.block || !Array.isArray(block.block.extrinsics)) {
      throw new Error("Unexpected block shape from chain_getBlock");
    }

    const numberHex: string = block.block.header?.number ?? "0x0";
    const number = BigInt(numberHex).toString(10);

    console.log(
      JSON.stringify(
        {
          blockNumber: number,
          blockHash,
          extrinsicsCount: block.block.extrinsics.length,
        },
        null,
        2,
      ),
    );

    block.block.extrinsics.forEach((hex: string, idx: number) => {
      const p = parseExtrinsic(hex);
      const out = {
        index: idx,
        ok: p.ok,
        callIndex: p.callIndex, // { pallet, call }
        isSigned: p.isSigned,
        sender: p.sender,
        recipient: p.recipient,
        amountPlanck: p.amountPlanck?.toString(),
        amountRES: p.amountRES,
        tipPlanck: p.tipPlanck?.toString(),
        tipRES: p.tipRES,
        nonce: p.nonce?.toString(),
        rawLength: p.rawLength,
        error: p.error,
      };
      console.log(JSON.stringify(out));
    });
  } catch (e: any) {
    console.error("error:", e?.message ?? e);
    process.exit(1);
  } finally {
    await rpc.close();
  }
})();
