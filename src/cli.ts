#!/usr/bin/env node
import { WebSocket } from "ws";
import type { RawData } from "ws";
import { cryptoWaitReady, encodeAddress } from "@polkadot/util-crypto";
import { BN } from "@polkadot/util";
import { UInt } from "@polkadot/types-codec";
import { TypeRegistry } from "@polkadot/types/create";
import { Metadata } from "@polkadot/types/metadata";
import { xxhashAsU8a } from "@polkadot/util-crypto";

/** ---------- CLI args ---------- */
const usage = `usage:
  decode-block-extrinsics <ws-url> <block-number-or-hash>

examples:
  decode-block-extrinsics wss://a.t.res.fm 129430
  decode-block-extrinsics wss://a.t.res.fm 0xd939e389d83c1bdd5414032d6b4c7529278cf9e7d19931e533fae899c6bbcc6c
`;

const args = process.argv.slice(2).filter((a) => a !== "--");
if (args.length !== 2) {
  console.error(usage);
  process.exit(1);
}
const [wsUrl, blockArg] = args;

/** ---------- Tiny JSON-RPC over WS ---------- */
class Rpc {
  private ws!: WebSocket;
  private id = 1;
  private waiting = new Map<
    number,
    { res: (v: any) => void; rej: (e: any) => void }
  >();

  constructor(private url: string) {}

  connect() {
    return new Promise<void>((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on("open", () => resolve());
      this.ws.on("error", (e: Error) => reject(e));
      this.ws.on("message", (d: RawData) => {
        let m: any;
        try {
          m = JSON.parse(d.toString());
        } catch {
          return;
        }
        if (m && typeof m.id === "number" && this.waiting.has(m.id)) {
          const w = this.waiting.get(m.id)!;
          this.waiting.delete(m.id);
          "error" in m
            ? w.rej(new Error(JSON.stringify(m.error)))
            : w.res(m.result);
        }
      });
    });
  }
  call(method: string, params: any[] = []) {
    const id = this.id++;
    this.ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    return new Promise<any>((res, rej) => this.waiting.set(id, { res, rej }));
  }
  async close() {
    if (!this.ws || this.ws.readyState === this.ws.CLOSED) return;
    await new Promise<void>((r) => {
      const done = () => r();
      this.ws.once("close", done);
      try {
        this.ws.close(1000);
      } catch {
        this.ws.off("close", done);
        r();
      }
    });
  }
}

/** ---------- SCALE helpers (metadata-free) ---------- */
function hexToU8a(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2) throw new Error("Invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function readCompactInt(a: Uint8Array, o: number): [bigint, number] {
  const b0 = a[o],
    mode = b0 & 3;
  if (mode === 0) return [BigInt(b0 >>> 2), 1];
  if (mode === 1) return [BigInt(((a[o] | (a[o + 1] << 8)) >>> 2) >>> 0), 2];
  if (mode === 2)
    return [
      BigInt(
        ((a[o] | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24)) >>>
          2) >>>
          0,
      ),
      4,
    ];
  const len = (b0 >>> 2) + 4;
  let v = 0n;
  for (let i = 0; i < len; i++) v |= BigInt(a[o + 1 + i]) << (8n * BigInt(i));
  return [v, 1 + len];
}
function readScaleBytes(a: Uint8Array, o: number): [Uint8Array, number] {
  const [len, r] = readCompactInt(a, o);
  const L = Number(len);
  return [a.slice(o + r, o + r + L), r + L];
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
  const quant = Math.max(period >> 12, 1);
  const phase = (encoded >> 6) * quant;
  return [{ type: "mortal", period, phase }, 2];
}
type MultiAddress =
  | { type: "Id"; id: Uint8Array }
  | { type: "Index"; index: bigint }
  | { type: "Raw"; data: Uint8Array }
  | { type: "Address32"; data: Uint8Array }
  | { type: "Address20"; data: Uint8Array };
function readMultiAddress(a: Uint8Array, o: number): [MultiAddress, number] {
  const k = a[o];
  if (k === 0x00) return [{ type: "Id", id: a.slice(o + 1, o + 33) }, 33];
  if (k === 0x01) {
    const [v, r] = readCompactInt(a, o + 1);
    return [{ type: "Index", index: v }, 1 + r];
  }
  if (k === 0x02) {
    const [b, r] = readScaleBytes(a, o + 1);
    return [{ type: "Raw", data: b }, 1 + r];
  }
  if (k === 0x03)
    return [{ type: "Address32", data: a.slice(o + 1, o + 33) }, 33];
  if (k === 0x04)
    return [{ type: "Address20", data: a.slice(o + 1, o + 21) }, 21];
  throw new Error(`Unknown MultiAddress kind 0x${k.toString(16)}`);
}

/** ---------- Formatting ---------- */
function toHuman(v: BN | bigint | string, decimals: number): string {
  const bn = BN.isBN(v) ? v : new BN(v.toString());
  const base = new BN(10).pow(new BN(decimals));
  const i = bn.div(base).toString();
  const fFull = bn.mod(base).toString().padStart(decimals, "0");
  const fTrim = fFull.replace(/0+$/, "");
  return fTrim ? `${i}.${fTrim}` : i;
}

/** ---------- Metadata helpers ---------- */
type CallInfo = {
  name: string;
  callsCount: number;
  callNameByIndex: Map<number, string>;
};

function buildCallIndexMap(metaHex: string) {
  const registry = new TypeRegistry();
  const metadata = new Metadata(registry, hexToU8a(metaHex));
  registry.setMetadata(metadata);

  // v14 pallets live under asLatest.pallets
  const pallets = (metadata as any).asLatest.pallets as any[];

  const callMap = new Map<number, CallInfo>();

  pallets.forEach((p: any) => {
    if (p.calls && p.calls.isSome) {
      const idx = Number(p.index.toNumber());
      const name = p.name.toString();

      // In v14, calls.unwrap().type is a Lookup type ID into the scale-info registry
      const callTypeId = p.calls.unwrap().type; // Compact<SiLookupTypeId>
      const siType = registry.lookup.getSiType(callTypeId);

      // Ensure the looked-up type is a Variant and collect its variants
      const names = new Map<number, string>();
      let count = 0;

      if (siType?.def?.isVariant) {
        const variants = siType.def.asVariant.variants;
        count = variants.length;
        variants.forEach((v: any, i: number) => {
          names.set(i, v.name.toString());
        });
      } else {
        // No variants => no callable dispatchables on this pallet
        count = 0;
      }

      callMap.set(idx, { name, callsCount: count, callNameByIndex: names });
    }
  });

  const ss58FromMeta: number | undefined = (registry as any).chainSS58;

  return { registry, metadata, callMap, ss58FromMeta };
}

function findCallHeaderWithMeta(
  a: Uint8Array,
  start: number,
  callMap: Map<number, { callsCount: number }>,
  scanLimit = 2048,
) {
  for (let sh = 0; sh <= scanLimit; sh++) {
    const i = start + sh;
    if (i + 2 > a.length) break;
    const pallet = a[i],
      call = a[i + 1];
    const info = callMap.get(pallet);
    if (info && call < info.callsCount) return { offset: i, pallet, call };
  }
  return null;
}

// Build the storage key for System.Events: twox128("System") ++ twox128("Events")
function systemEventsStorageKey(): `0x${string}` {
  const p = xxhashAsU8a("System", 128);
  const m = xxhashAsU8a("Events", 128);
  const key = new Uint8Array(p.length + m.length);
  key.set(p, 0);
  key.set(m, p.length);
  return ("0x" + Buffer.from(key).toString("hex")) as `0x${string}`;
}

type TransferEvt = { from: string; to: string; amount: string };

function decodeEventsAtBlock(
  registry: TypeRegistry,
  metadata: Metadata,
  eventsHex: string,
  ss58: number,
): Map<number, { transfers: TransferEvt[] }> {
  registry.setMetadata(metadata); // ensure types are active

  // register custom big-int used by this chain's events
  registry.register({ U512: (UInt.with as any)(512) });

  const bytes = hexToU8a(eventsHex);
  // Vec<EventRecord>
  const EventRecords = (registry as any).createType(
    "Vec<EventRecord>",
    bytes,
  ) as any;
  const byExtrinsic = new Map<number, { transfers: TransferEvt[] }>();
  for (const rec of EventRecords as any[]) {
    const phase = rec.phase; // Phase
    const event = rec.event; // { section, method, data }
    const section =
      event.section?.toString?.() ?? event.pallet?.toString?.() ?? "";
    const method =
      event.method?.toString?.() ?? event.variant?.toString?.() ?? "";

    // Only events that are tied to a specific extrinsic
    if (!phase.isApplyExtrinsic) continue;
    const idx = phase.asApplyExtrinsic.toNumber();

    if (section.toLowerCase() === "balances" && method === "Transfer") {
      // balances::Transfer(AccountId, AccountId, Balance)
      const [from, to, amount] = event.data as any[];
      const fromId = from.toU8a();
      const toId = to.toU8a();
      const t: TransferEvt = {
        from: encodeAddress(fromId, ss58),
        to: encodeAddress(toId, ss58),
        amount: amount.toBn ? amount.toBn().toString() : amount.toString(),
      };
      const entry = byExtrinsic.get(idx) ?? { transfers: [] };
      entry.transfers.push(t);
      byExtrinsic.set(idx, entry);
    }
  }

  return byExtrinsic;
}

/** ---------- Parser using metadata for alignment ---------- */
type Parsed = {
  ok: boolean;
  rawLength: number;
  version: number;
  isSigned: boolean;
  callIndex: { pallet: number; call: number };
  section?: string;
  method?: string;
  sender?: string;
  recipient?: string;
  amountPlanck?: string;
  amountHuman?: string;
  tipPlanck?: string;
  tipHuman?: string;
  nonce?: string;
  error?: string;
};

function parseExtrinsic(
  hex: string,
  ss58: number,
  decimals: number,
  callMap: Map<number, CallInfo>,
  symbol: string,
): Parsed {
  try {
    const all = hexToU8a(hex);
    let o = 0;
    const [len, lenBytes] = readCompactInt(all, o);
    const L = Number(len);
    o += lenBytes;
    const x = all.slice(o, o + L);
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
      if (signer.type === "Id") sender = encodeAddress(signer.id, ss58);

      // Signature as SCALE Bytes (PQ-safe: we don't care about its internals)
      const [_sig, sigRead] = readScaleBytes(x, i);
      i += sigRead;

      const [_era, eraRead] = readEra(x, i);
      i += eraRead;

      const [_nonce, nRead] = readCompactInt(x, i);
      i += nRead;
      nonce = _nonce;
      const [_tip, tRead] = readCompactInt(x, i);
      i += tRead;
      tip = _tip;

      // Do NOT assume anything else — use metadata to align to call header
    }

    // Align to the call header by validating (pallet, call) against metadata
    const slimMap = new Map<number, { callsCount: number }>(
      [...callMap.entries()].map(([k, v]) => [k, { callsCount: v.callsCount }]),
    );
    const found = findCallHeaderWithMeta(x, i, slimMap, 4096);

    if (!found) {
      return {
        ok: true,
        rawLength: L,
        version,
        isSigned,
        callIndex: { pallet: x[i] ?? 0, call: x[i + 1] ?? 0 },
        sender,
        tipPlanck: tip?.toString(),
        tipHuman: tip ? `${toHuman(tip, decimals)} ${symbol}` : undefined,
        nonce: nonce?.toString(),
      };
    }

    i = found.offset;
    const palletIndex = x[i++],
      callIndex = x[i++];

    const info = callMap.get(palletIndex)!;
    const section = info?.name;
    const method = info?.callNameByIndex.get(callIndex) ?? `call_${callIndex}`;

    let recipient: string | undefined;
    let amountPlanck: string | undefined;

    // Decode balances transfer-like args
    if (
      /^balances$/i.test(section) &&
      /^(transfer|transferKeepAlive|transferAllowDeath)$/i.test(method)
    ) {
      try {
        const [dest, dRead] = readMultiAddress(x, i);
        i += dRead;
        if (dest.type === "Id") recipient = encodeAddress(dest.id, ss58);
        const [amt, aRead] = readCompactInt(x, i);
        i += aRead;
        amountPlanck = amt.toString();
      } catch {
        /* leave undefined */
      }
    }

    return {
      ok: true,
      rawLength: L,
      version,
      isSigned,
      callIndex: { pallet: palletIndex, call: callIndex },
      section,
      method,
      sender,
      recipient,
      amountPlanck,
      amountHuman: amountPlanck
        ? `${toHuman(amountPlanck, decimals)} ${symbol}`
        : undefined,
      tipPlanck: tip?.toString(),
      tipHuman: tip ? `${toHuman(tip, decimals)} ${symbol}` : undefined,
      nonce: nonce?.toString(),
    };
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

    // Resolve block hash
    let blockHash: string;
    if (/^0x[0-9a-fA-F]{64}$/.test(blockArg)) {
      blockHash = blockArg;
    } else if (/^\d+$/.test(blockArg)) {
      const numHex = "0x" + BigInt(blockArg).toString(16);
      blockHash = await rpc.call("chain_getBlockHash", [numHex]);
    } else {
      throw new Error("Block must be a decimal number or 0x-hash");
    }

    // Chain props
    const props = await rpc.call("system_properties");
    const tokenSymbols: string[] = Array.isArray(props?.tokenSymbol)
      ? props.tokenSymbol
      : props?.tokenSymbol
        ? [String(props.tokenSymbol)]
        : ["UNIT"];
    const tokenDecimalsArr: number[] = Array.isArray(props?.tokenDecimals)
      ? props.tokenDecimals.map((d: any) => Number(d))
      : props?.tokenDecimals !== undefined
        ? [Number(props.tokenDecimals)]
        : [12];
    const ss58Format: number = Number(props?.ss58Format ?? 42);
    const symbol = tokenSymbols[0] ?? "UNIT";
    const decimals = tokenDecimalsArr[0] ?? 12;

    // Block & extrinsics
    const blk = await rpc.call("chain_getBlock", [blockHash]);
    const numberHex: string = blk.block.header?.number ?? "0x0";
    const number = BigInt(numberHex).toString(10);
    const extrinsics: string[] = blk.block.extrinsics;

    // Metadata at this block
    const metaHex: string = await rpc.call("state_getMetadata", [blockHash]);
    const { callMap, ss58FromMeta, registry, metadata } =
      buildCallIndexMap(metaHex);
    const ss58 = Number.isFinite(ss58FromMeta)
      ? (ss58FromMeta as number)
      : ss58Format;

    // Fetch & decode System.Events at this block
    const eventsKey = systemEventsStorageKey();
    const eventsHex: string = await rpc.call("state_getStorageAt", [
      eventsKey,
      blockHash,
    ]);
    // Note: some nodes use state_getStorage (no At). We already use the At variant.

    const eventsByExtrinsic = eventsHex
      ? decodeEventsAtBlock(registry, metadata, eventsHex, ss58)
      : new Map<number, { transfers: TransferEvt[] }>();

    console.log(
      JSON.stringify(
        {
          blockNumber: number,
          blockHash,
          extrinsicsCount: extrinsics.length,
          symbol,
          decimals,
          ss58Format: ss58,
        },
        null,
        2,
      ),
    );

    // Decode each extrinsic
    for (let idx = 0; idx < extrinsics.length; idx++) {
      const hex = extrinsics[idx];
      const p = parseExtrinsic(hex, ss58, decimals, callMap, symbol);

      // Fill from events if missing
      let recipient = p.recipient;
      let amountPlanck = p.amountPlanck;
      let amountHuman = p.amountHuman;

      // Get fee/weight using block context (preferred 2-arg; fallback 1-arg)
      let weight: { refTime?: string; proofSize?: string } | undefined;
      let partialFeePlanck: string | undefined;
      let partialFeeHuman: string | undefined;

      const ev = eventsByExtrinsic.get(idx);
      if ((!recipient || !amountPlanck) && ev && ev.transfers.length > 0) {
        // If multiple transfers, you can choose the first or aggregate; the explorer likely shows the primary one.
        const t = ev.transfers[0];
        recipient = t.to;
        amountPlanck = t.amount;
        amountHuman = `${toHuman(t.amount, decimals)} ${symbol}`;
      }

      const out = {
        index: idx,
        ok: p.ok,
        isSigned: p.isSigned,
        section: p.section,
        method: p.method,
        callIndex: p.callIndex,
        sender: p.sender,
        recipient,
        amountPlanck,
        amountHuman,
        tipPlanck: p.tipPlanck,
        tipHuman: p.tipHuman,
        nonce: p.nonce,
        weight,
        partialFeePlanck,
        partialFeeHuman,
        error: p.error,
      };
      console.log(JSON.stringify(out));
    }
  } catch (e: any) {
    console.error("error:", e?.message ?? e);
    process.exit(1);
  } finally {
    await rpc.close();
  }
})();
