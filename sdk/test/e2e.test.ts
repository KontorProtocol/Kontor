/**
 * End-to-end test of the codegen pipeline. Generates the token
 * contract's bindings, writes them to disk, dynamically imports the
 * `Contract` class, and exercises it against a mock transport. This
 * is the only test that catches structural bugs in the round-trip:
 *   canonical class → .toRaw() → WAVE encode → mock chain → WAVE
 *   decode → <Class>.fromRaw(raw) → typed value
 */
import { test, expect, beforeAll } from "vitest";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generate,
  type KontorTransport,
  Decimal,
  HolderRef,
} from "@kontor/sdk";
import tokenWit from "../../native-contracts/token/wit/contract.wit?raw";

const here = path.dirname(fileURLToPath(import.meta.url));
const generatedPath = path.join(here, "__generated__", "token.ts");

let Contract: new (transport: KontorTransport) => any;

beforeAll(async () => {
  const out = generate(tokenWit);
  mkdirSync(path.dirname(generatedPath), { recursive: true });
  writeFileSync(generatedPath, out);
  // Vitest transforms .ts on the fly; the generated file's
  // `import { ... } from "@kontor/sdk"` self-resolves via this
  // package's own exports.
  const mod = (await import(/* @vite-ignore */ generatedPath)) as {
    Contract: new (transport: KontorTransport) => any;
  };
  Contract = mod.Contract;
});

/**
 * Render a Decimal as its WAVE literal. The on-chain encoding is
 * `value * 10^18` packed into four little-endian u64 limbs, so writing
 * raw r0..r3 literals in tests is impractical — build them from a real
 * Decimal instead.
 */
function decimalWave(value: string): string {
  const raw = Decimal.from(value).toRaw();
  return `{r0: ${raw.r0}, r1: ${raw.r1}, r2: ${raw.r2}, r3: ${raw.r3}, sign: ${raw.sign}}`;
}

/**
 * Build a transport that returns a canned WAVE response keyed by the
 * function name the Contract called. Records each WAVE call so tests
 * can assert on the encoded shape.
 */
function mockTransport(
  responses: Record<string, string>,
): KontorTransport & { calls: string[] } {
  const calls: string[] = [];
  const handler = async (wave: string) => {
    calls.push(wave);
    const name = wave.match(/^([a-z][a-z0-9-]*)\(/)?.[1];
    if (name == null) {
      throw new Error(`could not parse function name from: ${wave}`);
    }
    const resp = responses[name];
    if (resp == null) {
      throw new Error(`no canned response for ${name}`);
    }
    return resp;
  };
  return { submit: handler, simulate: handler, calls };
}

test("e2e: balance() encodes HolderRef arg, decodes some(Decimal) result", async () => {
  const t = mockTransport({
    balance: `some(${decimalWave("100")})`,
  });
  const c = new Contract(t);
  const result = await c.balance(HolderRef.xOnlyPubkey("abc"));
  expect(result).toBeInstanceOf(Decimal);
  expect(result.toString()).toBe("100");
  expect(t.calls[0]).toBe('balance(x-only-pubkey("abc"))');
});

test("e2e: balance() decodes none → null", async () => {
  const t = mockTransport({ balance: "none" });
  const c = new Contract(t);
  expect(await c.balance(HolderRef.core())).toBeNull();
});

test("e2e: transfer() round-trips a Decimal arg and a Result<Transfer, Error>", async () => {
  const t = mockTransport({
    transfer: `ok({src: x-only-pubkey("aa"), dst: x-only-pubkey("bb"), amt: ${decimalWave("42")}})`,
  });
  const c = new Contract(t);
  const r = await c.transfer(HolderRef.xOnlyPubkey("bb"), Decimal.from("42"));
  expect(r.kind).toBe("ok");
  expect(r.value.amt).toBeInstanceOf(Decimal);
  expect(r.value.amt.toString()).toBe("42");
  expect(r.value.src.kind).toBe("x-only-pubkey");
  // Sanity-check the WAVE call: contract arg uses x-only-pubkey for dst
  // and the {r0..r3, sign} record for the Decimal amt.
  expect(t.calls[0]).toBe(
    `transfer(x-only-pubkey("bb"), ${decimalWave("42")})`,
  );
});

test("e2e: transfer() decodes err arm of result", async () => {
  const t = mockTransport({
    transfer: 'err(message("not enough funds"))',
  });
  const c = new Contract(t);
  const r = await c.transfer(HolderRef.core(), Decimal.from("0"));
  expect(r.kind).toBe("err");
  expect(r.value.kind).toBe("message");
  expect(r.value.value).toBe("not enough funds");
});

test("e2e: view-context methods dispatch via simulate, proc-context via submit", async () => {
  const zero = decimalWave("0");
  const calls: Array<{ on: "submit" | "simulate"; wave: string }> = [];
  const transport: KontorTransport = {
    submit: async (wave) => {
      calls.push({ on: "submit", wave });
      return `ok({src: core, dst: core, amt: ${zero}})`;
    },
    simulate: async (wave) => {
      calls.push({ on: "simulate", wave });
      return `some(${zero})`;
    },
  };
  const c = new Contract(transport);
  await c.balance(HolderRef.core()); // view-context → simulate
  await c.transfer(HolderRef.core(), Decimal.from("0")); // proc-context → submit
  expect(calls.map((c) => c.on)).toEqual(["simulate", "submit"]);
});

test("e2e: HolderRef.utxo round-trips with bigint vout", async () => {
  const t = mockTransport({
    balance: `some(${decimalWave("0")})`,
  });
  const c = new Contract(t);
  await c.balance(HolderRef.utxo({ txid: "deadbeef", vout: 7n }));
  // u64 vout becomes an unquoted decimal in WAVE.
  expect(t.calls[0]).toBe('balance(utxo({txid: "deadbeef", vout: 7}))');
});
