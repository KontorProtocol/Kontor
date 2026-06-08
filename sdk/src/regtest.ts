/**
 * `@kontor/sdk/regtest` — Node-only local devnet helper.
 *
 * `startRegtest()` spawns the `kontor regtest` subcommand — which owns all
 * network bringup (bitcoind, a single validator node, an auto-miner, and a
 * pre-funded deterministic dev account) — waits for it to print its
 * `KONTOR_REGTEST_INFO` readiness line, and hands back a `Regtest` for
 * talking to and tearing down the devnet.
 *
 *     import { startRegtest } from "@kontor/sdk/regtest";
 *     import { KontorSession } from "@kontor/sdk";
 *
 *     const devnet = await startRegtest();
 *     const session = new KontorSession({ chain: devnet.chain, account });
 *     // ...
 *     await devnet.stop();
 *
 * This module imports `node:child_process`; it is a separate package entry
 * precisely so it never reaches the browser bundle. The genesis/keys/mining
 * logic lives in the Rust binary — this is pure process management.
 */

import type { ChildProcess } from "node:child_process";
import { hex } from "@scure/base";
import { Transaction, p2tr } from "@scure/btc-signer";
import { regtestChain, type Chain } from "./chains.js";
import type { Utxo } from "./json-codec.js";
import { LocalKey } from "./local-key.js";
import type { Signing } from "./signing.js";

// `regtestChain` is a pure, browser-safe chain builder — it lives in
// `chains.ts` next to `signet`. Re-exported here so `@kontor/sdk/regtest`
// consumers still find it alongside `startRegtest`.
export { regtestChain };

export interface StartRegtestOptions {
  /**
   * Path to the `kontor` binary. Defaults to `$KONTOR_BIN`, falling back
   * to `kontor` (resolved via `PATH`). In-repo callers should point this
   * at `core/target/release/kontor`.
   */
  kontorBin?: string;
  /**
   * How long to wait for the devnet to report ready before giving up.
   * Bringup mines 100+ regtest blocks and starts a node, so this is
   * generous by default. Milliseconds; default 240_000.
   */
  timeoutMs?: number;
  /**
   * Forward the devnet's logs to this process's stderr. Off by default to
   * keep test output clean; turn on when debugging a bringup failure.
   */
  inheritStdio?: boolean;
}

/**
 * A pre-created identity from `kontor regtest`'s identity pool — its own
 * secp256k1 keypair, a P2TR address, one funded UTXO (1M sats), and a
 * fresh chunk of native tokens already issued by the binary. Tests claim
 * one identity per slot, fully isolated from each other.
 */
export interface RegtestIdentity {
  /** 32-byte secp256k1 private key, hex. */
  privateKey: string;
  /** x-only taproot pubkey, hex. */
  publicKey: string;
  /** bech32m (P2TR) address. */
  address: string;
  /** The identity's single funded UTXO — pass to `submit` as bootstrap. */
  fundingUtxo: Utxo;
}

/** The dev-account material + endpoints parsed from `kontor regtest`. */
export interface RegtestInfo {
  /** Indexer HTTP API base, e.g. `http://localhost:34197/api`. */
  apiUrl: string;
  /** Bitcoin Core regtest RPC endpoint, `rpc:rpc` credentials embedded. */
  bitcoinRpc: string;
  /** The pre-funded dev (admin) account's 32-byte secp256k1 secret, hex. */
  devPrivateKey: string;
  /** The dev account's x-only taproot pubkey, hex. */
  devPublicKey: string;
  /** The dev account's bech32m (P2TR) address. */
  devAddress: string;
  /**
   * Pre-created identity pool. Each is independently keyed, funded with
   * 1M sats (one UTXO), and pre-issued native tokens — ready to call
   * gas-paying ops or transfer/sell without any further setup. SDK
   * tests claim a slot by index (`identities[0]`, `identities[1]`, …).
   */
  identities: RegtestIdentity[];
}

/**
 * One pre-created identity, ready for a test slot — the `RegtestIdentity`
 * material lifted into runnable form (`LocalKey` + `fundingUtxo` to
 * pass straight to `http({ utxos: [fundingUtxo] })`).
 */
export interface RegtestAccount {
  /** Same as the matching `RegtestIdentity.privateKey`. */
  privateKey: string;
  /** A `LocalKey` (a `Signing`) derived from `privateKey`, ready to sign. */
  signing: LocalKey;
  /** The identity's single 1M-sat funding UTXO. */
  fundingUtxo: Utxo;
}

/**
 * Devnet client-side view: the connection info plus ready-made helpers
 * (`devAccount`, `accounts`, `fundAddress`, `createAccount`). Available
 * both to the process that owns the devnet (via `startRegtest`) and to
 * test workers that didn't spawn it (via `connectRegtest(info)`).
 *
 * Does NOT include `stop()` — only the spawning process can kill the
 * child.
 */
export interface RegtestClient extends RegtestInfo {
  /** A `Chain` wired to this devnet — pass straight to `KontorSession`. */
  chain: Chain;
  /** The dev (admin) account as a ready-to-sign `LocalKey`. */
  devAccount: LocalKey;
  /**
   * Pre-created identity pool lifted into runnable form. Each slot
   * carries its own `LocalKey` + funding UTXO; tests claim a slot
   * by index. Indices match `RegtestInfo.identities[i]`.
   */
  accounts: RegtestAccount[];
  /**
   * Send `sats` from `sourceAccount` (default: the dev account) to
   * `destAddress`. Builds a one-in/two-out P2TR key-path tx, signs it,
   * and broadcasts via the devnet's bitcoind RPC. Returns the new UTXO
   * at output 0; the change at output 1 stays with `sourceAccount`.
   *
   * Does NOT mine — `KontorSession.submit` happily spends mempool UTXOs
   * (CPFP). Throws if the source can't cover `sats + feeSats`.
   */
  fundAddress(opts: FundAddressOptions): Promise<Utxo>;
  /**
   * Mint a fresh `LocalKey` with random keys and fund it with
   * `sats` from `sourceUtxo`. One-line equivalent of: generate key →
   * build LocalKey → call `fundAddress`. Most tests can use a
   * pre-created `accounts[i]` instead; this remains for ad-hoc cases
   * where extra accounts are needed beyond the pool.
   */
  createAccount(opts: CreateAccountOptions): Promise<{
    signing: LocalKey;
    fundingUtxo: Utxo;
  }>;
  /**
   * Mine `count` blocks (default 1) to the dev address, immediately
   * advancing the chain. Returns the new block hashes.
   *
   * Most ops don't need this — the devnet's auto-miner ticks every
   * 10s, and the reactor batches `Call`/`Issuance`/`Sponsor`/
   * `RegisterBlsKey` between blocks. `Publish` is the exception: a
   * contract's address is `name@<height>_<tx_index>`, so the result
   * row can't materialize until the publish tx lands in a block.
   * Call `mine()` right after a Publish to drop the up-to-10s tail.
   */
  mine(count?: number): Promise<string[]>;
}

/**
 * A running `kontor regtest` devnet — `RegtestClient` plus the
 * process-owning `stop()`. Returned only by `startRegtest()`.
 */
export interface Regtest extends RegtestClient {
  /** Stop the devnet: SIGTERM the process and wait for a clean exit. */
  stop(): Promise<void>;
}

export interface FundAddressOptions {
  /** Destination P2TR address (bech32m). */
  destAddress: string;
  /** Destination's x-only taproot pubkey, hex. */
  destXOnlyPubKey: string;
  /** Amount to send. */
  sats: bigint;
  /** UTXO to spend. Typically `regtest.devFundingUtxos[i]`. */
  sourceUtxo: Utxo;
  /**
   * Account that owns `sourceUtxo` and signs the spend. Defaults to
   * the dev account.
   */
  sourceAccount?: Signing;
  /** Flat fee in sats. Default: 500. */
  feeSats?: bigint;
}

export interface CreateAccountOptions {
  /** How many sats to fund the new account with. */
  sats: bigint;
  /** UTXO to spend. Typically `regtest.devFundingUtxos[i]`. */
  sourceUtxo: Utxo;
  /**
   * Account that owns `sourceUtxo` and signs the funding spend.
   * Defaults to the dev account.
   */
  sourceAccount?: Signing;
  /** Flat fee in sats. Default: 500. */
  feeSats?: bigint;
}

/** The single stdout line `kontor regtest` prints once the devnet is up. */
const INFO_MARKER = "KONTOR_REGTEST_INFO ";

/** The string-valued fields of the `KONTOR_REGTEST_INFO` JSON payload. */
const INFO_STRING_FIELDS = [
  "apiUrl",
  "bitcoinRpc",
  "devPrivateKey",
  "devPublicKey",
  "devAddress",
] as const;

/**
 * Scan accumulated `kontor regtest` stdout for the readiness line.
 *
 * The binary prints exactly one `KONTOR_REGTEST_INFO {json}` line once the
 * devnet is fully up; everything else on the stream is node/bitcoind log
 * noise and is ignored. Returns the parsed `RegtestInfo` once that line has
 * appeared in full, otherwise `null`.
 *
 * Throws if the line is present but its JSON is malformed or missing a
 * field — that's a binary/SDK contract violation, not a "keep waiting".
 *
 * Exported for unit testing — `startRegtest` is the real entry point.
 */
export function parseRegtestInfo(stdout: string): RegtestInfo | null {
  // Only scan newline-terminated lines: the trailing segment of this
  // accumulating buffer may be the info line still streaming in, and a
  // half-arrived line would parse as truncated JSON.
  const lastNewline = stdout.lastIndexOf("\n");
  if (lastNewline < 0) return null;
  for (const line of stdout.slice(0, lastNewline).split("\n")) {
    if (line.startsWith(INFO_MARKER)) {
      return parseInfoPayload(line.slice(INFO_MARKER.length).trim());
    }
  }
  return null;
}

/** Parse + validate the JSON payload of a `KONTOR_REGTEST_INFO` line. */
function parseInfoPayload(json: string): RegtestInfo {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new Error(
      `KONTOR_REGTEST_INFO payload is not valid JSON: ${(e as Error).message}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("KONTOR_REGTEST_INFO payload is not a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  for (const field of INFO_STRING_FIELDS) {
    if (typeof obj[field] !== "string") {
      throw new Error(
        `KONTOR_REGTEST_INFO payload is missing string field '${field}'`,
      );
    }
  }
  return {
    apiUrl: obj.apiUrl as string,
    bitcoinRpc: obj.bitcoinRpc as string,
    devPrivateKey: obj.devPrivateKey as string,
    devPublicKey: obj.devPublicKey as string,
    devAddress: obj.devAddress as string,
    identities: parseIdentities(obj.identities),
  };
}

/** Parse + validate the `identities` array. */
function parseIdentities(raw: unknown): RegtestIdentity[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(
      "KONTOR_REGTEST_INFO: identities missing, not an array, or empty",
    );
  }
  return raw.map(parseIdentity);
}

/** Parse + validate one identity object. */
function parseIdentity(raw: unknown): RegtestIdentity {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("KONTOR_REGTEST_INFO: identity missing or not an object");
  }
  const i = raw as Record<string, unknown>;
  if (
    typeof i.privateKey !== "string" ||
    typeof i.publicKey !== "string" ||
    typeof i.address !== "string"
  ) {
    throw new Error(
      "KONTOR_REGTEST_INFO: identity has missing or mistyped fields",
    );
  }
  return {
    privateKey: i.privateKey,
    publicKey: i.publicKey,
    address: i.address,
    fundingUtxo: parseFundingUtxo(i.fundingUtxo),
  };
}

/** Parse + validate one funding-UTXO object into a `Utxo`. */
function parseFundingUtxo(raw: unknown): Utxo {
  if (typeof raw !== "object" || raw === null) {
    throw new Error(
      "KONTOR_REGTEST_INFO: fundingUtxo missing or not an object",
    );
  }
  const u = raw as Record<string, unknown>;
  if (
    typeof u.txid !== "string" ||
    typeof u.vout !== "number" ||
    typeof u.value !== "number" ||
    typeof u.scriptPubKey !== "string"
  ) {
    throw new Error(
      "KONTOR_REGTEST_INFO: fundingUtxo has missing or mistyped fields",
    );
  }
  // `value` arrives as a JSON number of satoshis; `Utxo.value` is bigint.
  return {
    txid: u.txid,
    vout: u.vout,
    value: BigInt(u.value),
    scriptPubKey: u.scriptPubKey,
  };
}

/** Resolve the `kontor` binary path: explicit option → `$KONTOR_BIN` → PATH. */
function resolveKontorBin(opt?: string): string {
  return opt ?? process.env.KONTOR_BIN ?? "kontor";
}

/** Minimal Bitcoin Core JSON-RPC POST helper for the regtest devnet. */
async function bitcoinRpc(
  url: string,
  method: string,
  params: unknown[],
): Promise<unknown> {
  const parsed = new URL(url);
  // Auth lives in the URL (rpc:rpc@host:port); strip it for the body URL.
  const auth =
    parsed.username !== ""
      ? btoa(`${parsed.username}:${parsed.password}`)
      : null;
  const cleanUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  const res = await fetch(cleanUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(auth != null ? { authorization: `Basic ${auth}` } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "1.0",
      id: "kontor-regtest",
      method,
      params,
    }),
  });
  const json = (await res.json()) as { result?: unknown; error?: unknown };
  if (json.error != null) {
    throw new Error(`bitcoinRpc ${method}: ${JSON.stringify(json.error)}`);
  }
  return json.result;
}

/**
 * Build, sign, and broadcast a one-in/two-out P2TR key-path send.
 * Shared body of `fundAddress`; broken out so `createAccount` can call
 * the same path without re-marshalling.
 */
async function performFundAddress(
  bitcoinRpcUrl: string,
  chain: Chain,
  defaultSigning: Signing,
  opts: FundAddressOptions,
): Promise<Utxo> {
  const feeSats = opts.feeSats ?? 500n;
  const change = opts.sourceUtxo.value - opts.sats - feeSats;
  if (change < 0n) {
    throw new Error(
      `fundAddress: source ${opts.sourceUtxo.value} cannot cover ${opts.sats}+${feeSats}`,
    );
  }
  const source = opts.sourceAccount ?? defaultSigning;
  const sourceXOnly = hex.decode(source.identity.xOnlyPubKey);
  const destScript = p2tr(
    hex.decode(opts.destXOnlyPubKey),
    undefined,
    chain.network,
  ).script;
  const changeScript = p2tr(sourceXOnly, undefined, chain.network).script;

  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({
    txid: opts.sourceUtxo.txid,
    index: opts.sourceUtxo.vout,
    witnessUtxo: {
      script: hex.decode(opts.sourceUtxo.scriptPubKey),
      amount: opts.sourceUtxo.value,
    },
    tapInternalKey: sourceXOnly,
  });
  tx.addOutput({ script: destScript, amount: opts.sats });
  tx.addOutput({ script: changeScript, amount: change });

  const signed = await source.psbt(tx.toPSBT());
  const final = Transaction.fromPSBT(signed);
  const sig = final.getInput(0).tapKeySig;
  if (sig == null) throw new Error("fundAddress: source input not signed");
  final.updateInput(0, { finalScriptWitness: [sig] });
  const rawHex = hex.encode(final.extract());
  const txid = (await bitcoinRpc(bitcoinRpcUrl, "sendrawtransaction", [
    rawHex,
  ])) as string;

  return {
    txid,
    vout: 0,
    value: opts.sats,
    scriptPubKey: hex.encode(destScript),
  };
}

/** Generate a random 32-byte private key as lowercase hex. */
function randomPrivateKey(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return hex.encode(bytes);
}

/**
 * Wire shape of `RegtestInfo` that crosses vitest's `provide()`/
 * `inject()` boundary or any other structured-clone-via-string path.
 * UTXO `value` is `bigint | string | number` because bigints survive
 * structured clone in Node but historically were stringified to
 * keep the payload browser-worker-safe.
 */
export interface ProvidedRegtestInfo {
  apiUrl: string;
  bitcoinRpc: string;
  devPrivateKey: string;
  devPublicKey: string;
  devAddress: string;
  identities: Array<{
    privateKey: string;
    publicKey: string;
    address: string;
    fundingUtxo: {
      txid: string;
      vout: number;
      value: bigint | string | number;
      scriptPubKey: string;
    };
  }>;
}

/**
 * Build the client-side `RegtestClient` view (chain + devAccount +
 * fundAddress + createAccount) from a serialized `RegtestInfo`. The
 * counterpart to `startRegtest()` for test workers that didn't spawn
 * the devnet themselves — vitest's `provide()`/`inject()` only carries
 * serializable data, so the helpers can't ride on the `Regtest` object
 * through that boundary. Tests call `connectRegtest(inject("regtest"))`
 * to recover them.
 *
 * Accepts the wide `ProvidedRegtestInfo` shape so callers don't have
 * to pre-`BigInt()` their UTXO values themselves.
 */
export function connectRegtest(info: ProvidedRegtestInfo): RegtestClient {
  const normalizedInfo: RegtestInfo = {
    ...info,
    identities: info.identities.map((id) => ({
      privateKey: id.privateKey,
      publicKey: id.publicKey,
      address: id.address,
      fundingUtxo: {
        txid: id.fundingUtxo.txid,
        vout: id.fundingUtxo.vout,
        value:
          typeof id.fundingUtxo.value === "bigint"
            ? id.fundingUtxo.value
            : BigInt(id.fundingUtxo.value),
        scriptPubKey: id.fundingUtxo.scriptPubKey,
      },
    })),
  };
  const chain = regtestChain(normalizedInfo);
  const devAccount = LocalKey.fromPrivateKey({
    privateKey: normalizedInfo.devPrivateKey,
    chain,
  });
  const accounts: RegtestAccount[] = normalizedInfo.identities.map((id) => ({
    privateKey: id.privateKey,
    signing: LocalKey.fromPrivateKey({ privateKey: id.privateKey, chain }),
    fundingUtxo: id.fundingUtxo,
  }));
  const fundAddress = (opts: FundAddressOptions): Promise<Utxo> =>
    performFundAddress(normalizedInfo.bitcoinRpc, chain, devAccount, opts);
  const mine = async (count: number = 1): Promise<string[]> =>
    (await bitcoinRpc(normalizedInfo.bitcoinRpc, "generatetoaddress", [
      count,
      normalizedInfo.devAddress,
    ])) as string[];
  const createAccount = async (
    opts: CreateAccountOptions,
  ): Promise<{ signing: LocalKey; fundingUtxo: Utxo }> => {
    const signing = LocalKey.fromPrivateKey({
      privateKey: randomPrivateKey(),
      chain,
    });
    const fundingUtxo = await fundAddress({
      destAddress: signing.identity.address,
      destXOnlyPubKey: signing.identity.xOnlyPubKey,
      sats: opts.sats,
      sourceUtxo: opts.sourceUtxo,
      sourceAccount: opts.sourceAccount,
      feeSats: opts.feeSats,
    });
    return { signing, fundingUtxo };
  };
  return {
    ...normalizedInfo,
    chain,
    devAccount,
    accounts,
    fundAddress,
    createAccount,
    mine,
  };
}

/** SIGTERM the child, escalating to SIGKILL if it doesn't exit promptly. */
function stopChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    const sigkill = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.once("exit", () => {
      clearTimeout(sigkill);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

/**
 * Spawn `kontor regtest` and resolve once the devnet is up. Rejects if the
 * process exits before reporting ready, or if `timeoutMs` elapses first —
 * in both cases the child is killed so nothing is left running.
 *
 * `node:child_process` is imported dynamically, not at the top of the
 * module: that keeps `regtest.ts` loadable in a browser (its pure helpers
 * — `parseRegtestInfo`, `regtestChain` — stay importable anywhere).
 * Calling `startRegtest` itself is Node-only, by nature.
 */
export async function startRegtest(
  opts: StartRegtestOptions = {},
): Promise<Regtest> {
  const { spawn } = await import("node:child_process");
  const bin = resolveKontorBin(opts.kontorBin);
  const timeoutMs = opts.timeoutMs ?? 240_000;

  return new Promise<Regtest>((resolve, reject) => {
    const child = spawn(bin, ["regtest"], {
      stdio: ["ignore", "pipe", opts.inheritStdio ? "inherit" : "ignore"],
    });

    let settled = false;
    let stdout = "";

    const timer = setTimeout(() => {
      finish(
        new Error(
          `startRegtest: devnet not ready within ${timeoutMs}ms — ` +
            `is '${bin}' a working kontor binary?`,
        ),
      );
    }, timeoutMs);

    /** Resolve or reject exactly once, cleaning up listeners + the child. */
    function finish(err: Error | null, regtest?: Regtest): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener("error", onError);
      child.removeListener("exit", onExit);
      // `onData` stays attached — it keeps draining stdout (so the child
      // never blocks on a full pipe) and, with `inheritStdio`, keeps
      // forwarding the devnet's logs past the readiness line.
      if (err != null) {
        child.kill("SIGTERM");
        reject(err);
      } else {
        resolve(regtest!);
      }
    }

    function onData(chunk: Buffer): void {
      if (opts.inheritStdio) process.stderr.write(chunk);
      // Post-ready: just drain (forwarded above); nothing left to parse.
      if (settled) return;
      stdout += chunk.toString("utf8");
      let info: RegtestInfo | null;
      try {
        info = parseRegtestInfo(stdout);
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      if (info == null) return;
      finish(null, {
        ...connectRegtest(info),
        stop: () => stopChild(child),
      });
    }

    function onError(err: Error): void {
      finish(
        new Error(`startRegtest: failed to spawn '${bin}': ${err.message}`),
      );
    }

    function onExit(code: number | null, signal: NodeJS.Signals | null): void {
      finish(
        new Error(
          `startRegtest: '${bin} regtest' exited (code=${code}, signal=${signal}) ` +
            `before the devnet was ready`,
        ),
      );
    }

    child.stdout!.on("data", onData);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}
