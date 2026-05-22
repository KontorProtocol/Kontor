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

import { spawn, type ChildProcess } from "node:child_process";
import type { Chain } from "./chains.js";

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

/** The dev-account material + endpoints parsed from `kontor regtest`. */
export interface RegtestInfo {
  /** Indexer HTTP API base, e.g. `http://localhost:34197/api`. */
  apiUrl: string;
  /** Bitcoin Core regtest RPC endpoint, `rpc:rpc` credentials embedded. */
  bitcoinRpc: string;
  /** The pre-funded dev account's 32-byte secp256k1 secret, hex. */
  devPrivateKey: string;
  /** The dev account's x-only taproot pubkey, hex. */
  devPublicKey: string;
  /** The dev account's bech32m (p2tr) address. */
  devAddress: string;
}

/** A running `kontor regtest` devnet. */
export interface Regtest extends RegtestInfo {
  /** A `Chain` wired to this devnet — pass straight to `KontorSession`. */
  chain: Chain;
  /** Stop the devnet: SIGTERM the process and wait for a clean exit. */
  stop(): Promise<void>;
}

/** The single stdout line `kontor regtest` prints once the devnet is up. */
const INFO_MARKER = "KONTOR_REGTEST_INFO ";

/** Required string fields of the `KONTOR_REGTEST_INFO` JSON payload. */
const INFO_FIELDS: readonly (keyof RegtestInfo)[] = [
  "apiUrl",
  "bitcoinRpc",
  "devPrivateKey",
  "devPublicKey",
  "devAddress",
];

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
  for (const field of INFO_FIELDS) {
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
  };
}

/**
 * Build a `Chain` for a `kontor regtest` devnet. Exposed for callers who
 * run `kontor regtest` themselves (e.g. a shared devnet) rather than via
 * `startRegtest`.
 */
export function regtestChain(info: Pick<RegtestInfo, "apiUrl" | "bitcoinRpc">): Chain {
  return {
    name: "regtest",
    nativeCurrency: { name: "Kontor", symbol: "KOR", decimals: 18 },
    // `kontor regtest` auto-mines roughly every 10s.
    blockTime: 10_000,
    urls: { http: info.apiUrl, bitcoinRpc: info.bitcoinRpc },
    contracts: { nativeToken: { name: "token", height: 0n, txIndex: 0n } },
    network: { bech32: "bcrt", pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef },
  };
}

/** Resolve the `kontor` binary path: explicit option → `$KONTOR_BIN` → PATH. */
function resolveKontorBin(opt?: string): string {
  return opt ?? process.env.KONTOR_BIN ?? "kontor";
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
 */
export function startRegtest(opts: StartRegtestOptions = {}): Promise<Regtest> {
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
      child.stdout?.removeListener("data", onData);
      child.removeListener("error", onError);
      child.removeListener("exit", onExit);
      if (err != null) {
        child.kill("SIGTERM");
        reject(err);
      } else {
        resolve(regtest!);
      }
    }

    function onData(chunk: Buffer): void {
      stdout += chunk.toString("utf8");
      if (opts.inheritStdio) process.stderr.write(chunk);
      let info: RegtestInfo | null;
      try {
        info = parseRegtestInfo(stdout);
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      if (info == null) return;
      // Keep draining stdout post-ready so the child never blocks on a
      // full pipe; the data is just discarded.
      child.stdout?.removeListener("data", onData);
      child.stdout?.resume();
      finish(null, {
        ...info,
        chain: regtestChain(info),
        stop: () => stopChild(child),
      });
    }

    function onError(err: Error): void {
      finish(new Error(`startRegtest: failed to spawn '${bin}': ${err.message}`));
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
