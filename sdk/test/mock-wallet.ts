/**
 * A headless test "wallet": a sats-connect-style `request(method, params)`
 * function backed by a real `LocalAccount`, so it produces genuine
 * signatures (PSBTs come out valid and finalizable) without a browser, an
 * extension, or user prompts. The linchpin fixture for the tier-1 tests;
 * a browser test can also register it under `window.btc_providers`.
 */
import { base64 } from "@scure/base";
import { SigHash } from "@scure/btc-signer";
import type { LocalKey } from "../src/local-key.js";
import type { SighashKind } from "../src/signing.js";
import type {
  WalletRequest,
  WalletRpcResponse,
} from "../src/wallets/sats-connect.js";

export interface MockWalletOptions {
  /** `addressType` the mock reports for its address (default `"p2tr"`). */
  addressType?: string;
  /** Public-key form the mock returns: x-only (default) or 33-byte compressed. */
  pubkeyForm?: "x-only" | "compressed";
}

/** Build a `WalletRequest` that signs with `account`. */
export function mockWalletRequest(
  signing: LocalKey,
  opts?: MockWalletOptions,
): WalletRequest {
  return async (method, params): Promise<WalletRpcResponse> => {
    switch (method) {
      case "getAccounts":
      case "getAddresses": {
        // A fake `02` prefix is fine — `normalizeXOnly` only strips a byte.
        const publicKey =
          opts?.pubkeyForm === "compressed"
            ? `02${signing.identity.xOnlyPubKey}`
            : signing.identity.xOnlyPubKey;
        return {
          status: "success",
          result: [
            {
              address: signing.identity.address,
              publicKey,
              addressType: opts?.addressType ?? "p2tr",
              purpose: "payment",
            },
          ],
        };
      }

      case "signMessage": {
        // LocalAccount's BIP-322 signMessage isn't implemented; return a
        // deterministic placeholder so the request path stays testable.
        return {
          status: "success",
          result: {
            signature: base64.encode(new TextEncoder().encode("mock-sig")),
          },
        };
      }

      case "signPsbt": {
        const p = params as {
          psbt: string;
          signInputs: Record<string, number[]>;
          allowedSignHash?: number;
        };
        const indexes = p.signInputs[signing.identity.address] ?? [];
        const sighash = allowedSignHashToKind(p.allowedSignHash);
        const signed = await signing.psbt(base64.decode(p.psbt), {
          inputs: indexes.map((index) => ({ index, sighash })),
        });
        return { status: "success", result: { psbt: base64.encode(signed) } };
      }

      default:
        return {
          status: "error",
          error: { message: `mock wallet: unhandled method "${method}"` },
        };
    }
  };
}

function allowedSignHashToKind(n: number | undefined): SighashKind {
  if (n == null) return "default";
  if (n === SigHash.ALL) return "all";
  if (n === SigHash.SINGLE_ANYONECANPAY) return "single-anyonecanpay";
  throw new Error(`mock wallet: unsupported allowedSignHash ${n}`);
}
