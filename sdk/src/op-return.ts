/**
 * OP_RETURN payload encoding for the attach/detach reveal.
 *
 * A transaction's OP_RETURN carries one directive per reveal input — on
 * the wire, a postcard-encoded `Vec<OpReturnEntry>`. For a detach the
 * directive is a `recipient`: where the detached asset should land,
 * named by an x-only pubkey (or, on the wire, an existing signer id).
 *
 * Encoding is delegated to `encodeOpReturn`, the WASM helper compiled
 * from the same Rust types — one source of truth for the wire shape.
 */

import { encodeOpReturn, type OpReturnEntry } from "./component/kontor-sdk.js";
import { SignerError } from "./errors.js";

/** One detached op's destination: which input it rode, and to whom. */
export interface RecipientEntry {
  /** The reveal input index carrying this detach op. */
  inputIndex: number;
  /** Recipient taproot x-only public key — 32-byte (64-hex-char) string. */
  recipient: string;
}

/**
 * Encode `entries` as the raw OP_RETURN bytes for a detach reveal.
 *
 * Validation lives in the WASM codec: it rejects a recipient that
 * isn't a well-formed x-only pubkey on the curve. That rejection
 * surfaces here as a `SignerError` rather than a raw wasm trap.
 */
export function encodeRecipientOpReturn(
  entries: readonly RecipientEntry[],
): Uint8Array {
  const witEntries: OpReturnEntry[] = entries.map(
    ({ inputIndex, recipient }) => ({
      inputIndex,
      recipient: { tag: "x-only-pubkey", val: recipient },
    }),
  );
  try {
    return encodeOpReturn(witEntries);
  } catch (cause) {
    throw new SignerError("attach: invalid detach recipient", {
      cause: cause instanceof Error ? cause : undefined,
      details: cause instanceof Error ? undefined : String(cause),
      docsPath: "/sdk/attach",
    });
  }
}
