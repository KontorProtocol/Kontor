/**
 * Unit tests for `encodeRecipientOpReturn` — the detach reveal's
 * OP_RETURN payload. Encoding is delegated to the Rust-compiled WASM
 * codec, so the test round-trips through `decodeOpReturn`: the
 * per-input recipient entries that go in must come back out.
 */
import { test, expect } from "vitest";
import { decodeOpReturn } from "@kontor/sdk";
import { encodeRecipientOpReturn } from "../src/op-return.js";

// secp256k1's generator point x-coordinate — a guaranteed-valid x-only
// pubkey (`SignerRef` deserialization validates the curve point).
const PUBKEY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/** The decoded WIT form of an `x-only-pubkey` recipient at `inputIndex`. */
const recipientEntry = (inputIndex: number) => ({
  inputIndex,
  recipient: { tag: "x-only-pubkey", val: PUBKEY },
});

test("encodeRecipientOpReturn: a single recipient round-trips", () => {
  const bytes = encodeRecipientOpReturn([{ inputIndex: 0, recipient: PUBKEY }]);
  expect(decodeOpReturn(bytes)).toStrictEqual([recipientEntry(0)]);
});

test("encodeRecipientOpReturn: multiple recipients keep their input indices", () => {
  const bytes = encodeRecipientOpReturn([
    { inputIndex: 0, recipient: PUBKEY },
    { inputIndex: 2, recipient: PUBKEY },
  ]);
  expect(decodeOpReturn(bytes)).toStrictEqual([
    recipientEntry(0),
    recipientEntry(2),
  ]);
});

test("encodeRecipientOpReturn: an empty list encodes to an empty payload", () => {
  expect(decodeOpReturn(encodeRecipientOpReturn([]))).toStrictEqual([]);
});

test("encodeRecipientOpReturn: a malformed pubkey is rejected by the WASM codec", () => {
  // The codec validates the x-only pubkey; the wasm `err` arm surfaces
  // as a SignerError instead of trapping.
  expect(() =>
    encodeRecipientOpReturn([{ inputIndex: 0, recipient: "deadbeef" }]),
  ).toThrow(/invalid detach recipient/);
});
