import { hex as hexCodec } from "@scure/base";
import { expect, test } from "vitest";
import vector from "../../core/indexer/src/protocol/coordinator/control/test-vector.json";

const cat = (...parts: Uint8Array[]) => {
  const bytes = new Uint8Array(
    parts.reduce((size, part) => size + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
};
const text = (value: string) => new TextEncoder().encode(value);
const hex = hexCodec.decode;
const toHex = hexCodec.encode;
const fixed = (value: number) => new Uint8Array(32).fill(value);
const byte = (value: number) => Uint8Array.of(value);
const u64 = (value: bigint) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
};
const u32 = (value: number) => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
};
const u16 = (value: number) => {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value);
  return bytes;
};
const blob = (value: Uint8Array) => cat(u32(value.length), value);
const digest = async (domain: string, value: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", cat(text(domain), byte(0), value)),
  );

// This encoder is independent of the Rust implementation and consumes no Rust
// codec output when constructing the expected manifest, action or state bytes.
function manifest(number: bigint, predecessor: Uint8Array) {
  return cat(
    text("KPM1"),
    fixed(1),
    u64(number),
    predecessor,
    fixed(2),
    fixed(3),
    u16(2),
    u32(1),
    u32(2),
    u16(1),
    u32(1),
    u32(1),
    u32(1),
    u32(1),
    u32(1),
    fixed(4),
    fixed(5),
    fixed(6),
    u32(1),
    u32(1),
  );
}

const current = manifest(1n, fixed(0));
const protocol = await digest("kontor/protocol-manifest/v1", current);
const context = cat(fixed(1), fixed(7), protocol, u32(1));
const target = manifest(2n, protocol);
const action = cat(
  text("KUA1"),
  context,
  fixed(8),
  u64(1n),
  byte(0),
  u64(9n),
  fixed(9),
  u64(244n),
  byte(1),
  blob(target),
  u64(1108n),
);
const actionId = await digest("kontor/upgrade-action/v1", action);
const approvalDigest = await digest(
  "kontor/upgrade-approval/v1",
  cat(text("KAP1"), actionId, hex(vector.approval_key!), fixed(21)),
);
const control = cat(
  text("KUC1"),
  blob(action),
  u32(1),
  hex(vector.approval_key!),
  fixed(21),
  hex(vector.approval_signature!),
);
const controlId = await digest("kontor/upgrade-control/v1", control);

test("JavaScript canonical manifest, action and approval envelope match Rust vectors", () => {
  expect(toHex(action)).toBe(vector.action_hex);
  expect(toHex(actionId)).toBe(vector.action_id);
  expect(toHex(approvalDigest)).toBe(vector.approval_digest);
  expect(toHex(control)).toBe(vector.control_hex);
  expect(toHex(controlId)).toBe(vector.control_id);
});

test("JavaScript empty and pending control states match Rust vectors", () => {
  const prefix = cat(text("KUS1"), context, blob(current));
  expect(toHex(cat(prefix, fixed(8), u64(0n), byte(0)))).toBe(
    vector.state_empty_hex,
  );
  expect(
    toHex(
      cat(
        prefix,
        controlId,
        u64(1n),
        byte(1),
        actionId,
        blob(target),
        u64(1108n),
        byte(0),
      ),
    ),
  ).toBe(vector.state_pending_hex);
});

test("Postpone and Cancel preserve wide integers and optional plan identity across languages", async () => {
  const targetId = await digest("kontor/protocol-manifest/v1", target);
  const prefix = cat(
    text("KUA1"),
    context,
    controlId,
    u64(2n ** 64n - 1n),
    byte(1),
    actionId,
    u64(2n ** 53n + 1n),
    fixed(9),
    u64(2n ** 64n - 2n),
  );
  for (const entry of vector.wide_actions) {
    expect(["postpone", "cancel"]).toContain(entry.kind);
    const encoded = cat(
      prefix,
      entry.kind === "postpone"
        ? cat(byte(2), targetId, u64(1108n), u64(2n ** 64n - 1n))
        : cat(byte(3), targetId, u64(1108n)),
    );
    expect(toHex(encoded)).toBe(entry.action_hex);
    expect(toHex(await digest("kontor/upgrade-action/v1", encoded))).toBe(
      entry.action_id,
    );
  }
});

test("WebCrypto Ed25519 independently verifies the Rust approval and rejects changed bindings", async () => {
  const key = await crypto.subtle.importKey(
    "raw",
    hex(vector.approval_key),
    "Ed25519",
    false,
    ["verify"],
  );
  const signature = hex(vector.approval_signature!);
  expect(
    await crypto.subtle.verify("Ed25519", key, signature, approvalDigest),
  ).toBe(true);
  const changedAction = new Uint8Array(action);
  changedAction[4] ^= 1;
  const changedActionDigest = await digest(
    "kontor/upgrade-action/v1",
    changedAction,
  );
  for (const [id, generation] of [
    [changedActionDigest, fixed(21)],
    [actionId, fixed(22)],
  ]) {
    const changed = await digest(
      "kontor/upgrade-approval/v1",
      cat(text("KAP1"), id!, hex(vector.approval_key!), generation!),
    );
    expect(await crypto.subtle.verify("Ed25519", key, signature, changed)).toBe(
      false,
    );
  }
});
