import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function rejected(action) {
  try {
    action();
  } catch (error) {
    return { name: error.name, message: error.message, payload: error.payload };
  }
  throw new Error("malformed SDK crypto input unexpectedly succeeded");
}

function exercise(sdk) {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const message = new TextEncoder().encode("Kontor protocol crypto compatibility");
  const secret = sdk.blsSecretKeyGen(seed);
  const publicKey = sdk.blsPubkeyFromSecret(secret);
  const signature = sdk.blsSign(secret, message);
  assert.equal(sdk.blsVerify(publicKey, message, signature), true);
  assert.equal(sdk.blsVerify(publicKey, new Uint8Array([1]), signature), false);
  const secondSecret = sdk.blsSecretKeyGen(new Uint8Array(32).fill(7));
  const secondSignature = sdk.blsSign(secondSecret, message);
  return {
    secret: hex(secret),
    publicKey: hex(publicKey),
    signature: hex(signature),
    aggregate: hex(sdk.blsAggregateSignatures([signature, secondSignature])),
    derivedRoot: hex(sdk.blsSecretFromSeedEip2333(seed, [])),
    derivedChild: hex(sdk.blsSecretFromSeedEip2333(seed, [12381, 0, 0, 0])),
    errors: {
      shortSeed: rejected(() => sdk.blsSecretKeyGen(new Uint8Array(31))),
      zeroSecret: rejected(() => sdk.blsPubkeyFromSecret(new Uint8Array(32))),
      invalidPublicKey: rejected(() => sdk.blsVerify(new Uint8Array(96), message, signature)),
      invalidSignature: rejected(() => sdk.blsVerify(publicKey, message, new Uint8Array(48))),
      shortSignature: rejected(() => sdk.blsVerify(publicKey, message, signature.slice(0, 47))),
      emptyAggregate: rejected(() => sdk.blsAggregateSignatures([])),
    },
  };
}

const [baselinePath, candidatePath, reportPath] = process.argv.slice(2);
if (!baselinePath || !candidatePath || !reportPath) {
  throw new Error("usage: node compare-sdk.mjs BASELINE_JS CANDIDATE_JS REPORT_JSON");
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const expected = JSON.parse(await readFile(new URL("./fixtures/sdk-vectors.json", import.meta.url), "utf8"));
const baselineWasm = await readFile(new URL("kontor-sdk.core.wasm", pathToFileURL(resolve(baselinePath))));
assert.equal(sha256(baselineWasm), expected.reference_wasm_sha256, "baseline must be the recorded pristine SDK artifact");
assert.equal(process.version, expected.node, "run with the recorded pinned Node version");
const baseline = exercise(await import(pathToFileURL(resolve(baselinePath)).href));
const candidate = exercise(await import(pathToFileURL(resolve(candidatePath)).href));
assert.deepEqual(baseline, expected.vectors, "baseline must reproduce the recorded crypto vectors");
assert.deepEqual(candidate, baseline, "SDK crypto outputs differ from the committed upstream build");
const report = {
  node: process.version,
  baselineModuleSha256: sha256(await readFile(baselinePath)),
  candidateModuleSha256: sha256(await readFile(candidatePath)),
  baselineWasmSha256: sha256(await readFile(new URL("kontor-sdk.core.wasm", pathToFileURL(resolve(baselinePath))))),
  candidateWasmSha256: sha256(await readFile(new URL("kontor-sdk.core.wasm", pathToFileURL(resolve(candidatePath))))),
  vectorsSha256: sha256(JSON.stringify(baseline)),
  vectors: baseline,
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
console.log("Actual SDK Wasm key generation, derivation, signing, aggregation, verification and error outputs match");
