/**
 * Pre-generate the token contract's TS bindings into
 * `test/__generated__/token.ts` so tests can static-import them. Runs
 * in Node before vitest collects tests, regardless of whether tests
 * will execute in Node or a browser — globalSetup always runs in the
 * test orchestrator's environment.
 */
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generate } from "@kontor/sdk";

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * Generate `test/__generated__/token.ts` from the native token's WIT.
 * Shared by the unit suite's globalSetup and the regtest suite's.
 */
export function generateTokenBindings(): void {
  const tokenWit = readFileSync(
    path.join(here, "..", "native-contracts", "token", "wit", "contract.wit"),
    "utf8",
  );
  const dir = path.join(here, "test", "__generated__");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "token.ts"), generate(tokenWit));
}

/**
 * Generate `test/__generated__/counter.ts` from the test counter's WIT —
 * the publish-round-trip regtest deploys the counter wasm from JS and
 * binds the result.
 */
export function generateCounterBindings(): void {
  const counterWit = readFileSync(
    path.join(here, "..", "test-contracts", "counter", "wit", "contract.wit"),
    "utf8",
  );
  const dir = path.join(here, "test", "__generated__");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "counter.ts"), generate(counterWit));
}

export default async function setup(): Promise<void> {
  generateTokenBindings();
  generateCounterBindings();
}
