/**
 * Pre-generate the token contract's TS bindings into
 * `test/__generated__/token.ts` so the e2e test can static-import
 * them. Runs in Node before vitest collects tests, regardless of
 * whether tests will execute in Node or a browser — globalSetup
 * always runs in the test orchestrator's environment.
 */
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generate } from "@kontor/sdk";

const here = path.dirname(fileURLToPath(import.meta.url));
const tokenWit = readFileSync(
  path.join(here, "..", "native-contracts", "token", "wit", "contract.wit"),
  "utf8",
);

export default async function setup(): Promise<void> {
  const out = generate(tokenWit);
  const dir = path.join(here, "test", "__generated__");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "token.ts"), out);
}
