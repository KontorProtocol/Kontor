import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const sdk = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const directory = mkdtempSync(join(tmpdir(), "kontor-sdk-package-"));
let passed = false;
try {
  const packed = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", directory],
      { cwd: sdk, encoding: "utf8" },
    ),
  );
  const consumer = join(directory, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  execFileSync(
    "npm",
    [
      "install",
      "--prefer-offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      join(directory, packed[0].filename),
    ],
    { cwd: consumer, stdio: "inherit" },
  );
  // Reuse lockfile-installed consumer tooling. Re-resolving Vite's tree here
  // would test today's registry instead of the compiler/peer used by this build.
  for (const name of ["vite", "@types/node"]) {
    const target = join(consumer, "node_modules", name);
    mkdirSync(dirname(target), { recursive: true });
    symlinkSync(join(sdk, "node_modules", name), target, "dir");
  }
  const installed = join(consumer, "node_modules/@kontor/sdk");
  const manifest = JSON.parse(
    readFileSync(join(installed, "package.json"), "utf8"),
  );
  for (const entry of Object.values(manifest.exports)) {
    for (const file of Object.values(entry))
      readFileSync(join(installed, file));
  }
  writeFileSync(
    join(consumer, "index.ts"),
    `
import type { KontorSession, TransactionInfo, ResultInfo, InspectedOp, ChainEvent } from "@kontor/sdk";
import { kontor } from "@kontor/sdk/vite";
import { startRegtest } from "@kontor/sdk/regtest";
import { connect } from "@kontor/sdk/wallets/sats-connect";
const plugin = kontor({ input: "contracts/*.wit", outDir: "generated" });
const regtest = startRegtest;
const wallet = connect;
declare const session: KontorSession;
const transaction: TransactionInfo | null = await session.transaction("txid");
if (transaction) {
  const position: number | null = transaction.confirmed_bitcoin_tx_index;
  // @ts-expect-error unknown confirmation cannot be treated as position zero
  const known: number = transaction.confirmed_bitcoin_tx_index;
}
declare const receipt: ResultInfo;
const height: number | null = receipt.confirmed_height;
declare const inspected: InspectedOp;
if (inspected.kind === "Materialized" && inspected.result) {
  const position: number | null = inspected.result.confirmed_bitcoin_tx_index;
}
declare const event: ChainEvent;
if (event.kind === "tx") {
  const execution: bigint = event.executionHeight;
  const confirmation: bigint | null = event.confirmedHeight;
}
`,
  );
  for (const [module, moduleResolution, customConditions] of [
    ["ESNext", "bundler", []],
    ["Node16", "node16", []],
    ["ESNext", "bundler", ["react-native"]],
  ]) {
    writeFileSync(
      join(consumer, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          strict: true,
          noEmit: true,
          target: "ES2022",
          lib: ["ES2022", "DOM", "ESNext.Disposable"],
          module,
          moduleResolution,
          customConditions,
          skipLibCheck: false,
          types: ["node"],
        },
        files: ["index.ts"],
      }),
    );
    execFileSync(
      join(sdk, "node_modules/.bin/tsc"),
      ["-p", join(consumer, "tsconfig.json")],
      { cwd: consumer, stdio: "inherit" },
    );
    console.log(
      `Consumer types passed: ${moduleResolution} ${customConditions.join(",")}`,
    );
  }
  for (const native of [false, true]) {
    for (const [subpath, entry] of Object.entries(manifest.exports)) {
      const specifier =
        subpath === "." ? "@kontor/sdk" : `@kontor/sdk/${subpath.slice(2)}`;
      const expected = new URL(
        entry[native && entry["react-native"] ? "react-native" : "import"],
        `file://${installed}/`,
      ).href;
      const resolved = execFileSync(
        process.execPath,
        [
          ...(native ? ["--conditions=react-native"] : []),
          "--input-type=module",
          "-e",
          `console.log(import.meta.resolve(${JSON.stringify(specifier)}))`,
        ],
        { cwd: consumer, encoding: "utf8" },
      ).trim();
      if (resolved !== expected)
        throw new Error(
          `${specifier} resolved to ${resolved}, expected ${expected}`,
        );
    }
  }
  passed = true;
  console.log(
    `Packed @kontor/sdk ${manifest.version}: export files and consumer types passed`,
  );
} finally {
  if (passed) rmSync(directory, { recursive: true, force: true });
  else console.error(`Package-check evidence retained at ${directory}`);
}
