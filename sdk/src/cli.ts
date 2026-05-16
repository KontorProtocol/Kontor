/**
 * `kontor-codegen` — emit a TypeScript binding from a Kontor contract
 * WIT. Same codegen the Vite plugin uses; this is the standalone
 * fallback for non-Vite build pipelines, CI checks, and one-off runs.
 *
 *     kontor-codegen contracts/token.wit -o src/generated/token.ts
 *     kontor-codegen contracts/token.wit -o src/generated/token.ts --watch
 */
import { readFileSync, writeFileSync, mkdirSync, watch } from "node:fs";
import path from "node:path";
import { generate } from "./codegen";

const HELP = `\
usage: kontor-codegen <input.wit> -o <output.ts> [--watch]

  -o, --output  Path to the generated TS file
  -w, --watch   Regenerate when the input changes
  -h, --help    Show this help
`;

function fail(msg: string): never {
  process.stderr.write(msg + "\n");
  process.exit(1);
}

const argv = process.argv.slice(2);
let input: string | null = null;
let output: string | null = null;
let watchMode = false;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "-o" || a === "--output") {
    output = argv[++i] ?? null;
  } else if (a === "-w" || a === "--watch") {
    watchMode = true;
  } else if (a === "-h" || a === "--help") {
    process.stdout.write(HELP);
    process.exit(0);
  } else if (!a.startsWith("-")) {
    input = a;
  } else {
    fail(`unknown flag: ${a}\n${HELP}`);
  }
}

if (input == null || output == null) fail(HELP);

const inputPath = path.resolve(input);
const outputPath = path.resolve(output);

function run(): void {
  const text = readFileSync(inputPath, "utf8");
  const out = generate(text);
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, out);
  process.stdout.write(`generated ${outputPath} from ${inputPath}\n`);
}

try {
  run();
} catch (e) {
  fail(`codegen failed: ${(e as Error).message}`);
}

if (watchMode) {
  watch(inputPath, () => {
    try {
      run();
    } catch (e) {
      process.stderr.write(`codegen failed: ${(e as Error).message}\n`);
    }
  });
  process.stdout.write(`watching ${inputPath}...\n`);
}
