/**
 * kontor-codegen — emit TypeScript bindings (types + Contract class) from
 * a Kontor contract WIT.
 *
 * Generated output:
 *   - `export type ...` for every reachable user-defined type
 *   - `function _encode<Name>(...)` / `function _decode<Name>(...)`
 *     helpers for every reachable compound type — these handle the
 *     bigint round-trip (u64/s64 as decimal strings) and the
 *     camelCase ↔ kebab-case record field name mapping
 *   - `export class Contract` with constructor `(transport)` and one
 *     method per export, dispatching through transport.simulate/submit
 *     based on the ctx borrow target
 *
 * Generated files are self-contained: no runtime walker dependency,
 * just `@kontor/sdk` for the WAVE codec (Wit) and the
 * KontorTransport interface.
 */
import { witCodec } from "./component/kontor-sdk";

type TypeRef = string | number;

interface TypeDef {
  name: string | null;
  kind: unknown;
  owner: { interface: number } | { world: number } | null;
}

interface World {
  name: string;
  exports: Record<string, WorldItem>;
  imports: Record<string, WorldItem>;
}

type WorldItem =
  | { function: WitFunction }
  | { interface: { id: number } }
  | { type: number };

interface WitFunction {
  name: string;
  params: Array<{ name: string; type: TypeRef }>;
  result: TypeRef | null;
}

interface Resolve {
  worlds: World[];
  interfaces: Array<{ name: string; types: Record<string, number> }>;
  types: TypeDef[];
}

function primitiveToTs(name: string): string {
  switch (name) {
    case "bool":
      return "boolean";
    case "s8":
    case "s16":
    case "s32":
    case "u8":
    case "u16":
    case "u32":
    case "f32":
    case "f64":
      return "number";
    case "u64":
    case "s64":
      return "bigint";
    case "char":
    case "string":
      return "string";
    default:
      return "unknown";
  }
}

function isBigintPrim(name: string): boolean {
  return name === "u64" || name === "s64";
}

function toCamel(s: string): string {
  return s.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
}

function toPascal(s: string): string {
  const c = toCamel(s);
  return c.charAt(0).toUpperCase() + c.slice(1);
}

/** Follow `use` aliases to the underlying TypeDef. */
function resolveAlias(id: number, resolve: Resolve): number {
  const def = resolve.types[id];
  const k = def.kind as any;
  if (typeof k === "object" && "type" in k && typeof k.type === "number") {
    return resolveAlias(k.type, resolve);
  }
  return id;
}

/** Stable helper-function suffix for a given type id. */
function helperSuffix(id: number, resolve: Resolve): string {
  const def = resolve.types[id];
  if (def.name != null) return toPascal(def.name);
  return `T${id}`;
}

function tsNameForType(id: number, resolve: Resolve): string | null {
  const def = resolve.types[id];
  if (def.name == null) return null;
  return toPascal(def.name);
}

function typeRefToTs(ref: TypeRef, resolve: Resolve): string {
  if (typeof ref === "string") return primitiveToTs(ref);
  const id = resolveAlias(ref, resolve);
  const def = resolve.types[id];
  const name = tsNameForType(id, resolve);
  if (name != null) return name;
  return typeDefBodyToTs(def, resolve);
}

function typeDefBodyToTs(def: TypeDef, resolve: Resolve): string {
  if (def.kind === "resource") return "unknown";
  const k = def.kind as any;
  if ("type" in k) return typeRefToTs(k.type, resolve);
  if ("list" in k) return `Array<${typeRefToTs(k.list, resolve)}>`;
  if ("option" in k) return `${typeRefToTs(k.option, resolve)} | null`;
  if ("result" in k) {
    const okArm =
      k.result.ok != null
        ? `{ kind: "ok"; value: ${typeRefToTs(k.result.ok, resolve)} }`
        : `{ kind: "ok" }`;
    const errArm =
      k.result.err != null
        ? `{ kind: "err"; value: ${typeRefToTs(k.result.err, resolve)} }`
        : `{ kind: "err" }`;
    return `${okArm} | ${errArm}`;
  }
  if ("record" in k) {
    const fields = k.record.fields
      .map(
        (f: any) =>
          `  ${toCamel(f.name)}: ${typeRefToTs(f.type, resolve)};`,
      )
      .join("\n");
    return `{\n${fields}\n}`;
  }
  if ("variant" in k) {
    const arms = k.variant.cases.map((c: any) =>
      c.type == null
        ? `{ kind: "${c.name}" }`
        : `{ kind: "${c.name}"; value: ${typeRefToTs(c.type, resolve)} }`,
    );
    return arms.join(" | ");
  }
  if ("enum" in k) {
    return k.enum.cases.map((c: any) => `"${c.name}"`).join(" | ");
  }
  if ("tuple" in k) {
    return `[${k.tuple.types
      .map((t: TypeRef) => typeRefToTs(t, resolve))
      .join(", ")}]`;
  }
  if ("flags" in k) {
    const names = k.flags.flags
      .map((f: any) => `"${f.name}"`)
      .join(" | ");
    return `Array<${names}>`;
  }
  return "unknown";
}

/** Recursively collect all compound type ids reachable from `ref`. */
function collectIds(
  ref: TypeRef,
  resolve: Resolve,
  seen: Set<number>,
): void {
  if (typeof ref === "string") return;
  const id = resolveAlias(ref, resolve);
  if (seen.has(id)) return;
  seen.add(id);
  const def = resolve.types[id];
  if (def.kind === "resource") return;
  const k = def.kind as any;
  if ("type" in k) collectIds(k.type, resolve, seen);
  else if ("list" in k) collectIds(k.list, resolve, seen);
  else if ("option" in k) collectIds(k.option, resolve, seen);
  else if ("result" in k) {
    if (k.result.ok != null) collectIds(k.result.ok, resolve, seen);
    if (k.result.err != null) collectIds(k.result.err, resolve, seen);
  } else if ("record" in k) {
    for (const f of k.record.fields) collectIds(f.type, resolve, seen);
  } else if ("variant" in k) {
    for (const c of k.variant.cases) {
      if (c.type != null) collectIds(c.type, resolve, seen);
    }
  } else if ("tuple" in k) {
    for (const t of k.tuple.types) collectIds(t, resolve, seen);
  }
}

/**
 * Emit a TS expression that encodes `expr` (a value of the WIT type `ref`)
 * to its wire JSON shape. Primitives are inline; compound types call their
 * named helper.
 */
function encodeExpr(ref: TypeRef, expr: string, resolve: Resolve): string {
  if (typeof ref === "string") {
    return isBigintPrim(ref) ? `${expr}.toString()` : expr;
  }
  const id = resolveAlias(ref, resolve);
  return `_encode${helperSuffix(id, resolve)}(${expr})`;
}

function decodeExpr(ref: TypeRef, expr: string, resolve: Resolve): string {
  if (typeof ref === "string") {
    return isBigintPrim(ref) ? `BigInt(${expr} as string)` : expr;
  }
  const id = resolveAlias(ref, resolve);
  return `_decode${helperSuffix(id, resolve)}(${expr})`;
}

/** Emit the body of `function _encode<Name>(v: T): unknown` for a typedef. */
function emitEncodeHelper(id: number, resolve: Resolve): string {
  const def = resolve.types[id];
  const tsName = typeRefToTs(id, resolve);
  const fnName = `_encode${helperSuffix(id, resolve)}`;
  if (def.kind === "resource") {
    return `function ${fnName}(v: ${tsName}): unknown { return v; }`;
  }
  const k = def.kind as any;
  if ("type" in k) {
    // Alias — just forward
    return `function ${fnName}(v: ${tsName}): unknown { return ${encodeExpr(k.type, "v", resolve)}; }`;
  }
  if ("list" in k) {
    return `function ${fnName}(v: ${tsName}): unknown { return v.map(x => ${encodeExpr(k.list, "x", resolve)}); }`;
  }
  if ("option" in k) {
    return `function ${fnName}(v: ${tsName}): unknown { return v == null ? null : ${encodeExpr(k.option, "v", resolve)}; }`;
  }
  if ("result" in k) {
    const okExpr =
      k.result.ok != null
        ? `{ kind: "ok", value: ${encodeExpr(k.result.ok, "v.value", resolve)} }`
        : `{ kind: "ok" }`;
    const errExpr =
      k.result.err != null
        ? `{ kind: "err", value: ${encodeExpr(k.result.err, "v.value", resolve)} }`
        : `{ kind: "err" }`;
    return `function ${fnName}(v: ${tsName}): unknown { return v.kind === "ok" ? ${okExpr} : ${errExpr}; }`;
  }
  if ("record" in k) {
    const fields = k.record.fields
      .map(
        (f: any) =>
          `${JSON.stringify(f.name)}: ${encodeExpr(f.type, `v.${toCamel(f.name)}`, resolve)}`,
      )
      .join(", ");
    return `function ${fnName}(v: ${tsName}): unknown { return { ${fields} }; }`;
  }
  if ("variant" in k) {
    const arms = k.variant.cases
      .map((c: any) => {
        const payload =
          c.type != null
            ? `, value: ${encodeExpr(c.type, "(v as any).value", resolve)}`
            : "";
        return `case ${JSON.stringify(c.name)}: return { kind: ${JSON.stringify(c.name)}${payload} };`;
      })
      .join(" ");
    return `function ${fnName}(v: ${tsName}): unknown { switch (v.kind) { ${arms} } }`;
  }
  if ("enum" in k || "flags" in k) {
    return `function ${fnName}(v: ${tsName}): unknown { return v; }`;
  }
  if ("tuple" in k) {
    const parts = k.tuple.types
      .map((t: TypeRef, i: number) => encodeExpr(t, `v[${i}]`, resolve))
      .join(", ");
    return `function ${fnName}(v: ${tsName}): unknown { return [${parts}]; }`;
  }
  return `function ${fnName}(v: ${tsName}): unknown { return v; }`;
}

function emitDecodeHelper(id: number, resolve: Resolve): string {
  const def = resolve.types[id];
  const tsName = typeRefToTs(id, resolve);
  const fnName = `_decode${helperSuffix(id, resolve)}`;
  if (def.kind === "resource") {
    return `function ${fnName}(v: unknown): ${tsName} { return v as ${tsName}; }`;
  }
  const k = def.kind as any;
  if ("type" in k) {
    return `function ${fnName}(v: unknown): ${tsName} { return ${decodeExpr(k.type, "v", resolve)}; }`;
  }
  if ("list" in k) {
    return `function ${fnName}(v: unknown): ${tsName} { return (v as unknown[]).map(x => ${decodeExpr(k.list, "x", resolve)}); }`;
  }
  if ("option" in k) {
    return `function ${fnName}(v: unknown): ${tsName} { return v == null ? null : ${decodeExpr(k.option, "v", resolve)}; }`;
  }
  if ("result" in k) {
    const okExpr =
      k.result.ok != null
        ? `{ kind: "ok" as const, value: ${decodeExpr(k.result.ok, "(v as any).value", resolve)} }`
        : `{ kind: "ok" as const }`;
    const errExpr =
      k.result.err != null
        ? `{ kind: "err" as const, value: ${decodeExpr(k.result.err, "(v as any).value", resolve)} }`
        : `{ kind: "err" as const }`;
    return `function ${fnName}(v: unknown): ${tsName} { return (v as any).kind === "ok" ? ${okExpr} : ${errExpr}; }`;
  }
  if ("record" in k) {
    const fields = k.record.fields
      .map(
        (f: any) =>
          `${toCamel(f.name)}: ${decodeExpr(f.type, `(v as any)[${JSON.stringify(f.name)}]`, resolve)}`,
      )
      .join(", ");
    return `function ${fnName}(v: unknown): ${tsName} { return { ${fields} }; }`;
  }
  if ("variant" in k) {
    const arms = k.variant.cases
      .map((c: any) => {
        const payload =
          c.type != null
            ? `, value: ${decodeExpr(c.type, "(v as any).value", resolve)}`
            : "";
        return `case ${JSON.stringify(c.name)}: return { kind: ${JSON.stringify(c.name)}${payload} } as ${tsName};`;
      })
      .join(" ");
    return `function ${fnName}(v: unknown): ${tsName} { switch ((v as any).kind) { ${arms} default: throw new Error("unknown variant case: " + (v as any).kind); } }`;
  }
  if ("enum" in k || "flags" in k) {
    return `function ${fnName}(v: unknown): ${tsName} { return v as ${tsName}; }`;
  }
  if ("tuple" in k) {
    const parts = k.tuple.types
      .map((t: TypeRef, i: number) =>
        decodeExpr(t, `(v as unknown[])[${i}]`, resolve),
      )
      .join(", ");
    return `function ${fnName}(v: unknown): ${tsName} { return [${parts}] as ${tsName}; }`;
  }
  return `function ${fnName}(v: unknown): ${tsName} { return v as ${tsName}; }`;
}

function ctxKind(
  func: WitFunction,
  resolve: Resolve,
): "simulate" | "submit" {
  const ctx = func.params[0]?.type;
  if (typeof ctx !== "number") return "submit";
  const def = resolve.types[ctx];
  const k = def.kind as any;
  if (typeof k !== "object" || !("handle" in k)) return "submit";
  const target = k.handle.borrow ?? k.handle.own;
  if (typeof target !== "number") return "submit";
  const resolved = resolveAlias(target, resolve);
  return resolve.types[resolved].name === "view-context"
    ? "simulate"
    : "submit";
}

export function generate(witText: string): string {
  const w = new witCodec.Wit(witText);
  const resolve = JSON.parse(w.parse()) as Resolve;
  const root = resolve.worlds.find((wo) => wo.name === "root");
  if (!root) throw new Error("no `root` world in parsed WIT");

  const out: string[] = [];
  out.push("// Generated by kontor-codegen. Do not edit by hand.");
  out.push(
    'import { Wit, type KontorTransport } from "@kontor/sdk";',
  );
  out.push("");

  // Collect all type ids reachable from the root world's exports.
  const seen = new Set<number>();
  for (const item of Object.values(root.exports)) {
    if (!("function" in item)) continue;
    for (const p of item.function.params.slice(1)) {
      collectIds(p.type, resolve, seen);
    }
    if (item.function.result != null) {
      collectIds(item.function.result, resolve, seen);
    }
  }
  const ids = [...seen].sort((a, b) => a - b);

  // Emit a TS type declaration for every named user-defined type.
  for (const id of ids) {
    const def = resolve.types[id];
    const name = tsNameForType(id, resolve);
    if (name == null) continue;
    if (def.kind === "resource") continue;
    out.push(`export type ${name} = ${typeDefBodyToTs(def, resolve)};`);
    out.push("");
  }

  // Embed the WIT and instantiate the Wit resource at module load.
  out.push("const WIT = String.raw`" + witText.replace(/`/g, "\\`") + "`;");
  out.push("const _wit = new Wit(WIT);");
  out.push("");

  // Emit one _encode + _decode helper per reachable compound type.
  for (const id of ids) {
    out.push(emitEncodeHelper(id, resolve));
    out.push(emitDecodeHelper(id, resolve));
  }
  out.push("");

  // Emit the Contract class.
  const methods = Object.entries(root.exports).filter(
    (e): e is [string, { function: WitFunction }] => "function" in e[1],
  );

  out.push("export class Contract {");
  out.push("  constructor(private transport: KontorTransport) {}");
  out.push("");
  for (const [name, { function: fn }] of methods) {
    const safeName = toCamel(name);
    const userParams = fn.params.slice(1);
    const sig = userParams
      .map((p) => `${toCamel(p.name)}: ${typeRefToTs(p.type, resolve)}`)
      .join(", ");
    const wireArgFields = userParams
      .map(
        (p) =>
          `${JSON.stringify(p.name)}: ${encodeExpr(p.type, toCamel(p.name), resolve)}`,
      )
      .join(", ");
    const ret =
      fn.result != null
        ? `Promise<${typeRefToTs(fn.result, resolve)}>`
        : "Promise<void>";
    const dispatch = ctxKind(fn, resolve);

    out.push(`  async ${safeName}(${sig}): ${ret} {`);
    out.push(`    const wireArgs = { ${wireArgFields} };`);
    out.push(
      `    const wave = _wit.encodeCall(${JSON.stringify(name)}, JSON.stringify(wireArgs));`,
    );
    out.push(`    const resp = await this.transport.${dispatch}(wave);`);
    if (fn.result == null) {
      out.push("    return;");
    } else {
      out.push(
        `    const raw = JSON.parse(_wit.decodeResult(${JSON.stringify(name)}, resp));`,
      );
      out.push(`    return ${decodeExpr(fn.result, "raw", resolve)};`);
    }
    out.push("  }");
    out.push("");
  }
  out.push("}");
  out.push("");

  return out.join("\n");
}
