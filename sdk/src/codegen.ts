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
 *
 * WIT type kinds are normalized into a strongly-typed `Kind` tagged
 * union once after JSON.parse (`normalizeKind`). Every walker function
 * then dispatches via `switch (k.tag)` — TS enforces exhaustiveness, so
 * an unhandled WIT kind is a compile error rather than silently falling
 * through. The untyped `def.kind: unknown` from wit_parser's JSON shape
 * never escapes the normalizer.
 */
import { witCodec } from "./component/kontor-sdk";

// ─── Parsed WIT graph ──────────────────────────────────────────
// Mirrors the JSON shape produced by `Wit.parse()` — wit_parser's
// Resolve arena serialized with stable string keys. `TypeDef.kind` is
// `unknown` here because wit_parser uses an untagged-by-key-presence
// serialization; we normalize it to `Kind` (below) right after parse.

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

interface Package {
  name: string;
  interfaces: Record<string, number>;
  worlds: Record<string, number>;
}

interface Resolve {
  worlds: World[];
  interfaces: Array<{ name: string; types: Record<string, number> }>;
  types: TypeDef[];
  packages?: Package[];
}

// ─── Normalized WIT type kinds ─────────────────────────────────

type Kind =
  | { tag: "alias"; type: TypeRef }
  | { tag: "list"; elem: TypeRef }
  | { tag: "option"; inner: TypeRef }
  | { tag: "result"; ok: TypeRef | null; err: TypeRef | null }
  | { tag: "record"; fields: Array<{ name: string; type: TypeRef }> }
  | { tag: "variant"; cases: Array<{ name: string; type: TypeRef | null }> }
  | { tag: "enum"; cases: string[] }
  | { tag: "tuple"; elems: TypeRef[] }
  | { tag: "flags"; names: string[] }
  | { tag: "resource" }
  | { tag: "handle"; borrow: TypeRef | null; own: TypeRef | null };

/**
 * Convert wit_parser's untagged single-key-record JSON into a typed
 * `Kind`. This is the only place that touches `unknown` kind data —
 * downstream every walker dispatches on `Kind.tag` exhaustively.
 */
function normalizeKind(raw: unknown): Kind {
  if (raw === "resource") return { tag: "resource" };
  const k = raw as Record<string, any>;
  if ("type" in k) return { tag: "alias", type: k.type };
  if ("list" in k) return { tag: "list", elem: k.list };
  if ("option" in k) return { tag: "option", inner: k.option };
  if ("result" in k) {
    return {
      tag: "result",
      ok: k.result.ok ?? null,
      err: k.result.err ?? null,
    };
  }
  if ("record" in k) return { tag: "record", fields: k.record.fields };
  if ("variant" in k) {
    return {
      tag: "variant",
      cases: k.variant.cases.map((c: any) => ({
        name: c.name,
        type: c.type ?? null,
      })),
    };
  }
  if ("enum" in k) {
    return { tag: "enum", cases: k.enum.cases.map((c: any) => c.name) };
  }
  if ("tuple" in k) return { tag: "tuple", elems: k.tuple.types };
  if ("flags" in k) {
    return { tag: "flags", names: k.flags.flags.map((f: any) => f.name) };
  }
  if ("handle" in k) {
    return {
      tag: "handle",
      borrow: k.handle.borrow ?? null,
      own: k.handle.own ?? null,
    };
  }
  throw new Error(`unrecognized WIT type kind: ${JSON.stringify(raw)}`);
}

// ─── Canonical Kontor types ────────────────────────────────────

/**
 * Canonical Kontor types with hand-written TS wrapper classes. Detected
 * by fully-qualified `package/interface.type` name. The walker emits
 * the class name in TS type expressions and uses `(v).toRaw()` /
 * `<Class>.fromRaw(raw)` at boundaries instead of generating a struct
 * helper.
 */
const CANONICAL_TYPES: Record<string, string> = {
  "kontor:built-in/numbers.decimal": "Decimal",
};

// ─── Shared utilities ──────────────────────────────────────────

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

// ─── Walker context + lookups ──────────────────────────────────

interface Ctx {
  resolve: Resolve;
  kinds: Kind[]; // parallel to resolve.types, indexed by type id
  canonical: Map<number, string>;
}

/** Follow `use` aliases to the underlying TypeDef id. Stops at primitives. */
function resolveAlias(id: number, ctx: Ctx): number {
  const k = ctx.kinds[id];
  if (k.tag === "alias" && typeof k.type === "number") {
    return resolveAlias(k.type, ctx);
  }
  return id;
}

/** Stable helper-function suffix for a given type id. */
function helperSuffix(id: number, ctx: Ctx): string {
  const def = ctx.resolve.types[id];
  return def.name != null ? toPascal(def.name) : `T${id}`;
}

function tsNameForType(id: number, ctx: Ctx): string | null {
  const def = ctx.resolve.types[id];
  return def.name != null ? toPascal(def.name) : null;
}

/**
 * Build a map from resolved type id → canonical class name. Walks
 * `packages` to find `{package}/{interface}.{type}` triples that match
 * `CANONICAL_TYPES` and records the underlying interface-owned type id.
 */
function buildCanonicalMap(resolve: Resolve): Map<number, string> {
  const out = new Map<number, string>();
  for (const pkg of resolve.packages ?? []) {
    for (const [ifaceName, ifaceId] of Object.entries(pkg.interfaces)) {
      const iface = resolve.interfaces[ifaceId];
      if (!iface) continue;
      for (const [typeName, typeId] of Object.entries(iface.types)) {
        const qname = `${pkg.name}/${ifaceName}.${typeName}`;
        const cls = CANONICAL_TYPES[qname];
        if (cls) out.set(typeId, cls);
      }
    }
  }
  return out;
}

// ─── Type expressions (TS source) ──────────────────────────────

function typeRefToTs(ref: TypeRef, ctx: Ctx): string {
  if (typeof ref === "string") return primitiveToTs(ref);
  const id = resolveAlias(ref, ctx);
  const canon = ctx.canonical.get(id);
  if (canon != null) return canon;
  const name = tsNameForType(id, ctx);
  return name ?? typeDefBody(id, ctx);
}

function typeDefBody(id: number, ctx: Ctx): string {
  const k = ctx.kinds[id];
  switch (k.tag) {
    case "resource":
    case "handle":
      return "unknown";
    case "alias":
      return typeRefToTs(k.type, ctx);
    case "list":
      return `Array<${typeRefToTs(k.elem, ctx)}>`;
    case "option":
      return `${typeRefToTs(k.inner, ctx)} | null`;
    case "result": {
      const okArm =
        k.ok != null
          ? `{ kind: "ok"; value: ${typeRefToTs(k.ok, ctx)} }`
          : `{ kind: "ok" }`;
      const errArm =
        k.err != null
          ? `{ kind: "err"; value: ${typeRefToTs(k.err, ctx)} }`
          : `{ kind: "err" }`;
      return `${okArm} | ${errArm}`;
    }
    case "record": {
      const fields = k.fields
        .map((f) => `  ${toCamel(f.name)}: ${typeRefToTs(f.type, ctx)};`)
        .join("\n");
      return `{\n${fields}\n}`;
    }
    case "variant":
      return k.cases
        .map((c) =>
          c.type == null
            ? `{ kind: "${c.name}" }`
            : `{ kind: "${c.name}"; value: ${typeRefToTs(c.type, ctx)} }`,
        )
        .join(" | ");
    case "enum":
      return k.cases.map((n) => `"${n}"`).join(" | ");
    case "tuple":
      return `[${k.elems.map((t) => typeRefToTs(t, ctx)).join(", ")}]`;
    case "flags":
      return `Array<${k.names.map((n) => `"${n}"`).join(" | ")}>`;
  }
}

// ─── Encode / decode expressions ───────────────────────────────

/**
 * Emit a TS expression that encodes `expr` (a value of WIT type `ref`)
 * to its wire JSON shape. Primitives inline; canonical types delegate
 * to the class's `.toRaw()`; everything else calls a named helper.
 */
function encodeExpr(ref: TypeRef, expr: string, ctx: Ctx): string {
  if (typeof ref === "string") {
    return isBigintPrim(ref) ? `${expr}.toString()` : expr;
  }
  const id = resolveAlias(ref, ctx);
  if (ctx.canonical.has(id)) return `(${expr}).toRaw()`;
  return `_encode${helperSuffix(id, ctx)}(${expr})`;
}

function decodeExpr(ref: TypeRef, expr: string, ctx: Ctx): string {
  if (typeof ref === "string") {
    return isBigintPrim(ref) ? `BigInt(${expr} as string)` : expr;
  }
  const id = resolveAlias(ref, ctx);
  const canon = ctx.canonical.get(id);
  if (canon != null) return `${canon}.fromRaw(${expr} as any)`;
  return `_decode${helperSuffix(id, ctx)}(${expr})`;
}

// ─── Helper-function bodies ────────────────────────────────────

function emitEncodeHelper(id: number, ctx: Ctx): string {
  const k = ctx.kinds[id];
  const tsName = typeRefToTs(id, ctx);
  const fnName = `_encode${helperSuffix(id, ctx)}`;
  switch (k.tag) {
    case "resource":
    case "handle":
    case "enum":
    case "flags":
      return `function ${fnName}(v: ${tsName}): unknown { return v; }`;
    case "alias":
      return `function ${fnName}(v: ${tsName}): unknown { return ${encodeExpr(k.type, "v", ctx)}; }`;
    case "list":
      return `function ${fnName}(v: ${tsName}): unknown { return v.map(x => ${encodeExpr(k.elem, "x", ctx)}); }`;
    case "option":
      return `function ${fnName}(v: ${tsName}): unknown { return v == null ? null : ${encodeExpr(k.inner, "v", ctx)}; }`;
    case "result": {
      const okExpr =
        k.ok != null
          ? `{ kind: "ok", value: ${encodeExpr(k.ok, "v.value", ctx)} }`
          : `{ kind: "ok" }`;
      const errExpr =
        k.err != null
          ? `{ kind: "err", value: ${encodeExpr(k.err, "v.value", ctx)} }`
          : `{ kind: "err" }`;
      return `function ${fnName}(v: ${tsName}): unknown { return v.kind === "ok" ? ${okExpr} : ${errExpr}; }`;
    }
    case "record": {
      const fields = k.fields
        .map(
          (f) =>
            `${JSON.stringify(f.name)}: ${encodeExpr(f.type, `v.${toCamel(f.name)}`, ctx)}`,
        )
        .join(", ");
      return `function ${fnName}(v: ${tsName}): unknown { return { ${fields} }; }`;
    }
    case "variant": {
      const arms = k.cases
        .map((c) => {
          const payload =
            c.type != null
              ? `, value: ${encodeExpr(c.type, "(v as any).value", ctx)}`
              : "";
          return `case ${JSON.stringify(c.name)}: return { kind: ${JSON.stringify(c.name)}${payload} };`;
        })
        .join(" ");
      return `function ${fnName}(v: ${tsName}): unknown { switch (v.kind) { ${arms} } }`;
    }
    case "tuple": {
      const parts = k.elems
        .map((t, i) => encodeExpr(t, `v[${i}]`, ctx))
        .join(", ");
      return `function ${fnName}(v: ${tsName}): unknown { return [${parts}]; }`;
    }
  }
}

function emitDecodeHelper(id: number, ctx: Ctx): string {
  const k = ctx.kinds[id];
  const tsName = typeRefToTs(id, ctx);
  const fnName = `_decode${helperSuffix(id, ctx)}`;
  switch (k.tag) {
    case "resource":
    case "handle":
    case "enum":
    case "flags":
      return `function ${fnName}(v: unknown): ${tsName} { return v as ${tsName}; }`;
    case "alias":
      return `function ${fnName}(v: unknown): ${tsName} { return ${decodeExpr(k.type, "v", ctx)}; }`;
    case "list":
      return `function ${fnName}(v: unknown): ${tsName} { return (v as unknown[]).map(x => ${decodeExpr(k.elem, "x", ctx)}); }`;
    case "option":
      return `function ${fnName}(v: unknown): ${tsName} { return v == null ? null : ${decodeExpr(k.inner, "v", ctx)}; }`;
    case "result": {
      const okExpr =
        k.ok != null
          ? `{ kind: "ok" as const, value: ${decodeExpr(k.ok, "(v as any).value", ctx)} }`
          : `{ kind: "ok" as const }`;
      const errExpr =
        k.err != null
          ? `{ kind: "err" as const, value: ${decodeExpr(k.err, "(v as any).value", ctx)} }`
          : `{ kind: "err" as const }`;
      return `function ${fnName}(v: unknown): ${tsName} { return (v as any).kind === "ok" ? ${okExpr} : ${errExpr}; }`;
    }
    case "record": {
      const fields = k.fields
        .map(
          (f) =>
            `${toCamel(f.name)}: ${decodeExpr(f.type, `(v as any)[${JSON.stringify(f.name)}]`, ctx)}`,
        )
        .join(", ");
      return `function ${fnName}(v: unknown): ${tsName} { return { ${fields} }; }`;
    }
    case "variant": {
      const arms = k.cases
        .map((c) => {
          const payload =
            c.type != null
              ? `, value: ${decodeExpr(c.type, "(v as any).value", ctx)}`
              : "";
          return `case ${JSON.stringify(c.name)}: return { kind: ${JSON.stringify(c.name)}${payload} } as ${tsName};`;
        })
        .join(" ");
      return `function ${fnName}(v: unknown): ${tsName} { switch ((v as any).kind) { ${arms} default: throw new Error("unknown variant case: " + (v as any).kind); } }`;
    }
    case "tuple": {
      const parts = k.elems
        .map((t, i) => decodeExpr(t, `(v as unknown[])[${i}]`, ctx))
        .join(", ");
      return `function ${fnName}(v: unknown): ${tsName} { return [${parts}] as ${tsName}; }`;
    }
  }
}

// ─── Reachability + dispatch ───────────────────────────────────

function collectIds(ref: TypeRef, seen: Set<number>, ctx: Ctx): void {
  if (typeof ref === "string") return;
  const id = resolveAlias(ref, ctx);
  if (seen.has(id)) return;
  seen.add(id);
  if (ctx.canonical.has(id)) return;
  const k = ctx.kinds[id];
  switch (k.tag) {
    case "resource":
    case "handle":
    case "enum":
    case "flags":
      return;
    case "alias":
      collectIds(k.type, seen, ctx);
      return;
    case "list":
      collectIds(k.elem, seen, ctx);
      return;
    case "option":
      collectIds(k.inner, seen, ctx);
      return;
    case "result":
      if (k.ok != null) collectIds(k.ok, seen, ctx);
      if (k.err != null) collectIds(k.err, seen, ctx);
      return;
    case "record":
      for (const f of k.fields) collectIds(f.type, seen, ctx);
      return;
    case "variant":
      for (const c of k.cases) {
        if (c.type != null) collectIds(c.type, seen, ctx);
      }
      return;
    case "tuple":
      for (const t of k.elems) collectIds(t, seen, ctx);
      return;
  }
}

function ctxDispatch(fn: WitFunction, ctx: Ctx): "simulate" | "submit" {
  const ctxParam = fn.params[0]?.type;
  if (typeof ctxParam !== "number") return "submit";
  const k = ctx.kinds[ctxParam];
  if (k.tag !== "handle") return "submit";
  const target = k.borrow ?? k.own;
  if (typeof target !== "number") return "submit";
  const resolved = resolveAlias(target, ctx);
  return ctx.resolve.types[resolved].name === "view-context"
    ? "simulate"
    : "submit";
}

// ─── Public API ────────────────────────────────────────────────

export function generate(witText: string): string {
  const w = new witCodec.Wit(witText);
  const resolve = JSON.parse(w.parse()) as Resolve;
  const root = resolve.worlds.find((wo) => wo.name === "root");
  if (!root) throw new Error("no `root` world in parsed WIT");

  const ctx: Ctx = {
    resolve,
    kinds: resolve.types.map((t) => normalizeKind(t.kind)),
    canonical: buildCanonicalMap(resolve),
  };

  // Collect all type ids reachable from the root world's exports.
  const seen = new Set<number>();
  for (const item of Object.values(root.exports)) {
    if (!("function" in item)) continue;
    for (const p of item.function.params.slice(1)) {
      collectIds(p.type, seen, ctx);
    }
    if (item.function.result != null) {
      collectIds(item.function.result, seen, ctx);
    }
  }
  const ids = [...seen].sort((a, b) => a - b);

  const usedCanonicalClasses = new Set<string>();
  for (const id of ids) {
    const cls = ctx.canonical.get(id);
    if (cls) usedCanonicalClasses.add(cls);
  }

  const out: string[] = [];
  out.push("// Generated by kontor-codegen. Do not edit by hand.");
  const sdkImports = ["Wit", "type KontorTransport"];
  for (const cls of [...usedCanonicalClasses].sort()) sdkImports.push(cls);
  out.push(`import { ${sdkImports.join(", ")} } from "@kontor/sdk";`);
  out.push("");

  // Emit a TS type declaration for every named user-defined type. Skip
  // canonical types — they're imported as classes from @kontor/sdk.
  for (const id of ids) {
    if (ctx.canonical.has(id)) continue;
    const k = ctx.kinds[id];
    const name = tsNameForType(id, ctx);
    if (name == null || k.tag === "resource") continue;
    out.push(`export type ${name} = ${typeDefBody(id, ctx)};`);
    out.push("");
  }

  // Embed the WIT and instantiate the Wit resource at module load.
  out.push("const WIT = String.raw`" + witText.replace(/`/g, "\\`") + "`;");
  out.push("const _wit = new Wit(WIT);");
  out.push("");

  // Emit _encode + _decode helpers per reachable non-canonical type.
  for (const id of ids) {
    if (ctx.canonical.has(id)) continue;
    out.push(emitEncodeHelper(id, ctx));
    out.push(emitDecodeHelper(id, ctx));
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
      .map((p) => `${toCamel(p.name)}: ${typeRefToTs(p.type, ctx)}`)
      .join(", ");
    const wireArgFields = userParams
      .map(
        (p) =>
          `${JSON.stringify(p.name)}: ${encodeExpr(p.type, toCamel(p.name), ctx)}`,
      )
      .join(", ");
    const ret =
      fn.result != null
        ? `Promise<${typeRefToTs(fn.result, ctx)}>`
        : "Promise<void>";
    const dispatch = ctxDispatch(fn, ctx);

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
      out.push(`    return ${decodeExpr(fn.result, "raw", ctx)};`);
    }
    out.push("  }");
    out.push("");
  }
  out.push("}");
  out.push("");

  return out.join("\n");
}
