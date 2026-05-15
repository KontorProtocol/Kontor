/**
 * kontor-codegen Tier 1: emit TypeScript types from a Kontor contract WIT.
 *
 * Walks the Resolve graph produced by `Wit.parse()` and emits:
 *   - A TS declaration for each named user-defined type reachable from
 *     the root world's exports
 *   - A `Contract` interface listing the world's exported functions
 *     with typed params (ctx param skipped per Kontor convention) and
 *     return types
 *
 * Tier 1 emits raw types only — no canonical-type ergonomics (Decimal
 * stays `{r0: bigint, ...}`), no contract wrapper class, no encode/decode
 * plumbing. Those are Tier 2 and Tier 3 respectively.
 */
import { witApi } from "./component/kontor-sdk";

type TypeRef = string | number;

interface TypeDef {
  name: string | null;
  kind:
    | "resource"
    | { record: { fields: Array<{ name: string; type: TypeRef }> } }
    | { variant: { cases: Array<{ name: string; type: TypeRef | null }> } }
    | { enum: { cases: Array<{ name: string }> } }
    | { result: { ok: TypeRef | null; err: TypeRef | null } }
    | { option: TypeRef }
    | { list: TypeRef }
    | { tuple: { types: TypeRef[] } }
    | { flags: { flags: Array<{ name: string }> } }
    | { type: TypeRef } // type alias
    | { handle: { borrow?: number; own?: number } }
    | { future?: TypeRef | null }
    | { stream?: TypeRef | null };
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

/** Map a primitive WIT type name to its TS equivalent. */
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
      return "bigint"; // FFI uses quoted decimal at the wire, exposed as bigint
    case "char":
    case "string":
      return "string";
    default:
      return "unknown /* primitive: " + name + " */";
  }
}

/** Kebab-case to camelCase for TS identifiers. */
function toCamel(s: string): string {
  return s.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
}

/** Kebab-case to PascalCase for TS type names. */
function toPascal(s: string): string {
  const c = toCamel(s);
  return c.charAt(0).toUpperCase() + c.slice(1);
}

/**
 * `use` re-exports create alias TypeDefs whose kind is `{type: target_id}`.
 * Follow the chain to the underlying definition so we don't emit
 * tautological `export type X = X;` declarations.
 */
function resolveAlias(id: number, resolve: Resolve): number {
  const def = resolve.types[id];
  const k = def.kind as any;
  if (typeof k === "object" && "type" in k && typeof k.type === "number") {
    return resolveAlias(k.type, resolve);
  }
  return id;
}

/** Look up the TS name for a TypeDef. Anonymous types get inlined. */
function tsNameForType(id: number, resolve: Resolve): string | null {
  const def = resolve.types[id];
  if (def.name == null) return null;
  return toPascal(def.name);
}

/** Convert a TypeRef (primitive string or type id) to TS source. */
function typeRefToTs(ref: TypeRef, resolve: Resolve): string {
  if (typeof ref === "string") return primitiveToTs(ref);
  const id = resolveAlias(ref, resolve);
  const def = resolve.types[id];
  const name = tsNameForType(id, resolve);
  if (name != null) return name;
  // Anonymous compound — inline it
  return typeDefToTs(def, resolve);
}

/** Convert a TypeDef body (the kind union) to TS source. */
function typeDefToTs(def: TypeDef, resolve: Resolve): string {
  if (def.kind === "resource") {
    return "unknown /* resource (runtime-only) */";
  }
  const k = def.kind as any;
  if ("type" in k) return typeRefToTs(k.type, resolve);
  if ("list" in k) return `Array<${typeRefToTs(k.list, resolve)}>`;
  if ("option" in k) return `${typeRefToTs(k.option, resolve)} | null`;
  if ("result" in k) {
    const ok =
      k.result.ok != null ? typeRefToTs(k.result.ok, resolve) : "void";
    const err =
      k.result.err != null ? typeRefToTs(k.result.err, resolve) : "void";
    const okArm =
      k.result.ok != null
        ? `{ kind: "ok"; value: ${ok} }`
        : `{ kind: "ok" }`;
    const errArm =
      k.result.err != null
        ? `{ kind: "err"; value: ${err} }`
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
    const arms = k.variant.cases.map((c: any) => {
      if (c.type == null) return `{ kind: "${c.name}" }`;
      return `{ kind: "${c.name}"; value: ${typeRefToTs(c.type, resolve)} }`;
    });
    return arms.join(" | ");
  }
  if ("enum" in k) {
    return k.enum.cases.map((c: any) => `"${c.name}"`).join(" | ");
  }
  if ("tuple" in k) {
    const items = k.tuple.types
      .map((t: TypeRef) => typeRefToTs(t, resolve))
      .join(", ");
    return `[${items}]`;
  }
  if ("flags" in k) {
    const names = k.flags.flags
      .map((f: any) => `"${f.name}"`)
      .join(" | ");
    return `Array<${names}>`;
  }
  if ("handle" in k) {
    return "unknown /* resource handle (runtime-only) */";
  }
  return `unknown /* unhandled kind: ${JSON.stringify(k)} */`;
}

/** Collect transitive type ids referenced from a TypeRef. */
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

/** Generate TypeScript types from a WIT source string. */
export function generate(witText: string): string {
  const w = new witApi.Wit(witText);
  const resolve = JSON.parse(w.parse()) as Resolve;
  const root = resolve.worlds.find((wo) => wo.name === "root");
  if (!root) {
    throw new Error("no `root` world in parsed WIT");
  }

  const out: string[] = [];
  out.push("// Generated by kontor-codegen. Do not edit by hand.");
  out.push("");

  // Collect all type ids reachable from the root world's exports.
  const seen = new Set<number>();
  for (const item of Object.values(root.exports)) {
    if (!("function" in item)) continue;
    // Skip the first (ctx) param; collect from the rest plus return.
    for (const p of item.function.params.slice(1)) {
      collectIds(p.type, resolve, seen);
    }
    if (item.function.result != null) {
      collectIds(item.function.result, resolve, seen);
    }
  }

  // Emit a TS declaration for every named type we've seen. Sort by id
  // so output is stable.
  const ids = [...seen].sort((a, b) => a - b);
  for (const id of ids) {
    const def = resolve.types[id];
    const name = tsNameForType(id, resolve);
    if (name == null) continue; // anonymous types get inlined at use site
    if (def.kind === "resource") continue;
    out.push(`export type ${name} = ${typeDefToTs(def, resolve)};`);
    out.push("");
  }

  // Emit the contract interface.
  out.push("export interface Contract {");
  for (const [name, item] of Object.entries(root.exports)) {
    if (!("function" in item)) continue;
    const userParams = item.function.params.slice(1); // drop ctx
    const sig = userParams
      .map((p) => `${toCamel(p.name)}: ${typeRefToTs(p.type, resolve)}`)
      .join(", ");
    const ret =
      item.function.result != null
        ? `Promise<${typeRefToTs(item.function.result, resolve)}>`
        : "Promise<void>";
    out.push(`  ${toCamel(name)}(${sig}): ${ret};`);
  }
  out.push("}");
  out.push("");

  return out.join("\n");
}
