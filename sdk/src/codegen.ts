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

/** Emit a TypeNode literal expression for a given TypeRef. */
function typeRefToTypeNode(ref: TypeRef, resolve: Resolve): string {
  if (typeof ref === "string") {
    if (ref === "u64" || ref === "s64") return `{ k: "bigint" }`;
    return `{ k: "passthrough" }`;
  }
  const id = resolveAlias(ref, resolve);
  const def = resolve.types[id];
  if (def.kind === "resource") return `{ k: "passthrough" }`;
  const k = def.kind as any;
  if ("type" in k) return typeRefToTypeNode(k.type, resolve);
  if ("list" in k) {
    return `{ k: "list", el: ${typeRefToTypeNode(k.list, resolve)} }`;
  }
  if ("option" in k) {
    return `{ k: "option", el: ${typeRefToTypeNode(k.option, resolve)} }`;
  }
  if ("result" in k) {
    const ok =
      k.result.ok != null ? typeRefToTypeNode(k.result.ok, resolve) : "null";
    const err =
      k.result.err != null ? typeRefToTypeNode(k.result.err, resolve) : "null";
    return `{ k: "result", ok: ${ok}, err: ${err} }`;
  }
  if ("record" in k) {
    const fields = k.record.fields
      .map(
        (f: any) =>
          `{ js: ${JSON.stringify(toCamel(f.name))}, wire: ${JSON.stringify(f.name)}, t: ${typeRefToTypeNode(f.type, resolve)} }`,
      )
      .join(", ");
    return `{ k: "record", fields: [${fields}] }`;
  }
  if ("variant" in k) {
    const cases = k.variant.cases
      .map((c: any) => {
        const inner =
          c.type != null ? typeRefToTypeNode(c.type, resolve) : "null";
        return `${JSON.stringify(c.name)}: ${inner}`;
      })
      .join(", ");
    return `{ k: "variant", cases: { ${cases} } }`;
  }
  if ("enum" in k) return `{ k: "passthrough" }`;
  if ("tuple" in k) {
    const els = k.tuple.types
      .map((t: TypeRef) => typeRefToTypeNode(t, resolve))
      .join(", ");
    return `{ k: "tuple", els: [${els}] }`;
  }
  return `{ k: "passthrough" }`;
}

/**
 * Determine whether a method is view-context (simulate) or proc-context
 * (submit) based on its ctx (first) param's borrow target.
 */
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
  // Follow alias chain to the underlying named type.
  const resolved = resolveAlias(target, resolve);
  const name = resolve.types[resolved].name;
  return name === "view-context" ? "simulate" : "submit";
}

/** Generate TypeScript types + Contract class from a WIT source string. */
export function generate(witText: string): string {
  const w = new witApi.Wit(witText);
  const resolve = JSON.parse(w.parse()) as Resolve;
  const root = resolve.worlds.find((wo) => wo.name === "root");
  if (!root) {
    throw new Error("no `root` world in parsed WIT");
  }

  const out: string[] = [];
  out.push("// Generated by kontor-codegen. Do not edit by hand.");
  out.push(
    'import { witApi, encodeJson, decodeJson, type TypeNode, type KontorTransport } from "@kontor/sdk";',
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
  for (const id of ids) {
    const def = resolve.types[id];
    const name = tsNameForType(id, resolve);
    if (name == null) continue;
    if (def.kind === "resource") continue;
    out.push(`export type ${name} = ${typeDefToTs(def, resolve)};`);
    out.push("");
  }

  // Embed the WIT source so the generated Contract is self-sufficient.
  out.push("const WIT = String.raw`" + witText.replace(/`/g, "\\`") + "`;");
  out.push("const _wit = new witApi.Wit(WIT);");
  out.push("");

  // Emit per-method TypeNode constants for the args + return type. Use
  // bracketed access syntax to allow kebab-case function names.
  const methods = Object.entries(root.exports).filter(
    (e): e is [string, { function: WitFunction }] => "function" in e[1],
  );
  for (const [name, { function: fn }] of methods) {
    const safeName = toCamel(name);
    const userParams = fn.params.slice(1);
    const argsNode =
      userParams.length === 0
        ? `{ k: "record", fields: [] }`
        : `{ k: "record", fields: [${userParams
            .map(
              (p) =>
                `{ js: ${JSON.stringify(toCamel(p.name))}, wire: ${JSON.stringify(p.name)}, t: ${typeRefToTypeNode(p.type, resolve)} }`,
            )
            .join(", ")}] }`;
    const resultNode =
      fn.result != null ? typeRefToTypeNode(fn.result, resolve) : "null";
    out.push(`const _${safeName}_args: TypeNode = ${argsNode};`);
    out.push(`const _${safeName}_result: TypeNode | null = ${resultNode};`);
  }
  out.push("");

  // Emit the Contract class.
  out.push("export class Contract {");
  out.push("  constructor(private transport: KontorTransport) {}");
  out.push("");
  for (const [name, { function: fn }] of methods) {
    const safeName = toCamel(name);
    const userParams = fn.params.slice(1);
    const sig = userParams
      .map((p) => `${toCamel(p.name)}: ${typeRefToTs(p.type, resolve)}`)
      .join(", ");
    const argObj = userParams
      .map((p) => `${toCamel(p.name)}`)
      .join(", ");
    const ret =
      fn.result != null
        ? `Promise<${typeRefToTs(fn.result, resolve)}>`
        : "Promise<void>";
    const dispatch = ctxKind(fn, resolve);
    out.push(`  async ${safeName}(${sig}): ${ret} {`);
    out.push(
      `    const wireArgs = encodeJson({ ${argObj} }, _${safeName}_args);`,
    );
    out.push(
      `    const wave = _wit.encodeCall(${JSON.stringify(name)}, JSON.stringify(wireArgs));`,
    );
    out.push(`    const resp = await this.transport.${dispatch}(wave);`);
    if (fn.result == null) {
      out.push(`    return;`);
    } else {
      out.push(
        `    const raw = JSON.parse(_wit.decodeResult(${JSON.stringify(name)}, resp));`,
      );
      out.push(
        `    return decodeJson(raw, _${safeName}_result!) as ${typeRefToTs(fn.result, resolve)};`,
      );
    }
    out.push(`  }`);
    out.push("");
  }
  out.push("}");
  out.push("");

  return out.join("\n");
}
