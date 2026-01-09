# Kontor WIT Validation Rules

This document describes the validation rules that Kontor enforces on WIT (WebAssembly Interface Types) signatures. These rules are **stricter than standard WIT** and are specific to the Kontor metaprotocol.

## 1. Function Signature Rules

- Functions **must** start with `export` (standard WIT allows functions in interfaces without `export`)
- Functions **must** be `async` (standard WIT allows sync functions)
- First parameter **must** be `ctx: borrow<proc-context|view-context|core-context|fall-context>` (standard WIT allows any parameters)
- Context types `proc-context`, `view-context`, `core-context`, `fall-context` are required Kontor resources (these don't exist in standard WIT)

### Valid Function Signature Format

```wit
export <name>: async func(ctx: borrow<proc-context|view-context|core-context|fall-context>, ...params) -> <return>;
```

### Special Functions: `init` and `fallback`

The `init` and `fallback` functions have fixed signatures:

```wit
// init - called once when contract is deployed (REQUIRED)
export init: async func(ctx: borrow<proc-context>);

// fallback - called when no matching function is found (optional)
export fallback: async func(ctx: borrow<fall-context>, expr: string) -> string;
```

- `init` is **required** - every contract must export it
- `init` must have exactly one parameter (`borrow<proc-context>`) and no return type
- `fallback` is optional
- `fallback` must have exactly two parameters (`borrow<fall-context>`, `string`) and return `string`

### Examples

```wit
// Valid
export transfer: async func(ctx: borrow<proc-context>, dst: string, amt: decimal) -> result<transfer, error>;
export balance: async func(ctx: borrow<view-context>, acc: string) -> option<decimal>;

// Invalid - missing export
transfer: async func(ctx: borrow<proc-context>, dst: string) -> result<transfer, error>;

// Invalid - missing context parameter
export transfer: async func(dst: string, amt: decimal) -> result<transfer, error>;

// Invalid - wrong context type
export transfer: async func(ctx: borrow<my-context>, dst: string) -> result<transfer, error>;

// Invalid - not async
export transfer: func(ctx: borrow<proc-context>, dst: string) -> result<transfer, error>;
```

---

## 2. Generic Type Restrictions

- `result<T, E>` must have **exactly 2** type parameters (standard WIT allows `result<T>` with 1 param)
- `result<T, E>` error type **must be `error`** (standard WIT allows any error type)
- Only these generics are recognized: `borrow`, `list`, `option`, `result` (standard WIT also has `own`, `stream`, `future`, `tuple`)

### Examples

```wit
// Valid
result<string, error>
result<my-record, error>
option<decimal>
list<string>
list<my-record>

// Invalid - result with 1 parameter
result<string>

// Invalid - result with non-error second parameter
result<string, my-error>
result<string, string>

// Invalid - unsupported generic
stream<u8>
future<string>
tuple<u64, string>
```

---

## 3. Supported Primitive Types

Kontor supports a **restricted subset** of WIT primitive types.

### Fully Supported

- `bool` - Boolean
- `string` - UTF-8 string
- `s64` - Signed 64-bit integer
- `u64` - Unsigned 64-bit integer
- `integer` - Arbitrary precision integer (Kontor-specific)
- `decimal` - Fixed-point decimal as `[bigint, number]` (Kontor-specific)
- `_` - Unit type

### Not Supported

- `char` - Single Unicode character
- `f32`, `f64` - Floating point numbers

---

## 4. Record Restrictions

- Records **must have at least one field** (standard WIT allows empty records)

### Examples

```wit
// Valid
record transfer { src: string, dst: string, amt: decimal }
record balance { acc: string, amt: decimal }

// Valid - nested records
record token-pair { a: contract-address, b: contract-address }

// Invalid - empty record
record empty { }
```

---

## 5. Enum/Variant/Flags

- `enum` - Fully supported
- `variant` - Supported with restrictions
- `flags` - Not yet implemented

### Enums

Enums are fully supported. They represent a set of named values without payloads.

```wit
// Valid
enum status { pending, approved, rejected }
```

### Variants

Variants are supported but with restrictions:

1. Each variant case can have **0 or 1** payload (not multiple)
2. Payloads **cannot be inline records** - they must reference a named type


```wit
// Valid - no payloads
variant event { started, stopped }

// Valid - single primitive payload
variant my-result { ok(string), err(string) }

// Valid - reference to a named record
variant response { success(my-record), failure }

// Invalid - inline record in a case
variant bad { success { message: string, code: u64 }, failure }

// Invalid - multiple payloads in a case
variant bad { item(string, u64) }
```

### Flags

Flags are not yet implemented.

---

## 6. No Cyclic Type References

Type definitions **cannot contain cycles**. This applies to all types - records, variants, enums, etc. Neither direct self-references nor indirect cycles through other types are allowed.

```wit
// Invalid - direct self-reference
record node { value: string, next: node }

// Invalid - direct self-reference in variant
variant tree { leaf(string), branch(tree) }

// Invalid - indirect cycle (record -> variant -> record)
record wrapper { data: my-variant }
variant my-variant { some(wrapper), none }

// Invalid - indirect cycle (record -> record -> record)
record a { b-field: b }
record b { a-field: a }
```

---

## 8. Context-Specific Type Restrictions

Some types have restrictions on where they can be used.

### `list<u8>` (bytes)

`list<u8>` is treated as a primitive byte array type, not a generic list. It can be used anywhere:
- Function inputs
- Function outputs
- Record fields
- Variant payloads

### `list<T>` (where T is not u8)

Generic lists can only be used in function signatures:
- Function inputs - allowed
- Function outputs - allowed
- Record fields - **not allowed**
- Variant payloads - **not allowed**

```wit
// Valid - list in function input/output
export get-names: func(ctx: borrow<view-context>) -> list<string>;
export process: func(ctx: borrow<proc-context>, items: list<my-record>) -> bool;

// Invalid - list as record field
record bad { names: list<string> }

// Invalid - list as variant payload
variant bad { items(list<string>) }
```

### `option<T>`

Options can be used anywhere:
- Function inputs
- Function outputs
- Record fields
- Variant payloads

### `result<T, error>`

Results can **only** be used as function return values:
- Function inputs - **not allowed**
- Function outputs - allowed
- Record fields - **not allowed**
- Variant payloads - **not allowed**

```wit
// Valid - result as return type
export transfer: func(ctx: borrow<proc-context>, dst: string) -> result<my-record, error>;

// Invalid - result as input parameter
export bad: func(ctx: borrow<proc-context>, r: result<string, error>) -> bool;

// Invalid - result as record field
record bad { outcome: result<string, error> }

// Invalid - result as variant payload
variant bad { success(result<string, error>) }
```

---

## 9. Nesting Restrictions

The encoding/decoding layer has strict limits on generic nesting depth.

### Allowed Nesting

```wit
list<string>
list<decimal>
list<my-record>
option<string>
option<decimal>
option<my-record>
result<string, error>
result<my-record, error>
result<list<my-record>, error>
```

### Not Allowed (Implementation Limitation)

```wit
// Nested lists
list<list<string>>

// Nested options
option<option<string>>

// Nested results
result<result<string, error>, error>

// Complex nesting in error channel
result<string, list<option<my-record>>>
```

---

## 10. Kontor-Specific Types

These types are unique to Kontor and do not exist in standard WIT:

- `integer` - Arbitrary precision integer (`bigint` in JS)
- `decimal` - Fixed-point decimal (`[bigint, number]` in JS, representing value and scale)
- `contract-address` - Kontor contract address (`string` in JS)
- `proc-context` - State-changing execution context (not user-facing)
- `view-context` - Read-only execution context (not user-facing)
- `core-context` - Core execution context (not user-facing)
- `fall-context` - Fallback execution context (not user-facing)
- `error` - Standard error type for result's error channel (`string` in JS)

---

## Summary

The key differences from standard WIT:

1. **Mandatory context parameter** - All functions must have `ctx: borrow<X-context>` as first parameter
2. **Fixed result error type** - `result<T, E>` must always be `result<T, error>`
3. **Limited primitives** - No 8/16/32-bit ints, no floats, no char
4. **Variant restrictions** - No inline records, max 1 payload per case
5. **No deep nesting** - Complex nested generics are not supported
6. **No cyclic types** - Type definitions cannot contain cycles
7. **Non-empty records** - Records must have at least one field
8. **Context-specific types** - `result` only in returns, `list<T>` (T≠u8) only in function signatures
9. **Custom types** - `integer`, `decimal`, `contract-address`, and context types
