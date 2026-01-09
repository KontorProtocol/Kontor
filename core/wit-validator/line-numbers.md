# Line Numbers in Validation Errors

## Current Limitation

wit-validator cannot provide line numbers in validation errors because wit-parser doesn't expose span information on resolved types.

## Why

wit-parser tracks spans during parsing in private fields (`InterfaceSpan.funcs`, `type_spans`, etc.) but discards them during resolution. The resolved `Function`, `TypeDef`, `Interface`, and `World` structs have no span fields. The `SourceMap::render_location()` method exists but is `pub(crate)`.

## Upstream PR Strategy

Add `pub span: Option<Span>` to resolved types in wit-parser:

```rust
// lib.rs
pub struct Function {
    pub name: String,
    pub kind: FunctionKind,
    pub params: Vec<(String, Type)>,
    pub result: Option<Type>,
    pub docs: Docs,
    pub stability: Stability,
    pub span: Option<Span>,  // add
}

pub struct TypeDef {
    pub name: Option<String>,
    pub kind: TypeDefKind,
    pub owner: TypeOwner,
    pub docs: Docs,
    pub stability: Stability,
    pub span: Option<Span>,  // add
}

pub struct Interface {
    // existing fields...
    pub span: Option<Span>,  // add
}

pub struct World {
    // existing fields...
    pub span: Option<Span>,  // add
}
```

Make `Span` and `SourceMap::render_location()` public:

```rust
// ast/lex.rs - Span is already pub, just needs re-export
// lib.rs
pub use ast::lex::Span;

// ast.rs
impl SourceMap {
    pub fn render_location(&self, span: Span) -> String { ... }  // change from pub(crate)
}
```

Thread spans through resolution by passing them from `InterfaceSpan.funcs[i]` to `Interface.functions[name].span` during the resolution in `resolve.rs`.

`Option<Span>` is `None` when loading from binary format (no source text).

## no_std Support

wit-parser could also benefit from a `std` feature to gate filesystem operations (`push_file`, `push_path`, `push_dir`) while keeping `push_str` available in `no_std` + `alloc` environments.
