use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Error, FieldsNamed, Ident, Meta, Result, Token, Type, token};

/// A declared secondary index: its name, its bucket field(s), an optional sort
/// field, and optional covering-projection fields. Built from both forms a value
/// can declare an index:
/// - field-level `#[index] f` — sugar for `#[index(f, by = f)]`.
/// - struct-level `#[index(name, by = field, sort = field, include = (a, b))]`.
///
/// The single source both the `Storage` derive (which writes the index) and the
/// `Model` derive (which reconciles it on in-place setters and reads it back for
/// diffs) parse from, so the descriptor they produce can't drift.
pub struct IndexDecl {
    pub name: String,
    pub by: Vec<Ident>,
    pub sort: Option<Ident>,
    /// Covering-projection fields (`include = (a, b)`) — copied into the index leaf
    /// value so a `.values()`/`.iter()` read is index-only (no follow-up `get` per
    /// member). Empty for a non-covering index. Each must be a round-trip scalar
    /// (`KeyElement`), enforced by the generated projection encode/decode.
    pub include: Vec<Ident>,
    /// Interned id for the index's `<index>` path segment — its declaration order
    /// within the value type (assigned by [`parse`]). The single source the write
    /// side ([`index_entry`]) and the read side (the typed lookup methods) both use,
    /// so the index path can't drift. Its own per-type id space (under `#idx`),
    /// distinct from the struct's field ids.
    pub id: u8,
}

/// The parsed arguments of a struct-level `#[index(...)]`. `name` is the leading
/// bare ident; the rest are `key = value` options.
struct IndexArgs {
    name: Ident,
    by: Option<Vec<Ident>>,
    sort: Option<Ident>,
    include: Option<Vec<Ident>>,
}

/// Parse a `field` or `(a, b, …)` field list — the shape shared by `by` and
/// `include`.
fn parse_ident_list(input: ParseStream) -> Result<Vec<Ident>> {
    if input.peek(token::Paren) {
        let content;
        syn::parenthesized!(content in input);
        let idents: Punctuated<Ident, Token![,]> =
            content.parse_terminated(Ident::parse, Token![,])?;
        Ok(idents.into_iter().collect())
    } else {
        Ok(vec![input.parse::<Ident>()?])
    }
}

impl Parse for IndexArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let mut args = IndexArgs {
            name,
            by: None,
            sort: None,
            include: None,
        };
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                // `by = field` or `by = (a, b)` (composite).
                "by" => args.by = Some(parse_ident_list(input)?),
                "sort" => args.sort = Some(input.parse()?),
                // `include = field` or `include = (a, b)` (covering projection).
                "include" => args.include = Some(parse_ident_list(input)?),
                other => {
                    return Err(Error::new(
                        key.span(),
                        format!(
                            "unknown index option `{other}` (expected `by`, `sort`, or `include`)"
                        ),
                    ));
                }
            }
        }
        Ok(args)
    }
}

/// Parse every index a struct declares (field-level sugar + struct-level forms),
/// validating that referenced fields exist, names are unique, and any `include`
/// (covering) fields are real, non-duplicate, and not the sort field.
pub fn parse(struct_attrs: &[Attribute], fields: &FieldsNamed) -> Result<Vec<IndexDecl>> {
    let mut decls = Vec::new();

    // Field-level `#[index]` sugar: bare attribute only.
    for field in &fields.named {
        let ident = field.ident.as_ref().unwrap();
        for attr in &field.attrs {
            if !attr.path().is_ident("index") {
                continue;
            }
            if !matches!(attr.meta, Meta::Path(_)) {
                return Err(Error::new_spanned(
                    attr,
                    "field-level `#[index]` takes no arguments; use the struct-level \
                     `#[index(name, by = …, sort = …)]` form for options",
                ));
            }
            if let Some(reason) = reserved_index_name(&ident.to_string()) {
                return Err(Error::new(
                    ident.span(),
                    format!(
                        "index name `{ident}` is reserved ({reason}); rename the field or use a named struct-level index"
                    ),
                ));
            }
            decls.push(IndexDecl {
                name: ident.to_string(),
                by: vec![ident.clone()],
                sort: None,
                include: Vec::new(),
                id: 0, // numbered after all decls are collected
            });
        }
    }

    // Struct-level `#[index(name, by = …, sort = …, include = (…))]`.
    for attr in struct_attrs {
        if !attr.path().is_ident("index") {
            continue;
        }
        let args: IndexArgs = attr.parse_args()?;
        if let Some(reason) = reserved_index_name(&args.name.to_string()) {
            return Err(Error::new_spanned(
                &args.name,
                format!(
                    "index name `{}` is reserved ({reason}); rename the index",
                    args.name
                ),
            ));
        }
        let by = args.by.unwrap_or_else(|| vec![args.name.clone()]);
        if by.is_empty() {
            return Err(Error::new_spanned(
                attr,
                "index `by` must name at least one field",
            ));
        }
        let include = args.include.unwrap_or_default();
        // Covering projection: each `include` field is copied into the index leaf.
        // Round-trip scalar (`KeyElement`) is enforced by the generated encode/decode;
        // here we reject name-level mistakes with a clear message. The sort field is
        // already carried in the leaf value for free (it leads the member key), so
        // including it is redundant; a duplicate include is a copy-paste slip.
        for (i, f) in include.iter().enumerate() {
            if args.sort.as_ref() == Some(f) {
                return Err(Error::new_spanned(
                    f,
                    format!(
                        "`{f}` is the sort field — it is already covered for free; drop it from `include`"
                    ),
                ));
            }
            if include[..i].contains(f) {
                return Err(Error::new_spanned(
                    f,
                    format!("`{f}` is listed twice in `include`"),
                ));
            }
        }
        for referenced in by.iter().chain(args.sort.iter()).chain(include.iter()) {
            if !field_exists(fields, referenced) {
                return Err(Error::new_spanned(
                    referenced,
                    format!("`{referenced}` is not a field of this struct"),
                ));
            }
        }
        decls.push(IndexDecl {
            name: args.name.to_string(),
            by,
            sort: args.sort,
            include,
            id: 0, // numbered after all decls are collected
        });
    }

    // Assign each index its interned id = declaration order. A u8 segment, so a
    // value type may declare at most 256 indexes (far beyond any real use).
    if decls.len() > 256 {
        return Err(Error::new(
            Span::call_site(),
            "a value type may not declare more than 256 indexes (interned id space)",
        ));
    }
    for (i, decl) in decls.iter_mut().enumerate() {
        decl.id = i as u8;
    }

    for i in 0..decls.len() {
        for j in (i + 1)..decls.len() {
            if decls[i].name == decls[j].name {
                return Err(Error::new(
                    Span::call_site(),
                    format!(
                        "duplicate index name `{}` (a field-level `#[index]` and a struct-level \
                         `#[index({0}, …)]` collide — drop one or rename)",
                        decls[i].name
                    ),
                ));
            }
        }
    }

    Ok(decls)
}

fn field_exists(fields: &FieldsNamed, ident: &Ident) -> bool {
    fields.named.iter().any(|f| f.ident.as_ref() == Some(ident))
}

/// If an index `name` would shadow one of the field model's inherent methods or a
/// query finisher, return why. The index name becomes a method on the field model,
/// and an inherent method wins over a trait method by name resolution — so a
/// colliding index would be silently unreachable. Reject it at parse time (before
/// any codegen) so the derive fails with just this error.
fn reserved_index_name(name: &str) -> Option<&'static str> {
    const MAP_SURFACE: &[&str] = &["get", "set", "keys", "load", "remove", "new"];
    const QUERY_FINISHERS: &[&str] = &[
        "iter",
        "values",
        "range",
        "len",
        "is_empty",
        "count",
        "with_scores",
    ];
    const PRIMITIVES: &[&str] = &["by_index", "by_index_sorted", "bucket_count"];
    if MAP_SURFACE.contains(&name) {
        Some("shadows the map accessor of the same name")
    } else if QUERY_FINISHERS.contains(&name) {
        Some("shadows a query finisher")
    } else if PRIMITIVES.contains(&name) {
        Some("shadows an index-scan primitive")
    } else {
        None
    }
}

/// Distinct fields referenced (bucket + sort + covering `include`) across `decls`, in
/// first-seen order. Reading each once before building entries avoids re-reading a
/// storage slot that two indexes share, or that a setter's old and new entry both need.
/// The `include` fields must be here too: the read model builds each entry's covering
/// projection from them, so they need the same `__idx_<field>` preload as `by`/`sort`.
pub fn referenced_fields<'a>(decls: impl IntoIterator<Item = &'a IndexDecl>) -> Vec<&'a Ident> {
    let mut out: Vec<&Ident> = Vec::new();
    for decl in decls {
        for field in decl
            .by
            .iter()
            .chain(decl.sort.iter())
            .chain(decl.include.iter())
        {
            if !out.contains(&field) {
                out.push(field);
            }
        }
    }
    out
}

/// The declared type of a named field. Callers only pass idents that [`parse`]
/// already validated against `fields`, so the lookup can't miss.
pub fn field_type<'a>(fields: &'a FieldsNamed, ident: &Ident) -> &'a Type {
    &fields
        .named
        .iter()
        .find(|f| f.ident.as_ref() == Some(ident))
        .expect("index field validated by parse")
        .ty
}

/// Render one `IndexEntry { name, bucket, sort }` literal for `decl`. `value_for`
/// maps a field ident to the expression yielding that field's value in the
/// caller's context — `self.field` in the `Storage` derive (real value), or a
/// getter like `self.field()` / `self.field().load()` in the read model and the
/// in-place setters. Centralizing the literal keeps every site's bucket/sort
/// encoding identical, so a write and a later diff can't disagree.
pub fn index_entry(decl: &IndexDecl, value_for: &impl Fn(&Ident) -> TokenStream) -> TokenStream {
    let name_id = decl.id;
    // One bucket segment per `by` field, in declared order (a single-field index
    // is just the one-element case).
    let bucket = decl.by.iter().map(|field| {
        let val = value_for(field);
        quote! { stdlib::IndexKey::index_key(&#val) }
    });
    let sort = match &decl.sort {
        Some(field) => {
            let sort_val = value_for(field);
            // The sort field's order-preserving codec element, pre-encoded; it
            // leads the `(sort, pk)` member tuple so the bucket scans in value order.
            quote! { Some(stdlib::KeyElement::encode(&#sort_val)) }
        }
        None => quote! { None },
    };
    // Covering projection: the `include=` fields' codec elements CONCATENATED as the
    // leaf VALUE (`None` for a non-covering index → a void leaf). Each `encode` is a
    // self-delimiting `KeyElement` (not the lossy bucket `IndexKey`), so the reader
    // decodes them back field-by-field in order — no tuple wrapper (keycodec has no
    // 1-tuple decode, and the projection is an opaque VALUE, never a walked path
    // element). A non-`KeyElement` include field is a compile error here.
    let projection = if decl.include.is_empty() {
        quote! { None }
    } else {
        let parts = decl.include.iter().map(|field| {
            let val = value_for(field);
            quote! { __proj.extend_from_slice(&stdlib::KeyElement::encode(&#val)); }
        });
        quote! {{
            let mut __proj = alloc::vec::Vec::new();
            #(#parts)*
            Some(__proj)
        }}
    };
    quote! {
        stdlib::IndexEntry {
            name_id: #name_id,
            bucket: alloc::vec![#(#bucket),*],
            sort: #sort,
            projection: #projection,
        }
    }
}
