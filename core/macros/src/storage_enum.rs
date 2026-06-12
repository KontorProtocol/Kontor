use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, Fields, Ident, Result};

/// One variant of a storage enum, in the form the generator needs: the Rust
/// variant ident, its index-bucket key (lowercased case name), and the match
/// pattern that binds it while ignoring any payload.
pub struct VariantSpec {
    pub ident: Ident,
    pub key: String,
    pub pattern: TokenStream,
}

/// Generate the index machinery for a storage enum:
///   - `<E>Kind`: a payload-free mirror of the variants, so a case can be named
///     (`<E>Kind::Failed`) without constructing its payload — the thing a
///     `where_<field>` lookup needs for a data-carrying variant.
///   - `From<&E>/From<E> for <E>Kind`: discriminant extraction (also lets a unit
///     enum's full value be passed where an `Into<<E>Kind>` is expected).
///   - `IndexKey` for both: the bucket key is the DISCRIMINANT name (lowercased),
///     never the payload, so `Failed(a)` and `Failed(b)` share bucket `"failed"`.
///
/// All four are NEW names, so this is safe to emit for EVERY storage enum,
/// including built-ins like `HolderRef` (no clash with their existing
/// `Display`/`FromStr`). It deliberately does NOT emit `Display`: that's the one
/// piece that would collide with the built-ins, and the index path keys through
/// `IndexKey`, not `Display`, so it isn't needed. Driven from the `Storage`
/// derive, whose `additional_derives` entry already lands on every WIT enum.
pub fn generate_impls(name: &Ident, variants: &[VariantSpec]) -> TokenStream {
    let kind_name = Ident::new(&format!("{name}Kind"), name.span());

    let kind_variants = variants.iter().map(|v| &v.ident);
    let from_arms = variants.iter().map(|v| {
        let pat = &v.pattern;
        let vid = &v.ident;
        quote! { #pat => #kind_name::#vid }
    });
    let key_arms = variants.iter().map(|v| {
        let vid = &v.ident;
        let key = &v.key;
        quote! { #kind_name::#vid => #key }
    });

    quote! {
        #[automatically_derived]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum #kind_name {
            #(#kind_variants,)*
        }

        #[automatically_derived]
        impl #kind_name {
            /// The discriminant's index-bucket key (lowercased case name).
            pub fn index_key_str(&self) -> &'static str {
                match self {
                    #(#key_arms,)*
                }
            }
        }

        #[automatically_derived]
        impl core::convert::From<&#name> for #kind_name {
            fn from(value: &#name) -> Self {
                match value {
                    #(#from_arms,)*
                }
            }
        }

        #[automatically_derived]
        impl core::convert::From<#name> for #kind_name {
            fn from(value: #name) -> Self {
                <#kind_name as core::convert::From<&#name>>::from(&value)
            }
        }

        #[automatically_derived]
        impl stdlib::IndexKey for #kind_name {
            fn index_key(&self) -> alloc::borrow::Cow<'static, str> {
                // The discriminant is `&'static str` — borrow it, no allocation.
                alloc::borrow::Cow::Borrowed(self.index_key_str())
            }
        }

        #[automatically_derived]
        impl stdlib::IndexKey for #name {
            fn index_key(&self) -> alloc::borrow::Cow<'static, str> {
                stdlib::IndexKey::index_key(&#kind_name::from(self))
            }
        }
    }
}

/// Entry point for the `Storage` derive's enum branch — variants come from the
/// `syn` enum.
pub fn generate(data_enum: &DataEnum, name: &Ident) -> Result<TokenStream> {
    let variants: Vec<VariantSpec> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let ident = variant.ident.clone();
            let key = ident.to_string().to_lowercase();
            // Match the variant while ignoring any payload — the Kind is unit-only.
            let pattern = match &variant.fields {
                Fields::Unit => quote! { #name::#ident },
                Fields::Unnamed(_) => quote! { #name::#ident(..) },
                Fields::Named(_) => quote! { #name::#ident { .. } },
            };
            VariantSpec {
                ident,
                key,
                pattern,
            }
        })
        .collect();

    Ok(generate_impls(name, &variants))
}
