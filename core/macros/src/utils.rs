use anyhow::{anyhow, bail};
use heck::ToUpperCamelCase;
use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use quote::quote;
use syn::PathArguments;
use syn::{DataEnum, Error, FieldsNamed, Ident, Result, Variant};
use wit_parser::{Handle, Resolve, Type as WitType, TypeDefKind};

/// Reject a storage struct with more fields than the interned path-id space can
/// hold. A field's id is its declaration index (`u8`) and an indexed-map field's
/// `#idx` sibling is `id | 0x80`, so field ids must stay in `0..128` to never
/// collide with the marker space (128..=255). 128 fields is far beyond any real
/// storage struct. Shared by the `Model` (read) and `Store` (write) derives so the
/// invariant lives in one place.
pub fn check_struct_field_count(fields: &FieldsNamed, span: Span) -> Result<()> {
    if fields.named.len() > 128 {
        return Err(Error::new(
            span,
            "storage struct may not exceed 128 fields (interned path-id space)",
        ));
    }
    Ok(())
}

/// Number an enum's variants by declaration order — the SINGLE source for each
/// variant's interned discriminant id (`u8`), so the read (`Model`) and write
/// (`Store`) derives can't assign different ids to the same variant. Caps at 256
/// (the `u8` id space) rather than silently wrapping.
pub fn numbered_variants(data_enum: &DataEnum, span: Span) -> Result<Vec<(u8, &Variant)>> {
    if data_enum.variants.len() > 256 {
        return Err(Error::new(
            span,
            "storage enum may not exceed 256 variants (interned id space)",
        ));
    }
    Ok(data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| (i as u8, v))
        .collect())
}

pub fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Option"
                    && matches!(segment.arguments, PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_result_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Result"
                    && matches!(segment.arguments, syn::PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_primitive_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last().map(|s| s.ident.to_string());
        let generic_segment = type_path
            .path
            .segments
            .last()
            .to_token_stream()
            .to_string()
            .replace(" ", "");
        matches!(
            segment.as_deref(),
            Some(
                "u32"
                    | "i32"
                    | "u64"
                    | "i64"
                    | "String"
                    | "bool"
                    | "ContractAddress"
                    | "HolderRef"
                    | "Holder"
                    | "Integer"
                    | "Decimal"
            )
        ) || ["Vec<u8>", "Vec::<u8>"].contains(&generic_segment.as_str())
    } else {
        false
    }
}

/// True if `ty`'s path ends in a segment named `name` (e.g. `Map`, `Deque`),
/// ignoring any generic arguments.
fn last_segment_named(ty: &syn::Type, name: &str) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == name)
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_map_type(ty: &syn::Type) -> bool {
    last_segment_named(ty, "Map")
}

pub fn is_deque_type(ty: &syn::Type) -> bool {
    last_segment_named(ty, "Deque")
}

pub fn wit_type_to_rust_type(
    resolve: &Resolve,
    ty: &WitType,
    use_str: bool,
) -> anyhow::Result<TokenStream> {
    match (ty, use_str) {
        (WitType::U8, _) => Ok(quote! { u8 }),
        (WitType::U32, _) => Ok(quote! { u32 }),
        (WitType::S32, _) => Ok(quote! { i32 }),
        (WitType::U64, _) => Ok(quote! { u64 }),
        (WitType::S64, _) => Ok(quote! { i64 }),
        (WitType::Bool, _) => Ok(quote! { bool }),
        (WitType::String, false) => Ok(quote! { String }),
        (WitType::String, true) => Ok(quote! { &str }),
        (WitType::Id(id), _) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => Ok(wit_type_to_rust_type(resolve, inner, use_str)?),
                TypeDefKind::Option(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Option<#inner_ty> })
                }
                TypeDefKind::List(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Vec<#inner_ty> })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    let err_ty = match result.err {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    Ok(quote! { Result<#ok_ty, #err_ty> })
                }
                TypeDefKind::Handle(Handle::Borrow(resource_id)) => {
                    let resource_def = &resolve.types[*resource_id];
                    let resource_name = resource_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed resource types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&resource_name, Span::call_site());
                    Ok(quote! { &context::#ident })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    let name = ty_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&name, Span::call_site());
                    Ok(quote! { #ident })
                }
                _ => bail!("Unsupported type definition kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}
