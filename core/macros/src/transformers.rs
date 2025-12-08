use anyhow::{anyhow, bail};
use heck::ToUpperCamelCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Ident, PathArguments, Type as SynType, TypePath};
use wit_parser::{Handle, Resolve, Type as WitType, TypeDefKind};

pub fn wit_type_to_unwrap_expr(
    resolve: &Resolve,
    ty: &WitType,
    value: TokenStream,
) -> anyhow::Result<TokenStream> {
    match ty {
        WitType::U64 => Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_u64(&#value) }),
        WitType::S64 => Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_s64(&#value) }),
        WitType::Bool => Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_bool(&#value) }),
        WitType::String => {
            Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_string(&#value).into_owned() })
        }
        WitType::Id(id) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => wit_type_to_unwrap_expr(resolve, inner, value),
                TypeDefKind::Option(inner) => {
                    let inner_unwrap =
                        wit_type_to_unwrap_expr(resolve, inner, quote! { v.into_owned() })?;
                    Ok(
                        quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_option(&#value).map(|v| #inner_unwrap) },
                    )
                }
                TypeDefKind::List(inner) => {
                    let inner_unwrap =
                        wit_type_to_unwrap_expr(resolve, inner, quote! { v.into_owned() })?;
                    Ok(
                        quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_list(&#value).map(|v| #inner_unwrap).collect() },
                    )
                }
                TypeDefKind::Result(result) => {
                    let ok_unwrap = match result.ok {
                        Some(ok_ty) => {
                            let unwrap_expr = wit_type_to_unwrap_expr(
                                resolve,
                                &ok_ty,
                                quote! { v.unwrap().into_owned() },
                            )?;
                            quote! {
                                |v| #unwrap_expr
                            }
                        }
                        None => quote! { |_| () },
                    };
                    let err_unwrap = match result.err {
                        Some(err_ty) => {
                            let unwrap_expr = wit_type_to_unwrap_expr(
                                resolve,
                                &err_ty,
                                quote! { e.unwrap().into_owned() },
                            )?;
                            quote! {
                                |e| #unwrap_expr
                            }
                        }
                        None => quote! { |_| () },
                    };
                    Ok(quote! {
                        stdlib::wasm_wave::wasm::WasmValue::unwrap_result(&#value).map(#ok_unwrap).map_err(#err_unwrap)
                    })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    Ok(quote! { #value.into() })
                }
                _ => bail!("Unsupported WIT type definition kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}

pub fn wit_type_to_rust_type(
    resolve: &Resolve,
    ty: &WitType,
    use_str: bool,
) -> anyhow::Result<TokenStream> {
    match (ty, use_str) {
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

pub fn syn_type_to_unwrap_expr(ty: &SynType, value: TokenStream) -> syn::Result<TokenStream> {
    if let SynType::Path(TypePath { qself: None, path }) = ty
        && let Some(segment) = &path.segments.last()
        && segment.arguments == PathArguments::None
    {
        let ident = segment.ident.to_string();
        match ident.as_str() {
            "u64" => {
                return Ok(
                    quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_u64(&#value.into_owned()) },
                );
            }
            "i64" => {
                return Ok(
                    quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_s64(&#value.into_owned()) },
                );
            }
            "bool" => {
                return Ok(
                    quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_bool(&#value.into_owned()) },
                );
            }
            "String" => {
                return Ok(
                    quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_string(&#value.into_owned()).into_owned() },
                );
            }
            _ => {}
        }
    }
    Ok(quote! { #value.into_owned().into() })
}
