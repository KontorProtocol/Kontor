use anyhow::{Result, anyhow, bail};
use heck::{ToKebabCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use wit_parser::{Enum, Function, Handle, Record, Resolve, Type, TypeDefKind, Variant};

fn type_name(resolve: &Resolve, ty: &Type) -> Result<TokenStream> {
    match ty {
        Type::U64 => Ok(quote! { u64 }),
        Type::S64 => Ok(quote! { i64 }),
        Type::String => Ok(quote! { String }),
        Type::Id(id) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => Ok(type_name(resolve, inner)?),
                TypeDefKind::Option(inner) => {
                    let inner_ty = type_name(resolve, inner)?;
                    Ok(quote! { Option<#inner_ty> })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => type_name(resolve, &ty)?,
                        None => quote! { () },
                    };
                    let err_ty = match result.err {
                        Some(ty) => type_name(resolve, &ty)?,
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

fn value_type_for(resolve: &Resolve, ty: &Type) -> Result<TokenStream> {
    match ty {
        Type::U64 => Ok(quote! { wasm_wave::value::Type::U64 }),
        Type::S64 => Ok(quote! { wasm_wave::value::Type::S64 }),
        Type::String => Ok(quote! { wasm_wave::value::Type::String }),
        Type::Id(id) => {
            let ty_def = &resolve.types[*id];

            match &ty_def.kind {
                TypeDefKind::Type(inner) => Ok(value_type_for(resolve, inner)?),
                TypeDefKind::Option(inner) => {
                    let inner_ty = type_name(resolve, inner)?;
                    Ok(quote! { wasm_wave::value::Type::option(<#inner_ty>::wave_type()) })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => {
                            let value_type_ = value_type_for(resolve, &ty)?;
                            quote! { Some(#value_type_) }
                        }
                        None => {
                            quote! { None }
                        }
                    };
                    let err_ty = match result.err {
                        Some(ty) => {
                            let value_type_ = value_type_for(resolve, &ty)?;
                            quote! { Some(#value_type_) }
                        }
                        None => {
                            quote! { None }
                        }
                    };
                    Ok(quote! { wasm_wave::value::Type::result(#ok_ty, #err_ty) })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    let name = ty_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Unnamed return types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&name, Span::call_site());
                    Ok(quote! { <#ident>::wave_type() })
                }
                TypeDefKind::Handle(_) => {
                    bail!("Resource handles cannot be used as return types");
                }
                _ => bail!("Unsupported return type kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported return type: {:?}", ty),
    }
}

fn unwrap_expr_for_wit_type(ty: &Type, resolve: &Resolve) -> Result<TokenStream> {
    match ty {
        Type::U64 => Ok(quote! { unwrap_u64() }),
        Type::S64 => Ok(quote! { unwrap_s64() }),
        Type::String => Ok(quote! { unwrap_string().into_owned() }),
        Type::Id(id) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => unwrap_expr_for_wit_type(inner, resolve),
                TypeDefKind::Option(inner) => {
                    let inner_unwrap = unwrap_expr_for_wit_type(inner, resolve)?;
                    Ok(quote! { unwrap_option().map(|v| v.into_owned().#inner_unwrap) })
                }
                TypeDefKind::Result(result) => {
                    let ok_unwrap = match result.ok {
                        Some(ok_ty) => unwrap_expr_for_wit_type(&ok_ty, resolve)?,
                        None => quote! { into() },
                    };
                    let err_unwrap = match result.err {
                        Some(err_ty) => unwrap_expr_for_wit_type(&err_ty, resolve)?,
                        None => quote! { into() },
                    };
                    Ok(quote! {
                        unwrap_result().map(|v| v.unwrap().into_owned().#ok_unwrap).map_err(|e| e.unwrap().into_owned().#err_unwrap)
                    })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    Ok(quote! { into() })
                }
                _ => bail!("Unsupported WIT type definition kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}

pub fn generate_functions(
    resolve: &Resolve,
    export: &Function,
    height: i64,
    tx_index: i64,
) -> Result<TokenStream> {
    let fn_name = Ident::new(&export.name.to_snake_case(), Span::call_site());
    let params = export
        .params
        .iter()
        .map(|(name, ty)| {
            let param_name = Ident::new(&name.to_snake_case(), Span::call_site());
            let param_ty = type_name(resolve, ty)?;
            Ok(quote! { #param_name: #param_ty })
        })
        .collect::<Result<Vec<_>>>()?;

    let ret_ty = match &export.result {
        Some(ty) => type_name(resolve, ty)?,
        None => quote! { () },
    };

    let expr_parts = export
        .params
        .iter()
        .enumerate()
        .skip(1)
        .map(|(_i, (name, ty))| {
            let param_name = Ident::new(&name.to_snake_case(), Span::call_site());
            Ok(match ty {
                Type::Id(id) if matches!(resolve.types[*id].kind, TypeDefKind::Option(_)) => {
                    let _inner_ty = match resolve.types[*id].kind {
                        TypeDefKind::Option(inner) => type_name(resolve, &inner)?,
                        _ => unreachable!(),
                    };
                    quote! {
                        match #param_name {
                            Some(val) => wasm_wave::to_string(&wasm_wave::value::Value::from(val)).unwrap(),
                            None => "null".to_string(),
                        }
                    }
                }
                _ => quote! {
                    wasm_wave::to_string(&wasm_wave::value::Value::from(#param_name)).unwrap()
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let fn_name_kebab = fn_name.to_string().to_kebab_case();
    let expr = if expr_parts.is_empty() {
        quote! { format!("{}()", #fn_name_kebab) }
    } else {
        quote! { format!("{}({})", #fn_name_kebab, [#(#expr_parts),*].join(", ")) }
    };

    let ret_expr = match &export.result {
        Some(ty) => {
            let value_ty = value_type_for(resolve, ty)?;
            let unwrap_expr = unwrap_expr_for_wit_type(ty, resolve)?;
            quote! {
                wasm_wave::from_str::<wasm_wave::value::Value>(&#value_ty, &ret).unwrap().#unwrap_expr
            }
        }
        None => quote! { () },
    };

    let (_, ctx_type) = export.params.first().unwrap();
    let ctx_type_name = type_name(resolve, ctx_type)?;
    let is_proc_context = ctx_type_name.to_string() == quote! { &context::ProcContext }.to_string();
    let ctx_signer = if is_proc_context {
        quote! { Some(&ctx.signer()) }
    } else {
        quote! { None }
    };

    Ok(quote! {
        pub fn #fn_name(#(#params),*) -> #ret_ty {
            let expr = #expr;
            let ret = foreign::call(
                &foreign::ContractAddress {
                    name: CONTRACT_NAME.to_string(),
                    height: #height,
                    tx_index: #tx_index,
                },
                #ctx_signer,
                expr.as_str(),
            );
            #ret_expr
        }
    })
}

pub fn print_typedef_record(resolve: &Resolve, name: &str, record: &Record) -> Result<TokenStream> {
    let struct_name = Ident::new(&name.to_upper_camel_case(), Span::call_site());
    let fields = record
        .fields
        .iter()
        .map(|field| {
            let field_name = Ident::new(&field.name.to_snake_case(), Span::call_site());
            let field_ty = type_name(resolve, &field.ty)?;
            Ok(quote! { pub #field_name: #field_ty })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        #[derive(Debug, Clone, Wavey)]
        pub struct #struct_name {
            #(#fields),*
        }
    })
}

pub fn print_typedef_enum(name: &str, enum_: &Enum) -> Result<TokenStream> {
    let enum_name = Ident::new(&name.to_upper_camel_case(), Span::call_site());
    let variants = enum_.cases.iter().map(|case| {
        let variant_name = Ident::new(&case.name.to_upper_camel_case(), Span::call_site());
        quote! { #variant_name }
    });

    Ok(quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum #enum_name {
            #(#variants),*
        }
    })
}

pub fn print_typedef_variant(
    resolve: &Resolve,
    name: &str,
    variant: &Variant,
) -> Result<TokenStream> {
    let enum_name = Ident::new(&name.to_upper_camel_case(), Span::call_site());
    let variants = variant
        .cases
        .iter()
        .map(|case| {
            let variant_name = Ident::new(&case.name.to_upper_camel_case(), Span::call_site());
            match &case.ty {
                Some(ty) => {
                    let ty_name = type_name(resolve, ty)?;
                    Ok(quote! { #variant_name(#ty_name) })
                }
                None => Ok(quote! { #variant_name }),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        #[derive(Debug, Clone, Wavey)]
        pub enum #enum_name {
            #(#variants),*
        }
    })
}
