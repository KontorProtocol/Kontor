use crate::transformers;

use anyhow::Result;
use heck::{ToKebabCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use wit_parser::{Enum, Function, Record, Resolve, Type, TypeDefKind, Variant};

pub fn generate_functions(
    resolve: &Resolve,
    test: bool,
    export: &Function,
    height: i64,
    tx_index: i64,
) -> Result<TokenStream> {
    let fn_name = Ident::new(&export.name.to_snake_case(), Span::call_site());
    let mut params = export
        .params
        .iter()
        .map(|(name, ty)| {
            let param_name = Ident::new(&name.to_snake_case(), Span::call_site());
            let param_ty = transformers::wit_type_to_rust_type(resolve, ty, true)?;
            Ok(quote! { #param_name: #param_ty })
        })
        .collect::<Result<Vec<_>>>()?;

    let (_, ctx_type) = export.params.first().unwrap();
    let ctx_type_name = transformers::wit_type_to_rust_type(resolve, ctx_type, false)?;
    let is_proc_context = ctx_type_name.to_string() == quote! { &context::ProcContext }.to_string();

    if test {
        let runtime_name = Ident::new("runtime", Span::call_site());
        let runtime_ty = quote! { &Runtime };
        params[0] = quote! { #runtime_name: #runtime_ty};
        if is_proc_context {
            let signer_name = Ident::new("signer", Span::call_site());
            let signer_ty = quote! { &str };
            params.insert(1, quote! { #signer_name: #signer_ty });
        }
    }

    let ret_ty = match &export.result {
        Some(ty) => transformers::wit_type_to_rust_type(resolve, ty, false)?,
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
                        TypeDefKind::Option(inner) => transformers::wit_type_to_rust_type(resolve, &inner, false)?,
                        _ => unreachable!(),
                    };
                    quote! {
                        match #param_name {
                            Some(val) => stdlib::wasm_wave::to_string(&stdlib::wasm_wave::value::Value::from(val)).unwrap(),
                            None => "null".to_string(),
                        }
                    }
                }
                _ => quote! {
                    stdlib::wasm_wave::to_string(&stdlib::wasm_wave::value::Value::from(#param_name)).unwrap()
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
            let wave_ty = transformers::wit_type_to_wave_type(resolve, ty)?;
            let unwrap_expr = transformers::wit_type_to_unwrap_expr(resolve, ty)?;
            quote! {
                stdlib::wasm_wave::from_str::<stdlib::wasm_wave::value::Value>(&#wave_ty, &ret).unwrap().#unwrap_expr
            }
        }
        None => quote! { () },
    };

    let ctx_signer = if is_proc_context {
        if test {
            quote! { Some(signer) }
        } else {
            quote! { Some(&ctx.signer()) }
        }
    } else {
        quote! { None }
    };

    let execute = if test {
        quote! { runtime.execute }
    } else {
        quote! { foreign::call }
    };

    let fn_keywords = if test {
        quote! { pub async fn }
    } else {
        quote! { pub fn }
    };

    let awaited = if test {
        quote! { .await.unwrap() }
    } else {
        quote! {}
    };

    Ok(quote! {
        #[allow(clippy::unused_unit)]
        #fn_keywords #fn_name(#(#params),*) -> #ret_ty {
            let expr = #expr;
            let ret = #execute(
                #ctx_signer,
                &ContractAddress {
                    name: CONTRACT_NAME.to_string(),
                    height: #height,
                    tx_index: #tx_index,
                },
                expr.as_str(),
            )#awaited;
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
            let field_ty = transformers::wit_type_to_rust_type(resolve, &field.ty, false)?;
            Ok(quote! { pub #field_name: #field_ty })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        #[derive(Debug, Clone, Wavey, PartialEq, Eq)]
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
                    let ty_name = transformers::wit_type_to_rust_type(resolve, ty, false)?;
                    Ok(quote! { #variant_name(#ty_name) })
                }
                None => Ok(quote! { #variant_name }),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        #[derive(Debug, Clone, Wavey, PartialEq, Eq)]
        pub enum #enum_name {
            #(#variants),*
        }
    })
}
