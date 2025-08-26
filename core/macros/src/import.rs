use crate::transformers;

use anyhow::Result;
use heck::{ToKebabCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use wit_parser::{Enum, Function, Record, Resolve, Type, TypeDefKind, Variant};

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
            let param_ty = transformers::wit_type_to_rust_type(resolve, ty)?;
            Ok(quote! { #param_name: #param_ty })
        })
        .collect::<Result<Vec<_>>>()?;

    let ret_ty = match &export.result {
        Some(ty) => transformers::wit_type_to_rust_type(resolve, ty)?,
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
                        TypeDefKind::Option(inner) => transformers::wit_type_to_rust_type(resolve, &inner)?,
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
            let wave_ty = transformers::wit_type_to_wave_type(resolve, ty)?;
            let expr = transformers::wit_type_to_unwrap_expr(resolve, ty)?;
            quote! {
                wasm_wave::from_str::<wasm_wave::value::Value>(&#wave_ty, &ret).unwrap().#expr
            }
        }
        None => quote! { () },
    };

    let (_, ctx_type) = export.params.first().unwrap();
    let ctx_type_name = transformers::wit_type_to_rust_type(resolve, ctx_type)?;
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
            let field_ty = transformers::wit_type_to_rust_type(resolve, &field.ty)?;
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
                    let ty_name = transformers::wit_type_to_rust_type(resolve, ty)?;
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
