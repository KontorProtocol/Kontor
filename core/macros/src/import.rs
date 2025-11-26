use std::{fs, panic};

use crate::transformers;

use anyhow::Result;
use darling::FromMeta;
use heck::{ToKebabCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use wit_parser::{
    Enum, Function, Record, Resolve, Type, TypeDefKind, Variant, WorldItem, WorldKey,
};

#[derive(FromMeta)]
pub struct Config {
    name: String,
    mod_name: Option<String>,
    height: u64,
    tx_index: u64,
    path: String,
    public: Option<bool>,
    internal: Option<bool>,
}

pub fn generate(config: Config, test: bool) -> TokenStream {
    let name = config.name;
    let module_name =
        Ident::from_string(&config.mod_name.unwrap_or(name.clone().to_snake_case())).unwrap();
    let height = config.height;
    let tx_index = config.tx_index;
    let path = config.path;
    let public = config.public.unwrap_or_default();
    let internal = config.internal.unwrap_or_default();

    import(
        path,
        module_name,
        "root".to_string(),
        Some((&name, height, tx_index)),
        test,
        public,
        internal,
    )
}

pub fn import(
    mut path: String,
    module_name: Ident,
    world_name: String,
    contract_id: Option<(&str, u64, u64)>,
    test: bool,
    public: bool,
    internal: bool,
) -> TokenStream {
    if internal {
        let mod_dir = env!("CARGO_MANIFEST_DIR");
        path = [mod_dir, &path].join("/");
    }
    assert!(fs::metadata(&path).is_ok());
    let mut resolve = Resolve::new();
    resolve.push_dir(&path).unwrap();

    let (_world_id, world) = resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == world_name)
        .unwrap();

    let exports = world
        .exports
        .iter()
        .filter_map(|e| match e {
            (WorldKey::Name(name), WorldItem::Function(f))
                if !["init"].contains(&name.as_str()) =>
            {
                Some(f)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut type_streams = Vec::new();
    for (_id, def) in resolve.types.iter().filter(|(_, def)| {
        if let Some(name) = def.name.as_deref() {
            ![
                "transaction",
                "contract-address",
                "view-context",
                "view-storage",
                "fall-context",
                "proc-context",
                "proc-storage",
                "core-context",
                "signer",
                "error",
                "keys",
                "integer",
                "decimal",
            ]
            .contains(&name)
        } else {
            false
        }
    }) {
        let name = def.name.as_deref().expect("Filtered types have names");
        let stream = match &def.kind {
            TypeDefKind::Record(record) => print_typedef_record(&resolve, name, record),
            TypeDefKind::Enum(enum_) => print_typedef_enum(name, enum_),
            TypeDefKind::Variant(variant) => print_typedef_variant(&resolve, name, variant),
            _ => panic!("Unsupported type definition kind: {:?}", def.kind),
        }
        .expect("Failed to generate type");
        type_streams.push(stream);
    }

    let mut func_streams = Vec::new();
    for export in exports {
        func_streams.push(
            generate_functions(&resolve, test, export, contract_id)
                .expect("Function didn't generate"),
        )
    }

    let supers = if test {
        quote! {
            use super::ContractAddress;
            use super::Error;
            use super::AnyhowError;
            use super::Runtime;
            use super::Signer;
            use super::{ Decimal, Integer };
        }
    } else {
        quote! {
            use super::context;
            use super::foreign;
            use super::foreign::ContractAddress;
            use super::error::Error;
            use super::numbers::{ Decimal, Integer };
        }
    };

    let mod_keyword = if public {
        quote! { pub mod }
    } else {
        quote! { mod }
    };

    quote! {
        #mod_keyword #module_name {
            #supers

            #(#type_streams)*
            #(#func_streams)*
        }
    }
}

pub fn generate_functions(
    resolve: &Resolve,
    test: bool,
    export: &Function,
    contract_id: Option<(&str, u64, u64)>,
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
    let is_core_context = ctx_type_name.to_string() == quote! { &context::CoreContext }.to_string();

    if test {
        let runtime_name = Ident::new("runtime", Span::call_site());
        let runtime_ty = quote! { &mut Runtime };
        params[0] = quote! { #runtime_name: #runtime_ty};
        if is_proc_context || is_core_context {
            let signer_name = Ident::new("signer", Span::call_site());
            let signer_ty = quote! { &Signer };
            params.insert(1, quote! { #signer_name: #signer_ty });
        }
    } else if is_proc_context || is_core_context {
        let signer_name = Ident::new("signer", Span::call_site());
        let signer_ty = quote! { foreign::Signer };
        params[0] = quote! { #signer_name: #signer_ty };
    } else {
        params.remove(0);
    }

    let contract_arg = if let Some((name, height, tx_index)) = contract_id {
        quote! {
            &ContractAddress {
                name: #name.to_string(),
                height: #height,
                tx_index: #tx_index,
            }
        }
    } else {
        params.insert(
            if test { 1 } else { 0 },
            quote! { contract_address_: &ContractAddress },
        );
        quote! { contract_address_ }
    };

    let mut ret_ty = match &export.result {
        Some(ty) => transformers::wit_type_to_rust_type(resolve, ty, false)?,
        None => quote! { () },
    };

    if test {
        ret_ty = quote! { Result<#ret_ty, AnyhowError> }
    }

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

    let mut ret_expr = match &export.result {
        Some(ty) => {
            let wave_ty = transformers::wit_type_to_wave_type(resolve, ty)?;
            transformers::wit_type_to_unwrap_expr(
                resolve,
                ty,
                quote! {
                    stdlib::wasm_wave::from_str::<stdlib::wasm_wave::value::Value>(&#wave_ty, &ret).unwrap()
                },
            )?
        }
        None => quote! { () },
    };
    if test {
        ret_expr = quote! { Ok(#ret_expr) };
    }

    let ctx_signer = if is_proc_context || is_core_context {
        quote! { Some(signer) }
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
        quote! { .await? }
    } else {
        quote! {}
    };

    Ok(quote! {
        #[allow(clippy::unused_unit)]
        #fn_keywords #fn_name(#(#params),*) -> #ret_ty {
            let expr = #expr;
            let ret = #execute(
                #ctx_signer,
                #contract_arg,
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
        #[derive(Debug, Clone, stdlib::Wavey, PartialEq, Eq)]
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
        #[derive(Debug, Clone, stdlib::Wavey, PartialEq, Eq)]
        pub enum #enum_name {
            #(#variants),*
        }
    })
}
