use std::{panic, path::Path};

use anyhow::Result;
use darling::FromMeta;
use heck::{ToKebabCase, ToSnakeCase};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::Ident;

use wit_parser::{Function, Resolve, Type, TypeDefKind, TypeOwner, WorldItem, WorldKey};

use crate::utils;

/// The interfaces `contract!` remaps onto `built-in-types`; imported worlds
/// must alias the same family.
const REMAPPED_BUILT_INS: &[(&str, &str)] = &[
    ("file-registry-types", "built_in_types::file_registry_types"),
    ("error", "built_in_types::error"),
    ("numbers", "built_in_types::numbers"),
    ("numbers-types", "built_in_types::numbers_types"),
    ("context-types", "built_in_types::context_types"),
    ("context", "built_in_types::context"),
];

#[derive(FromMeta)]
pub struct Config {
    name: String,
    mod_name: Option<String>,
    height: u64,
    tx_index: u32,
    path: String,
    public: Option<bool>,
}

pub fn generate(config: Config, test: bool) -> TokenStream {
    let name = config.name;
    let module_name =
        Ident::from_string(&config.mod_name.unwrap_or(name.clone().to_snake_case())).unwrap();
    let height = config.height;
    let tx_index = config.tx_index;
    let path = config.path;
    let public = config.public.unwrap_or_default();

    import(
        path,
        module_name,
        "root".to_string(),
        Some((&name, height, tx_index)),
        test,
        public,
    )
}

pub fn import(
    path: String,
    module_name: Ident,
    world_name: String,
    contract_id: Option<(&str, u64, u32)>,
    test: bool,
    public: bool,
) -> TokenStream {
    let abs_path = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("Failed to canonicalize path")
        .join(&path);
    if !abs_path.exists() {
        panic!("Path does not exist: {}", abs_path.display());
    }
    let mut resolve = Resolve::new();
    resolve
        .push_dir(abs_path.to_string_lossy().to_string())
        .unwrap();

    let (_world_id, world) = resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == world_name)
        .unwrap();

    // Same validation as contract! — the no-resources-in-signatures rule is
    // what lets the shims below treat every signature type as plain data.
    let validation = wit_validator::Validator::validate_resolve(&resolve);
    if validation.has_errors() {
        let messages: Vec<String> = validation
            .errors
            .iter()
            .map(|e| format!("  - {e}"))
            .collect();
        panic!(
            "WIT validation failed for imported contract at {}:\n{}",
            abs_path.display(),
            messages.join("\n")
        );
    }

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

    let mut with_entries = Vec::new();
    for (_key, item) in world.imports.iter() {
        let WorldItem::Interface { id, .. } = item else {
            continue;
        };
        let iface = &resolve.interfaces[*id];
        let Some(pkg_id) = iface.package else {
            continue;
        };
        let pkg_name = &resolve.packages[pkg_id].name;
        if pkg_name.namespace != "kontor" || pkg_name.name != "built-in" {
            continue;
        }
        let Some(iface_name) = iface.name.as_deref() else {
            continue;
        };
        if let Some((_, module)) = REMAPPED_BUILT_INS.iter().find(|(n, _)| *n == iface_name) {
            with_entries.push((
                format!("kontor:built-in/{iface_name}"),
                wit_bindgen_rust::WithOption::Path(module.to_string()),
            ));
        } else {
            // Un-remapped built-ins regenerate as dead stubs. Their resources
            // can't reach the shims (validator rule above); a plain data type
            // here would generate as a twin family, so reject it.
            let owns_data_types = resolve.types.iter().any(|(_, td)| {
                td.name.is_some()
                    && td.owner == TypeOwner::Interface(*id)
                    && !matches!(td.kind, TypeDefKind::Type(_) | TypeDefKind::Resource)
            });
            if owns_data_types {
                panic!(
                    "built-in interface `{iface_name}` owns data type definitions but \
                     has no `with:` remap in macros/src/import.rs REMAPPED_BUILT_INS — \
                     add it (generated once in built-in-types) or its types will be \
                     generated twice"
                );
            }
        }
    }

    // wit-bindgen's library backend, driven directly (its parser is a
    // different version than `resolve`'s, hence the second parse) so the
    // output can be doctored: exports cleared (we call this world, we don't
    // implement it) and the component-type section static filtered below (it
    // would merge this world into the contract's chain-visible WIT).
    let mut gen_resolve = wit_bindgen_core::wit_parser::Resolve::new();
    gen_resolve
        .push_dir(abs_path.to_string_lossy().to_string())
        .expect("imported wit dir parses under wit-bindgen's parser");
    let gen_world_id = gen_resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == world_name)
        .map(|(id, _)| id)
        .expect("imported world exists under wit-bindgen's parser");
    gen_resolve.worlds[gen_world_id].exports = Default::default();

    let opts = wit_bindgen_rust::Opts {
        generate_all: true,
        generate_unused_types: true,
        additional_derive_attributes: vec![
            "stdlib::Wavey".to_string(),
            "PartialEq".to_string(),
            "Eq".to_string(),
        ],
        with: with_entries,
        runtime_path: Some("stdlib::wit_bindgen::rt".to_string()),
        disable_custom_section_link_helpers: true,
        ..Default::default()
    };
    let mut generator = opts.build();
    let mut files = wit_bindgen_core::Files::default();
    wit_bindgen_core::WorldGenerator::generate(
        &mut generator,
        &mut gen_resolve,
        gen_world_id,
        &mut files,
    )
    .expect("wit-bindgen generation for the imported world");
    let (_name, contents) = files.iter().next().expect("one generated bindings file");
    let generated =
        syn::parse_file(std::str::from_utf8(contents).expect("generated bindings are utf-8"))
            .expect("generated bindings parse");
    let items_before = generated.items.len();
    let bindings_items: Vec<syn::Item> = generated
        .items
        .into_iter()
        .filter(|item| match item {
            syn::Item::Static(item_static) => !item_static.attrs.iter().any(|attr| {
                quote!(#attr)
                    .to_string()
                    .contains("component-type:wit-bindgen")
            }),
            _ => true,
        })
        .collect();
    // If a wit-bindgen bump renames the section, filtering nothing would be a
    // silent regression — fail instead.
    assert_eq!(
        items_before - bindings_items.len(),
        1,
        "expected to filter exactly one component-type custom-section static \
         from wit-bindgen's output — its section naming has changed; update \
         the filter in macros/src/import.rs"
    );

    let mut func_streams = Vec::new();
    for export in exports.iter() {
        func_streams.push(
            generate_functions(&resolve, test, public, export, contract_id)
                .expect("Function didn't generate"),
        )
    }

    let mut wave_func_streams = Vec::new();
    for export in exports.iter() {
        wave_func_streams
            .push(generate_wave_functions(&resolve, export).expect("Wave function didn't generate"))
    }

    let typed_call_import = if test && !public {
        quote! { use super::TypedCall; }
    } else {
        quote! {}
    };

    let supers = if test {
        quote! {
            use super::ContractAddress;
            use super::HolderRef;
            use super::RawFileDescriptor;
            use super::Error;
            use super::AnyhowError;
            use super::Runtime;
            use super::Signer;
            use super::{ Decimal, Integer };
            #typed_call_import
        }
    } else {
        quote! {
            use super::context;
            use super::context_types::HolderRef;
            use super::foreign;
            use super::context_types::ContractAddress;
            use super::file_registry_types::RawFileDescriptor;
            use super::error::Error;
            use super::numbers::{ Decimal, Integer };
        }
    };

    let mod_keywords = if public {
        quote! { pub mod }
    } else {
        quote! { mod }
    };

    let wave_mod_keywords = if test {
        quote! { pub mod }
    } else {
        quote! { mod }
    };

    quote! {
        // Generated glue may reference the guest context wrappers the
        // disallowed-types fence targets.
        #[allow(clippy::disallowed_types)]
        #mod_keywords #module_name {
            extern crate alloc;

            use alloc::{
                format,
                string::{String, ToString},
                vec::Vec,
            };

            mod __bindings {
                #(#bindings_items)*
            }
            // Explicit `use super::…` names below shadow same-named aliases
            // from this glob (same underlying types).
            pub use __bindings::*;

            #wave_mod_keywords wave {
                use super::*;

                #(#wave_func_streams)*
            }

            #supers

            #(#func_streams)*
        }
    }
}

fn make_params(resolve: &Resolve, export: &Function) -> Result<Vec<TokenStream>> {
    export
        .params
        .iter()
        .map(|param| {
            let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
            let param_ty = utils::wit_type_to_rust_type(resolve, &param.ty, true)?;
            Ok(quote! { #param_name: #param_ty })
        })
        .collect::<Result<Vec<_>>>()
}

fn make_call_expr(resolve: &Resolve, export: &Function) -> Result<TokenStream> {
    let fn_name = Ident::new(&export.name.to_snake_case(), Span::call_site());
    let expr_parts = export
        .params
        .iter()
        .enumerate()
        .skip(1)
        .map(|(_i, param)| {
            let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
            Ok(match &param.ty {
                Type::Id(id) if matches!(resolve.types[*id].kind, TypeDefKind::Option(_)) => {
                    let _inner_ty = match resolve.types[*id].kind {
                        TypeDefKind::Option(inner) => {
                            utils::wit_type_to_rust_type(resolve, &inner, false)?
                        }
                        _ => unreachable!(),
                    };
                    quote! {
                        match #param_name {
                            Some(val) => stdlib::to_wave_expr(val),
                            None => "null".to_string(),
                        }
                    }
                }
                Type::Id(id) if matches!(resolve.types[*id].kind, TypeDefKind::List(_)) => {
                    quote! {
                        {
                            let items: Vec<String> = #param_name.into_iter().map(|item| stdlib::to_wave_expr(item)).collect();
                            alloc::format!("[{}]", items.join(", "))
                        }
                    }
                }
                Type::Id(id)
                    if resolve.types[*id]
                        .name
                        .as_deref()
                        .is_some_and(|n| n == "holder-ref") =>
                {
                    quote! {
                        stdlib::to_wave_expr(Into::<HolderRef>::into(#param_name))
                    }
                }
                _ => quote! {
                    stdlib::to_wave_expr(#param_name)
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let fn_name_kebab = fn_name.to_string().to_kebab_case();
    Ok(if expr_parts.is_empty() {
        quote! { alloc::format!("{}()", #fn_name_kebab) }
    } else {
        quote! { alloc::format!("{}({})", #fn_name_kebab, [#(#expr_parts),*].join(", ")) }
    })
}

fn make_return_type(resolve: &Resolve, export: &Function) -> Result<TokenStream> {
    Ok(match &export.result {
        Some(ty) => utils::wit_type_to_rust_type(resolve, ty, false)?,
        None => quote! { () },
    })
}

fn make_return_expr(export: &Function) -> Result<TokenStream> {
    Ok(match &export.result {
        Some(_) => {
            quote! {
                stdlib::from_wave_expr(s)
            }
        }
        None => quote! {},
    })
}

fn make_fn_ident(export: &Function) -> Ident {
    Ident::new(&export.name.to_snake_case(), Span::call_site())
}

fn make_fn_name_call_expr(export: &Function) -> Ident {
    format_ident!("{}_call_expr", make_fn_ident(export))
}

fn make_fn_name_parse_return_expr(export: &Function) -> Ident {
    format_ident!("{}_parse_return_expr", make_fn_ident(export))
}

pub fn generate_wave_functions(resolve: &Resolve, export: &Function) -> Result<TokenStream> {
    let mut params = make_params(resolve, export)?;
    params.remove(0); // remove context parameter
    for (i, param) in export.params.iter().skip(1).enumerate() {
        if let Type::Id(id) = &param.ty {
            let ty_def = &resolve.types[*id];
            if ty_def.name.as_deref() == Some("holder-ref") {
                let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
                params[i] = quote! { #param_name: impl Into<HolderRef> };
            }
        }
    }
    let fn_name_call_expr = make_fn_name_call_expr(export);
    let call_expr_body = make_call_expr(resolve, export)?;
    let fn_name_parse_return_expr = make_fn_name_parse_return_expr(export);
    let ret_ty = make_return_type(resolve, export)?;
    let parse_return_expr_body = make_return_expr(export)?;
    Ok(quote! {
        pub fn #fn_name_call_expr(#(#params),*) -> String {
            #call_expr_body
        }

        pub fn #fn_name_parse_return_expr(s: &str) -> #ret_ty {
            #parse_return_expr_body
        }
    })
}

pub fn generate_functions(
    resolve: &Resolve,
    test: bool,
    public: bool,
    export: &Function,
    contract_id: Option<(&str, u64, u32)>,
) -> Result<TokenStream> {
    let fn_name = make_fn_ident(export);
    let mut params = make_params(resolve, export)?;

    if !public {
        for (i, param) in export.params.iter().enumerate() {
            if let Type::Id(id) = &param.ty {
                let ty_def = &resolve.types[*id];
                if ty_def.name.as_deref() == Some("holder-ref") {
                    let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
                    params[i] = quote! { #param_name: impl Into<HolderRef> };
                }
            }
        }
    }

    let call_expr_param_names = export
        .params
        .iter()
        .skip(1)
        .map(|param| {
            let name = Ident::new(&param.name.to_snake_case(), Span::call_site());
            quote! { #name }
        })
        .collect::<Vec<_>>();

    let ctx_param = export.params.first().unwrap();
    let ctx_type_name = utils::wit_type_to_rust_type(resolve, &ctx_param.ty, false)?;
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

    let mut ret_ty = make_return_type(resolve, export)?;

    if test {
        ret_ty = quote! { Result<#ret_ty, AnyhowError> }
    }

    let fn_name_call_expr = make_fn_name_call_expr(export);

    let fn_name_parse_return_expr = make_fn_name_parse_return_expr(export);

    let mut ret_expr = quote! {
        wave::#fn_name_parse_return_expr(&s)
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
        // Api wrappers are host-side / system calls: always Core-paid.
        // `execute_api` is the entry point that handles that on both
        // `indexer::Runtime` and `testlib::Runtime`.
        quote! { runtime.execute_api }
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

    // Generate the _call constructor for batching (test mode, proc/core context only)
    let call_constructor = if test && !public && (is_proc_context || is_core_context) {
        let call_fn_name = format_ident!("{}_call", fn_name);
        let ret_ty_inner = make_return_type(resolve, export)?;

        let (call_params, contract_expr) = if let Some((name, height, tx_index)) = contract_id {
            let mut params = Vec::new();
            for param in export.params.iter().skip(1) {
                let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
                if let Type::Id(id) = &param.ty {
                    let ty_def = &resolve.types[*id];
                    if ty_def.name.as_deref() == Some("holder-ref") {
                        params.push(quote! { #param_name: impl Into<HolderRef> });
                        continue;
                    }
                }
                let param_ty = utils::wit_type_to_rust_type(resolve, &param.ty, true)?;
                params.push(quote! { #param_name: #param_ty });
            }
            let expr = quote! {
                ContractAddress {
                    name: #name.to_string(),
                    height: #height,
                    tx_index: #tx_index,
                }
            };
            (params, expr)
        } else {
            let mut params = vec![quote! { contract_address_: &ContractAddress }];
            for param in export.params.iter().skip(1) {
                let param_name = Ident::new(&param.name.to_snake_case(), Span::call_site());
                if let Type::Id(id) = &param.ty {
                    let ty_def = &resolve.types[*id];
                    if ty_def.name.as_deref() == Some("holder-ref") {
                        params.push(quote! { #param_name: impl Into<HolderRef> });
                        continue;
                    }
                }
                let param_ty = utils::wit_type_to_rust_type(resolve, &param.ty, true)?;
                params.push(quote! { #param_name: #param_ty });
            }
            (params, quote! { contract_address_.clone() })
        };

        quote! {
            pub fn #call_fn_name(#(#call_params),*) -> super::TypedCall<#ret_ty_inner> {
                super::TypedCall {
                    contract: #contract_expr,
                    expr: wave::#fn_name_call_expr(#(#call_expr_param_names),*),
                    parse: wave::#fn_name_parse_return_expr,
                }
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        #fn_keywords #fn_name(#(#params),*) -> #ret_ty {
            let expr = wave::#fn_name_call_expr(#(#call_expr_param_names),*);
            let s = #execute(
                #ctx_signer,
                #contract_arg,
                expr.as_str(),
            )#awaited;
            #ret_expr
        }

        #call_constructor
    })
}
