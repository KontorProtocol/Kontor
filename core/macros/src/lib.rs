extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, ItemFn, parse_macro_input, spanned::Spanned};

mod contract;
mod impls;
mod import;
mod interface;
mod root;
mod runtime;
mod store;
mod transformers;
mod utils;
mod wavey;
mod wrapper;

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = contract::Config::from_list(&attr_args).unwrap();
    contract::generate(config).into()
}

#[proc_macro]
pub fn impls(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = impls::Config::from_list(&attr_args).unwrap();
    impls::generate(config).into()
}

#[proc_macro]
pub fn import(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = import::Config::from_list(&attr_args).unwrap();
    import::generate(config, false).into()
}

#[proc_macro]
pub fn import_test(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = import::Config::from_list(&attr_args).unwrap();
    import::generate(config, true).into()
}

#[proc_macro]
pub fn interface(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = interface::Config::from_list(&attr_args).unwrap();
    interface::generate(config, false).into()
}

#[proc_macro]
pub fn interface_test(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = interface::Config::from_list(&attr_args).unwrap();
    interface::generate(config, true).into()
}

#[proc_macro_derive(Store)]
pub fn derive_store(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    if !generics.params.is_empty() {
        return Error::new(
            generics.span(),
            "Store derive does not support generic parameters (lifetimes or types)",
        )
        .to_compile_error()
        .into();
    }

    let body = match &input.data {
        Data::Struct(data_struct) => store::generate_struct_body(data_struct, name),
        Data::Enum(data_enum) => store::generate_enum_body(data_enum, name),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Store derive is not supported for unions",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics stdlib::Store for #name #ty_generics #where_clause {
            fn __set(ctx: &impl stdlib::WriteContext, base_path: stdlib::DotPathBuf, value: #name #ty_generics) {
                #body
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Wrapper)]
pub fn derive_wrapper(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data_struct) => wrapper::generate_struct_wrapper(data_struct, name),
        Data::Enum(data_enum) => wrapper::generate_enum_wrapper(data_enum, name),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Wrapper derive is not supported for unions",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (_impl_generics, _ty_generics, _where_clause) = generics.split_for_impl();
    quote! {
        #body
    }
    .into()
}

#[proc_macro_derive(Storage)]
pub fn derive_storage(input: TokenStream) -> TokenStream {
    let mut tokens = derive_store(input.clone());
    tokens.extend(derive_wrapper(input));
    tokens
}

#[proc_macro_derive(Root)]
pub fn derive_root(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data_struct) => root::generate_root_struct(data_struct, name),
        _ => Err(Error::new(
            name.span(),
            "Root derive only supports structs with named fields",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (_impl_generics, _ty_generics, _where_clause) = generics.split_for_impl();
    quote! {
        #body
    }
    .into()
}

#[proc_macro_derive(StorageRoot)]
pub fn derive_storage_root(input: TokenStream) -> TokenStream {
    let mut tokens = derive_store(input.clone());
    tokens.extend(derive_wrapper(input.clone()));
    tokens.extend(derive_root(input));
    tokens
}

#[proc_macro_derive(Wavey)]
pub fn derive_wavey(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let wave_type_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_wave_type(data),
        Data::Enum(data) => wavey::generate_enum_wave_type(data),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let wave_type_body = match wave_type_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let from_self_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_to_value(data, name),
        Data::Enum(data) => wavey::generate_enum_to_value(data, name),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let from_self_body = match from_self_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let from_value_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_from_value(data, name),
        Data::Enum(data) => wavey::generate_enum_from_value(data, name),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let from_value_body = match from_value_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            pub fn wave_type() -> stdlib::wasm_wave::value::Type {
                #wave_type_body
            }
        }

        #[automatically_derived]
        impl #impl_generics From<#name #ty_generics> for stdlib::wasm_wave::value::Value #where_clause {
            fn from(value_: #name #ty_generics) -> Self {
                #from_self_body
            }
        }

        #[automatically_derived]
        impl #impl_generics From<stdlib::wasm_wave::value::Value> for #name #ty_generics #where_clause {
            fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
                #from_value_body
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn runtime(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config: runtime::Config = match syn::parse(attr) {
        Ok(v) => v,
        Err(e) => {
            return e.to_compile_error().into();
        }
    };
    let mut func = parse_macro_input!(item as ItemFn);

    func.attrs = vec![];
    let fn_name = &func.sig.ident;
    let fn_generics = &func.sig.generics;
    let fn_inputs = &func.sig.inputs;
    let fn_vis = &func.vis;
    let fn_block = &func.block;
    let contracts_dir = config.contracts_dir;
    let mode = config.mode.unwrap_or("local".to_string());

    let body = if mode == "regtest" {
        quote! {
            let (
                _bitcoin_data_dir,
                bitcoin_child,
                bitcoin_client,
                _kontor_data_dir,
                kontor_child,
                kontor_client,
                identity,
            ) = RegTester::setup().await?;
            let result = tokio::spawn({
                let bitcoin_client = bitcoin_client.clone();
                let kontor_client = kontor_client.clone();
                async move {
                    let reg_tester = RegTester::new(identity, bitcoin_client, kontor_client).await?;
                    let mut runtime = &mut Runtime::new_regtest(RuntimeConfig::builder().contracts_dir(#contracts_dir).build(), reg_tester).await?;
                    #fn_block
                }
            })
            .await;
            RegTester::teardown(bitcoin_client, bitcoin_child, kontor_client, kontor_child).await?;
            result?
        }
    } else {
        quote! {
            let mut runtime = &mut Runtime::new_local(RuntimeConfig::builder().contracts_dir(#contracts_dir).build()).await?;
            #fn_block
        }
    };

    let output = quote! {
        #[tokio::test]
        #fn_vis async fn #fn_name #fn_generics(#fn_inputs) -> Result<()> {
            #body
        }
    };

    output.into()
}
