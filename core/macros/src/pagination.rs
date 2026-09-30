use anyhow::Result;
use heck::ToSnakeCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use wit_parser::{Function, Resolve, WorldItem};
use wit_validator::pagination::{PaginationShape, is_builtin, shape};

use crate::utils;

pub fn binding(
    resolve: &Resolve,
    export: &Function,
    shape: &PaginationShape,
    test: bool,
    contract_id: Option<(&str, u64, u32)>,
    local: bool,
) -> Result<TokenStream> {
    let name = Ident::new(&export.name.to_snake_case(), Span::call_site());
    let page = utils::wit_type_to_rust_type(resolve, &shape.page, false)?;
    let item = utils::wit_type_to_rust_type(resolve, &shape.item, false)?;
    let mut params = Vec::new();
    let mut conversions = Vec::new();
    let mut filters = Vec::new();
    for param in export.params.iter().take(shape.request_index).skip(1) {
        let ident = Ident::new(&param.name.to_snake_case(), Span::call_site());
        let ty = utils::wit_type_to_rust_type(resolve, &param.ty, false)?;
        if is_builtin(resolve, param.ty, "context-types", "holder-ref") {
            params.push(quote! { #ident: impl Into<HolderRef> });
            conversions.push(quote! { let #ident: HolderRef = #ident.into(); });
        } else {
            params.push(quote! { #ident: #ty });
        }
        filters.push(ident);
    }
    let raw_return = if shape.fallible {
        quote! { Result<#page, Error> }
    } else {
        quote! { #page }
    };
    if local {
        params.insert(0, quote! { ctx: &'a context::ViewContext });
    } else if test {
        params.insert(0, quote! { runtime: &'a mut Runtime });
    }
    let contract_arg = match contract_id {
        Some((name, height, tx_index)) => {
            quote! { &ContractAddress { name: String::from(#name), height: #height, tx_index: #tx_index } }
        }
        None if !local => {
            params.insert(
                usize::from(test),
                quote! { contract_address_: &'a ContractAddress },
            );
            quote! { contract_address_ }
        }
        None => quote! {},
    };
    let fn_name = &export.name;
    let after = if test {
        quote! { __after }
    } else {
        quote! { __after.map(String::from) }
    };
    let request = quote! { __CursorRequest { after: #after, limit: __limit } };
    let expression = quote! {
        let expr = format!("{}({})", #fn_name, [
            #(stdlib::to_wave_expr(#filters.clone()),)*
            stdlib::to_wave_expr(#request),
        ].join(", "));
    };
    if test {
        return Ok(quote! {
            pub fn #name<'a>(#(#params),*) -> AsyncCursorQuery<
                impl AsyncFnMut(Option<String>, Option<u64>) -> Result<#raw_return, AnyhowError> + 'a,
                #raw_return, AnyhowError,
            > {
                #(#conversions)*
                AsyncCursorQuery::new(async move |__after: Option<String>, __limit: Option<u64>| {
                    #expression
                    let s = runtime.execute_api(None, #contract_arg, &expr).await?;
                    Ok(stdlib::from_wave_expr::<#raw_return>(&s))
                })
            }
        });
    }
    let call = if local {
        quote! { <Self as Guest>::#name(ctx, #(#filters.clone(),)* #request) }
    } else {
        quote! {{
            #expression
            let s = foreign::call(None, #contract_arg, &expr);
            stdlib::from_wave_expr::<#raw_return>(&s)
        }}
    };
    let call = if shape.fallible {
        call
    } else {
        quote! { Ok(#call) }
    };
    Ok(quote! {
        pub fn #name<'a>(#(#params),*) -> CursorQuery<
            impl FnMut(Option<&str>, Option<u64>) -> Result<#page, Error> + 'a,
            #page, #item, Error,
        > {
            #(#conversions)*
            CursorQuery::new(
                move |__after: Option<&str>, __limit: Option<u64>| #call,
                |page| (page.items, page.next),
                || Error::Message(String::from("Pagination cursor did not advance")),
            )
        }
    })
}

pub fn local_bindings(resolve: &Resolve) -> Result<Vec<TokenStream>> {
    let Some((_, world)) = resolve
        .worlds
        .iter()
        .find(|(_, world)| world.name == "root")
    else {
        return Ok(Vec::new());
    };
    world
        .exports
        .values()
        .filter_map(|item| {
            let WorldItem::Function(function) = item else {
                return None;
            };
            match shape(resolve, function) {
                Ok(Some(shape)) => Some(binding(resolve, function, &shape, false, None, true)),
                Ok(None) => None,
                Err(error) => Some(Err(error.into())),
            }
        })
        .collect()
}
