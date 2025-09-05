use crate::transformers;
use heck::ToKebabCase;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DataStruct, Error, Fields, Ident, Result, spanned::Spanned};

pub fn generate_struct_wave_type(data: &DataStruct) -> Result<TokenStream> {
    match &data.fields {
        Fields::Named(fields) => {
            let field_types = fields
                .named
                .iter()
                .map(|field| {
                    let field_name_str = field.ident.as_ref().unwrap().to_string().to_kebab_case();
                    let field_ty = &field.ty;
                    let wave_ty = transformers::syn_type_to_wave_type(field_ty)?;
                    Ok(quote! { (#field_name_str, #wave_ty) })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(quote! {
                stdlib::wasm_wave::value::Type::record([#(#field_types),*]).unwrap()
            })
        }
        _ => Err(Error::new(
            data.struct_token.span,
            "Wavey derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum_wave_type(data: &DataEnum) -> Result<TokenStream> {
    let variant_types = data
        .variants
        .iter()
        .map(|variant| {
            let variant_name = variant.ident.to_string().to_lowercase();
            match &variant.fields {
                Fields::Unit => Ok(quote! { (#variant_name, None) }),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    let inner_ty = &fields.unnamed[0].ty;
                    let inner_wave_ty = transformers::syn_type_to_wave_type(inner_ty)?;
                    Ok(quote! { (#variant_name, Some(#inner_wave_ty)) })
                }
                _ => Err(Error::new(
                    variant.span(),
                    "Wavey derive only supports unit or single-field tuple variants for enums",
                )),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        stdlib::wasm_wave::value::Type::variant([#(#variant_types),*]).unwrap()
    })
}

pub fn generate_struct_to_value(data: &DataStruct, name: &Ident) -> Result<TokenStream> {
    match &data.fields {
        Fields::Named(fields) => {
            let field_assigns = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string().to_kebab_case();
                quote! { (#field_name_str, stdlib::wasm_wave::value::Value::from(value_.#field_name)) }
            });
            Ok(quote! {
                <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                    &#name::wave_type(),
                    [#(#field_assigns),*],
                ).unwrap()
            })
        }
        _ => Err(Error::new(
            data.struct_token.span,
            "Wavey derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum_to_value(data: &DataEnum, name: &Ident) -> Result<TokenStream> {
    let arms = data.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();
        match &variant.fields {
            Fields::Unit => Ok(quote! {
                #name::#variant_ident => <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_variant(&#name::wave_type(), #variant_name, None)
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(quote! {
                #name::#variant_ident(operand) => <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_variant(&#name::wave_type(), #variant_name, Some(stdlib::wasm_wave::value::Value::from(operand)))
            }),
            _ => Err(Error::new(variant.span(), "Wavey derive only supports unit or single-field tuple variants for enums")),
        }
    }).collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        (match value_ {
            #(#arms,)*
        }).unwrap()
    })
}

pub fn generate_struct_from_value(data: &DataStruct, name: &Ident) -> Result<TokenStream> {
    match &data.fields {
        Fields::Named(fields) => {
            let mut_inits = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                quote! { let mut #field_name = None; }
            });
            let match_arms = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string().to_kebab_case();
                let unwrap_expr = transformers::syn_type_to_unwrap_expr(&field.ty)
                    .unwrap_or_else(|_| panic!("Could not unwrap expr for type: {:?}", &field.ty));
                quote! { #field_name_str => #field_name = Some(val_.#unwrap_expr), }
            });
            let constructs = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                quote! { #field_name: #field_name.expect(&format!("Missing '{}' field", #field_name_str)), }
            });
            Ok(quote! {
                #(#mut_inits)*
                for (key_, val_) in value_.unwrap_record() {
                    match key_.as_ref() {
                        #(#match_arms)*
                        key_ => panic!("Unknown field: {key_}"),
                    }
                }
                #name {
                    #(#constructs)*
                }
            })
        }
        _ => Err(Error::new(
            data.struct_token.span,
            "Wavey derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum_from_value(data: &DataEnum, name: &Ident) -> Result<TokenStream> {
    let arms = data.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();
        match &variant.fields {
            Fields::Unit => Ok(quote! {
                key_ if key_.eq(#variant_name) => #name::#variant_ident,
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let unwrap_expr = transformers::syn_type_to_unwrap_expr(&fields.unnamed[0].ty)?;
                Ok(quote! {
                    key_ if key_.eq(#variant_name) => #name::#variant_ident(val_.unwrap().#unwrap_expr),
                })
            }
            _ => Err(Error::new(variant.span(), "Wavey derive only supports unit or single-field tuple variants for enums")),
        }
    }).collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        let (key_, val_) = value_.unwrap_variant();
        match key_ {
            #(#arms)*
            key_ => panic!("Unknown tag {key_}"),
        }
    })
}
