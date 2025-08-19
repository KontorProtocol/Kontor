use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    DataEnum, DataStruct, Error, Fields, Ident, PathArguments, Result, Type, TypePath,
    spanned::Spanned,
};

pub fn generate_struct_wave_type(data: &DataStruct) -> Result<TokenStream> {
    match &data.fields {
        Fields::Named(fields) => {
            let field_types = fields
                .named
                .iter()
                .map(|field| {
                    let field_name_str = field.ident.as_ref().unwrap().to_string();
                    let field_ty = &field.ty;
                    let wave_ty = type_to_wave_type(field_ty)?;
                    Ok(quote! { (#field_name_str, #wave_ty) })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(quote! {
                wasm_wave::value::Type::record([#(#field_types),*]).unwrap()
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
                    let inner_wave_ty = type_to_wave_type(inner_ty)?;
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
        wasm_wave::value::Type::variant([#(#variant_types),*]).unwrap()
    })
}

pub fn generate_struct_to_value(data: &DataStruct, name: &Ident) -> Result<TokenStream> {
    match &data.fields {
        Fields::Named(fields) => {
            let field_assigns = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                quote! { (#field_name_str, wasm_wave::value::Value::from(value_.#field_name)) }
            });
            Ok(quote! {
                wasm_wave::value::Value::make_record(
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
                #name::#variant_ident => wasm_wave::value::Value::make_variant(&#name::wave_type(), #variant_name, None)
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(quote! {
                #name::#variant_ident(operand) => wasm_wave::value::Value::make_variant(&#name::wave_type(), #variant_name, Some(wasm_wave::value::Value::from(operand)))
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
                let field_name_str = field_name.to_string();
                let unwrap_expr = unwrap_expr_for_type(&field.ty)
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
                let unwrap_expr = unwrap_expr_for_type(&fields.unnamed[0].ty)?;
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

fn type_to_wave_type(ty: &Type) -> Result<TokenStream> {
    if let Some(prim) = get_wave_primitive_type(ty) {
        Ok(prim)
    } else {
        Ok(quote! { #ty::wave_type() })
    }
}

fn get_wave_primitive_type(ty: &Type) -> Option<TokenStream> {
    if let Type::Path(TypePath { qself: None, path }) = ty
        && path.segments.len() == 1
    {
        let segment = &path.segments[0];
        if segment.arguments == PathArguments::None {
            match segment.ident.to_string().as_str() {
                "u64" => Some(quote! { wasm_wave::value::Type::U64 }),
                "i64" => Some(quote! { wasm_wave::value::Type::S64 }),
                "String" => Some(quote! { wasm_wave::value::Type::STRING }),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn unwrap_expr_for_type(ty: &Type) -> Result<TokenStream> {
    if let Type::Path(TypePath { qself: None, path }) = ty
        && path.segments.len() == 1
    {
        let segment = &path.segments[0];
        if segment.arguments == PathArguments::None {
            let ident = segment.ident.to_string();
            match ident.as_str() {
                "u64" => return Ok(quote! { unwrap_u64() }),
                "i64" => return Ok(quote! { unwrap_s64() }),
                "String" => return Ok(quote! { unwrap_string().into_owned() }),
                _ => {}
            }
        }
    }
    Ok(quote! { into_owned().into() })
}
