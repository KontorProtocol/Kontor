use heck::ToPascalCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    DataEnum, DataStruct, Error, Fields, GenericArgument, Ident, PathArguments, Result, Type,
    spanned::Spanned,
};

use crate::utils;

pub fn generate_struct_wrapper(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let wrapper_name = Ident::new(&format!("{}Wrapper", type_name), type_name.span());

            let mut special_wrappers = vec![];

            let getters = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;

                if utils::is_map_type(field_ty) {
                    let (k_ty, v_ty) = get_map_types(field_ty)?;
                    let field_wrapper_name = Ident::new(&format!("{}{}Wrapper", type_name, &field_name.to_string().to_pascal_case()), field.span());

                    let (get_return, get_body) = if utils::is_primitive_type(&v_ty) {
                        (quote! { Option<#v_ty> }, quote! { ctx.__get(self.base_path.push(key.to_string())) })
                    } else {
                        let v_wrapper_ty = get_wrapper_ident(&v_ty, field.span())?;
                        (quote! { Option<#v_wrapper_ty> }, quote! { ctx.__exists(&base_path.push(key.to_string())).then(|| #v_wrapper_ty::new(ctx, base_path.push(key.to_string()))) })
                    };

                    special_wrappers.push(quote! {
                        #[derive(Clone)]
                        pub struct #field_wrapper_name {
                            pub base_path: stdlib::DotPathBuf,
                        }

                        impl #field_wrapper_name {
                            pub fn get(&self, ctx: &impl stdlib::ReadContext, key: #k_ty) -> #get_return {
                                let base_path = self.base_path.push(key.to_string());
                                #get_body
                            }

                            pub fn set(&self, ctx: &impl stdlib::WriteContext, key: #k_ty, value: #v_ty) {
                                ctx.__set(self.base_path.push(key.to_string()), value)
                            }

                            pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Map<#k_ty, #v_ty> {
                                Map::new(&[])
                            }
                        }
                    });

                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_wrapper_name {
                            #field_wrapper_name { base_path: self.base_path.push(#field_name_str) }
                        }
                    })
                } else if utils::is_option_type(field_ty) {
                    let inner_ty = get_option_inner_type(field_ty)?;
                    let base_path = quote! { self.base_path.push(#field_name_str) };
                    if utils::is_primitive_type(&inner_ty) {
                        Ok(quote! {
                            pub fn #field_name(&self, ctx: &impl stdlib::ReadContext) -> Option<#inner_ty> {
                                let base_path = #base_path;
                                if ctx.__is_void(&base_path) {
                                    None
                                } else {
                                    ctx.__get(base_path)
                                }
                            }
                        })
                    } else {
                        let inner_wrapper_ty = get_wrapper_ident(&inner_ty, field.span())?;
                        Ok(quote! {
                            pub fn #field_name(&self, ctx: &impl stdlib::ReadContext) -> Option<#inner_wrapper_ty> {
                                let base_path = #base_path;
                                if ctx.__is_void(&base_path) {
                                    None
                                } else {
                                    Some(#inner_wrapper_ty::new(ctx, base_path))
                                }
                            }
                        })
                    }
                } else if utils::is_primitive_type(field_ty) {
                    Ok(quote! {
                        pub fn #field_name(&self, ctx: &impl stdlib::ReadContext) -> #field_ty {
                            ctx.__get(self.base_path.push(#field_name_str)).unwrap()
                        }
                    })
                } else {
                    let field_wrapper_ty = get_wrapper_ident(field_ty, field.span())?;
                    Ok(quote! {
                        pub fn #field_name(&self, ctx: &impl stdlib::ReadContext) -> #field_wrapper_ty {
                            #field_wrapper_ty::new(ctx, self.base_path.push(#field_name_str))
                        }
                    })
                }
            }).collect::<Result<Vec<_>>>()?;

            let setters = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;
                let set_field_name = Ident::new(&format!("set_{}", field_name), field_name.span());

                if utils::is_map_type(field_ty) {
                    Ok(quote! { })
                } else if utils::is_option_type(field_ty) {
                    let inner_ty = get_option_inner_type(field_ty)?;
                    Ok(quote! {
                        pub fn #set_field_name(&self, ctx: &impl stdlib::WriteContext, value: Option<#inner_ty>) {
                            let base_path = self.base_path.push(#field_name_str);
                            match value {
                                Some(inner) => ctx.__set(base_path, inner),
                                None => ctx.__set(base_path, ()),
                            }
                        }
                    })
                } else {
                    Ok(quote! {
                        pub fn #set_field_name(&self, ctx: &impl stdlib::WriteContext, value: #field_ty) {
                            ctx.__set(self.base_path.push(#field_name_str), value);
                        }
                    })
                }
            }).collect::<Result::<Vec<_>>>()?;

            let load_fields = fields
                .named
                .iter()
                .map(|field| {
                    let field_name = field.ident.as_ref().unwrap();
                    let _field_name_str = field_name.to_string();
                    let field_ty = &field.ty;

                    if utils::is_map_type(field_ty) {
                        let (_k_ty, _v_ty) = get_map_types(field_ty)?;
                        Ok(quote! {
                            #field_name: self.#field_name().load(ctx)
                        })
                    } else if utils::is_option_type(field_ty) {
                        let inner_ty = get_option_inner_type(field_ty)?;
                        if utils::is_primitive_type(&inner_ty) {
                            Ok(quote! {
                                #field_name: self.#field_name(ctx)
                            })
                        } else {
                            Ok(quote! {
                                #field_name: self.#field_name(ctx).map(|p| p.load(ctx))
                            })
                        }
                    } else if utils::is_primitive_type(field_ty) {
                        Ok(quote! {
                            #field_name: self.#field_name(ctx)
                        })
                    } else {
                        Ok(quote! {
                            #field_name: self.#field_name(ctx).load(ctx)
                        })
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let result = quote! {
                #[derive(Clone)]
                pub struct #wrapper_name {
                    pub base_path: stdlib::DotPathBuf,
                }

                impl #wrapper_name {
                    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
                        Self { base_path }
                    }

                    #(#getters)*

                    #(#setters)*

                    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> #type_name {
                        #type_name {
                            #(#load_fields,)*
                        }
                    }
                }

                #(#special_wrappers)*
            };

            Ok(result)
        }
        _ => Err(Error::new(
            type_name.span(),
            "Wrapper derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum_wrapper(data_enum: &DataEnum, type_name: &Ident) -> Result<TokenStream> {
    let wrapper_name = Ident::new(&format!("{}Wrapper", type_name), type_name.span());

    let wrapper_variants: Result<Vec<_>> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            match &variant.fields {
                Fields::Unit => Ok(quote! { #variant_ident }),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    let inner_ty = &fields.unnamed[0].ty;
                    if utils::is_primitive_type(inner_ty) {
                        Ok(quote! { #variant_ident(#inner_ty) })
                    } else {
                        let inner_wrapper_ty = get_wrapper_ident(inner_ty, variant.ident.span())?;
                        Ok(quote! { #variant_ident(#inner_wrapper_ty) })
                    }
                }
                _ => Err(Error::new(
                    variant.ident.span(),
                    "Wrapper derive only supports unit or single-field tuple variants",
                )),
            }
        })
        .collect();

    let wrapper_variants = wrapper_variants?;

    let variant_names = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_name = variant.ident.to_string().to_lowercase();
            quote! { #variant_name }
        })
        .collect::<Vec<_>>();

    let new_arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();

        match &variant.fields {
            Fields::Unit => Ok(quote! {
                p if p.starts_with(base_path.push(#variant_name).as_ref()) => #wrapper_name::#variant_ident
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    Ok(quote! {
                        p if p.starts_with(base_path.push(#variant_name).as_ref()) => #wrapper_name::#variant_ident(ctx.__get(base_path.push(#variant_name)).unwrap())
                    })
                } else {
                    let inner_wrapper_ty = get_wrapper_ident(inner_ty, variant.ident.span())?;
                    Ok(quote! {
                        p if p.starts_with(base_path.push(#variant_name).as_ref()) => #wrapper_name::#variant_ident(#inner_wrapper_ty::new(ctx, base_path.push(#variant_name)))
                    })
                }
            }
            _ => unreachable!(),
        }
    }).collect::<Result<Vec<_>>>()?;

    let load_arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => quote! {
                #wrapper_name::#variant_ident => #type_name::#variant_ident
            },
            Fields::Unnamed(fields) => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    quote! {
                        #wrapper_name::#variant_ident(inner) => #type_name::#variant_ident(inner.clone())
                    }
                } else {
                    quote! {
                        #wrapper_name::#variant_ident(inner) => #type_name::#variant_ident(inner.load(ctx))
                    }
                }
            }
            _ => unreachable!(),
        }
    }).collect::<Vec<_>>();

    Ok(quote! {
        #[derive(Clone)]
        pub enum #wrapper_name {
            #(#wrapper_variants,)*
        }

        impl #wrapper_name {
            pub fn new(ctx: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
                ctx.__matching_path(&format!(r"^{}.({})(\..*|$)", base_path, [#(#variant_names),*].join("|")))
                    .map(|path| match path {
                        #(#new_arms,)*
                        _ => {
                            panic!("Matching path not found")
                        }
                    })
                    .unwrap()
            }

            pub fn load(&self, ctx: &impl stdlib::ReadContext) -> #type_name {
                match self {
                    #(#load_arms,)*
                }
            }
        }
    })
}

fn get_wrapper_ident(ty: &Type, span: Span) -> Result<Ident> {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| Ident::new(&format!("{}Wrapper", segment.ident), span))
            .ok_or_else(|| Error::new(span, "Expected a named type for variant field"))
    } else {
        Err(Error::new(span, "Expected a named type for variant field"))
    }
}

fn get_option_inner_type(ty: &Type) -> Result<Type> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Option"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let GenericArgument::Type(inner_ty) = &args.args[0]
    {
        return Ok(inner_ty.clone());
    }
    Err(Error::new(ty.span(), "Expected Option<T> type"))
}

fn get_map_types(ty: &Type) -> Result<(Type, Type)> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Map"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 2
        && let (GenericArgument::Type(k_ty), GenericArgument::Type(v_ty)) =
            (&args.args[0], &args.args[1])
    {
        return Ok((k_ty.clone(), v_ty.clone()));
    }
    Err(Error::new(ty.span(), "Expected Map<K, V> type"))
}
