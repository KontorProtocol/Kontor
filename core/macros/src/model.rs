use heck::ToPascalCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    DataEnum, DataStruct, Error, Fields, GenericArgument, Ident, PathArguments, Result, Type,
    spanned::Spanned,
};

use crate::utils;

pub fn generate_struct(
    data_struct: &DataStruct,
    type_name: &Ident,
    write: bool,
) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let write_prefix = if write { "Write" } else { "" };
            let read_only_model_name = Ident::new(&format!("{}Model", type_name), type_name.span());
            let model_name = Ident::new(
                &format!("{}{}Model", type_name, write_prefix),
                type_name.span(),
            );
            let context_param = if write {
                quote! { crate::context::ProcStorage }
            } else {
                quote! { crate::context::ViewStorage }
            };

            let mut special_models = vec![];

            let getters = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;

                if utils::is_map_type(field_ty) {
                    let (k_ty, v_ty) = get_map_types(field_ty)?;
                    let field_model_name = Ident::new(&format!("{}{}{}Model", type_name, &field_name.to_string().to_pascal_case(), write_prefix), field.span());

                    let (get_return, get_body) = if utils::is_primitive_type(&v_ty) {
                        (quote! { Option<#v_ty> }, quote! { self.ctx.__get(base_path) })
                    } else {
                        let v_model_ty = get_model_ident(write, &v_ty, field.span())?;
                        if utils::is_built_in_type(&v_ty) {
                            (quote! { Option<#v_ty> }, quote! { self.ctx.__exists(&base_path).then(|| #v_model_ty::new(self.ctx.clone(), base_path).load()) })
                        } else {
                            (quote! { Option<#v_model_ty> }, quote! { self.ctx.__exists(&base_path).then(|| #v_model_ty::new(self.ctx.clone(), base_path)) })
                        }
                    };

                    let setter = if write {
                        quote! {
                            pub fn set(&self, key: #k_ty, value: #v_ty) {
                                self.ctx.__set(self.base_path.push(key.to_string()), value)
                            }
                        }
                    } else {
                        quote!{}
                    };

                    special_models.push(quote! {
                        #[derive(Clone)]
                        pub struct #field_model_name {
                            pub base_path: stdlib::DotPathBuf,
                            ctx: std::rc::Rc<#context_param>,
                        }

                        impl #field_model_name {
                            pub fn get(&self, key: impl ToString) -> #get_return {
                                let base_path = self.base_path.push(key.to_string());
                                #get_body
                            }

                            #setter

                            pub fn load(&self) -> Map<#k_ty, #v_ty> {
                                Map::new(&[])
                            }

                            pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
                                &'a self,
                            ) -> impl Iterator<Item = T> + 'a {
                                self.ctx.__get_keys(&self.base_path)
                            }
                        }
                    });

                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_model_name {
                            #field_model_name { base_path: self.base_path.push(#field_name_str), ctx: self.ctx.clone() }
                        }
                    })
                } else if utils::is_option_type(field_ty) {
                    let inner_ty = get_option_inner_type(field_ty)?;
                    let base_path = quote! { self.base_path.push(#field_name_str) };
                    if utils::is_primitive_type(&inner_ty) {
                        Ok(quote! {
                            pub fn #field_name(&self) -> Option<#inner_ty> {
                                let base_path = #base_path;
                                if self.ctx.__extend_path_with_match(&base_path, &["none"]).is_some() {
                                    None
                                } else {
                                    self.ctx.__get(base_path.push("some"))
                                }
                            }
                        })
                    } else {
                        let inner_model_ty = get_model_ident(write, &inner_ty, field.span())?;
                        let (load, ret_ty)= if utils::is_built_in_type(&inner_ty) {
                            (quote! { .load() }, quote! { #inner_ty })
                        } else {
                            (quote! {}, quote! { #inner_model_ty })
                        };
                        Ok(quote! {
                            pub fn #field_name(&self) -> Option<#ret_ty> {
                                let base_path = #base_path;
                                if self.ctx.__extend_path_with_match(&base_path, &["none"]).is_some() {
                                    None
                                } else {
                                    Some(#inner_model_ty::new(self.ctx.clone(), base_path.push("some"))#load)
                                }
                            }
                        })
                    }
                } else if utils::is_primitive_type(field_ty) {
                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_ty {
                            self.ctx.__get(self.base_path.push(#field_name_str)).unwrap()
                        }
                    })
                } else {
                    let field_model_ty = get_model_ident(write, field_ty, field.span())?;
                    Ok(if utils::is_built_in_type(field_ty) {
                        quote! {
                            pub fn #field_name(&self) -> #field_ty {
                                #field_model_ty::new(self.ctx.clone(), self.base_path.push(#field_name_str)).load()
                            }
                        }
                    } else {
                        quote! {
                            pub fn #field_name(&self) -> #field_model_ty {
                                #field_model_ty::new(self.ctx.clone(), self.base_path.push(#field_name_str))
                            }
                        }
                    })
                }
            }).collect::<Result<Vec<_>>>()?;

            let setters = if write {
                fields
                    .named
                    .iter()
                    .map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_name_str = field_name.to_string();
                        let field_ty = &field.ty;
                        let set_field_name =
                            Ident::new(&format!("set_{}", field_name), field_name.span());

                        if utils::is_map_type(field_ty) {
                            Ok(quote! {})
                        } else {
                            Ok(quote! {
                                pub fn #set_field_name(&self, value: #field_ty) {
                                    self.ctx.__set(self.base_path.push(#field_name_str), value);
                                }
                            })
                        }
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };

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
                            #field_name: self.#field_name().load()
                        })
                    } else if utils::is_option_type(field_ty) {
                        let inner_ty = get_option_inner_type(field_ty)?;
                        if utils::is_primitive_type(&inner_ty) {
                            Ok(quote! {
                                #field_name: self.#field_name()
                            })
                        } else {
                            let load = if utils::is_built_in_type(&inner_ty) {
                                quote! {}
                            } else {
                                quote! {
                                    .map(|p| p.load())
                                }
                            };
                            Ok(quote! {
                                #field_name: self.#field_name()#load
                            })
                        }
                    } else if utils::is_primitive_type(field_ty) {
                        Ok(quote! {
                            #field_name: self.#field_name()
                        })
                    } else {
                        Ok(if utils::is_built_in_type(field_ty) {
                            quote! {
                                #field_name: self.#field_name()
                            }
                        } else {
                            quote! {
                                #field_name: self.#field_name().load()
                            }
                        })
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let proc_props = if write {
                quote! {
                    model: #read_only_model_name,
                }
            } else {
                quote! {}
            };

            let proc_prelude = if write {
                quote! {
                    let view_storage = ctx.view_storage();
                }
            } else {
                quote! {}
            };

            let proc_assigns = if write {
                quote! {
                    model: #read_only_model_name::new(std::rc::Rc::new(view_storage), base_path.clone()),
                }
            } else {
                quote! {}
            };

            let proc_impls = if write {
                quote! {
                    impl std::ops::Deref for #model_name {
                        type Target = #read_only_model_name;

                        fn deref(&self) -> &Self::Target {
                            &self.model
                        }
                    }
                }
            } else {
                quote! {}
            };

            // let proc_methods = if write {
            //     quote! {
            //         pub fn read_only(&'a self) -> #read_only_model_name<'a> {
            //             #read_only_model_name::new(&self.view_context, self.base_path.clone())
            //         }
            //     }
            // } else {
            //     quote! {}
            // };

            let result = quote! {
                pub struct #model_name {
                    pub base_path: stdlib::DotPathBuf,
                    ctx: std::rc::Rc<#context_param>,
                    #proc_props
                }

                impl #model_name {
                    pub fn new(ctx: std::rc::Rc<#context_param>, base_path: stdlib::DotPathBuf) -> Self {
                        #proc_prelude
                        Self {
                            base_path: base_path.clone(),
                            ctx,
                            #proc_assigns
                        }
                    }

                    #(#getters)*

                    #(#setters)*

                    pub fn load(&self) -> #type_name {
                        #type_name {
                            #(#load_fields,)*
                        }
                    }
                }

                #proc_impls

                #(#special_models)*
            };

            Ok(result)
        }
        _ => Err(Error::new(
            type_name.span(),
            "Model derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum(data_enum: &DataEnum, type_name: &Ident, write: bool) -> Result<TokenStream> {
    let write_prefix = if write { "Write" } else { "" };
    let model_name = Ident::new(
        &format!("{}{}Model", type_name, write_prefix),
        type_name.span(),
    );
    let context_param = if write {
        quote! { crate::context::ProcStorage }
    } else {
        quote! { crate::context::ViewStorage }
    };

    let model_variants: Result<Vec<_>> = data_enum
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
                        let inner_model_ty =
                            get_model_ident(write, inner_ty, variant.ident.span())?;
                        Ok(quote! { #variant_ident(#inner_model_ty) })
                    }
                }
                _ => Err(Error::new(
                    variant.ident.span(),
                    "Model derive only supports unit or single-field tuple variants",
                )),
            }
        })
        .collect();

    let model_variants = model_variants?;

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
                p if p.starts_with(base_path.push(#variant_name).as_ref()) => #model_name::#variant_ident
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    Ok(quote! {
                        p if p.starts_with(base_path.push(#variant_name).as_ref()) => #model_name::#variant_ident(ctx.__get(base_path.push(#variant_name)).unwrap())
                    })
                } else {
                    let inner_model_ty = get_model_ident(write, inner_ty, variant.ident.span())?;
                    Ok(quote! {
                        p if p.starts_with(base_path.push(#variant_name).as_ref()) => #model_name::#variant_ident(#inner_model_ty::new(ctx.clone(), base_path.push(#variant_name)))
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
                #model_name::#variant_ident => #type_name::#variant_ident
            },
            Fields::Unnamed(fields) => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    quote! {
                        #model_name::#variant_ident(inner) => #type_name::#variant_ident(inner.clone())
                    }
                } else {
                    quote! {
                        #model_name::#variant_ident(inner) => #type_name::#variant_ident(inner.load())
                    }
                }
            }
            _ => unreachable!(),
        }
    }).collect::<Vec<_>>();

    Ok(quote! {
        pub enum #model_name {
            #(#model_variants,)*
        }

        impl #model_name {
            pub fn new(ctx: std::rc::Rc<#context_param>, base_path: stdlib::DotPathBuf) -> Self {
                ctx.__extend_path_with_match(&base_path, &[#(#variant_names),*])
                    .map(|path| match path {
                        #(#new_arms,)*
                        _ => {
                            panic!("Matching path not found")
                        }
                    })
                    .unwrap()
            }

            pub fn load(&self) -> #type_name {
                match self {
                    #(#load_arms,)*
                }
            }
        }
    })
}

fn get_model_ident(write: bool, ty: &Type, span: Span) -> Result<Ident> {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                Ident::new(
                    &format!("{}{}Model", segment.ident, if write { "Write" } else { "" }),
                    span,
                )
            })
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
