extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    DataEnum, DataStruct, DeriveInput, Error, Fields, Ident, PathArguments, Result, Type,
    parse_macro_input, spanned::Spanned,
};

#[proc_macro_derive(Store)]
pub fn derive_store(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        syn::Data::Struct(data_struct) => generate_struct_body(data_struct, name),
        syn::Data::Enum(data_enum) => generate_enum_body(data_enum, name),
        syn::Data::Union(_) => Err(Error::new(
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
        impl #impl_generics stdlib::Store for #name #ty_generics #where_clause {
            fn __set(ctx: &impl stdlib::WriteContext, base_path: stdlib::DotPathBuf, value: #name #ty_generics) {
                #body
            }
        }
    };

    TokenStream::from(expanded)
}

fn generate_struct_body(
    data_struct: &DataStruct,
    type_name: &Ident,
) -> Result<proc_macro2::TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let field_sets = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;

                if is_option_type(field_ty) {
                    quote! {
                        match value.#field_name {
                            Some(inner) => ctx.__set(base_path.push(#field_name_str), inner),
                            None => ctx.__set(base_path.push(#field_name_str), ()),
                        }
                    }
                } else {
                    quote! {
                        ctx.__set(base_path.push(#field_name_str), value.#field_name);
                    }
                }
            });
            Ok(quote! { #(#field_sets)* })
        }
        _ => Err(Error::new(
            type_name.span(),
            "Store derive only supports structs with named fields",
        )),
    }
}

fn generate_enum_body(data_enum: &DataEnum, type_name: &Ident) -> Result<proc_macro2::TokenStream> {
    let arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();

        match &variant.fields {
            Fields::Unit => {
                Ok(quote! {
                    #type_name::#variant_ident => ctx.__set(base_path.push(#variant_name), ()),
                })
            }
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                Ok(quote! {
                    #type_name::#variant_ident(inner) => ctx.__set(base_path.push(#variant_name), inner),
                })
            }
            _ => Err(Error::new(
                variant_ident.span(),
                "Store derive only supports unit or single-field tuple variants",
            )),
        }
    });

    // Collect results, propagating any errors
    let arms: Result<Vec<_>> = arms.collect();
    let arms = arms?;

    Ok(quote! {
        match value {
            #(#arms)*
        }
    })
}

fn is_option_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Option"
                    && matches!(segment.arguments, PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

#[derive(FromMeta)]
struct ContractConfig {
    name: String,
    world: Option<String>,
    path: Option<String>,
}

fn to_pascal_case(name: &str) -> String {
    name.split('-')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

#[proc_macro_derive(Wrapper)]
pub fn derive_wrapper(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        syn::Data::Struct(data_struct) => generate_struct_wrapper(data_struct, name),
        syn::Data::Enum(data_enum) => generate_enum_wrapper(data_enum, name),
        syn::Data::Union(_) => Err(Error::new(
            name.span(),
            "Wrapper derive is not supported for unions",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (_impl_generics, _ty_generics, _where_clause) = generics.split_for_impl();
    let expanded = quote! {
        #body
    };

    TokenStream::from(expanded)
}

fn generate_struct_wrapper(
    data_struct: &DataStruct,
    type_name: &Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let wrapper_name = Ident::new(&format!("{}Wrapper", type_name), type_name.span());

            let mut special_wrappers = vec![];

            let getters = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;

                if is_map_type(field_ty) {
                    let (k_ty, v_ty) = get_map_types(field_ty)?;
                    let field_wrapper_name = Ident::new(&format!("{}{}Wrapper", type_name, to_pascal_case(&field_name.to_string())), field.span());

                    let (get_return, get_body) = if is_primitive_type(&v_ty) {
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
                } else if is_option_type(field_ty) {
                    let inner_ty = get_option_inner_type(field_ty)?;
                    let base_path = quote! { self.base_path.push(#field_name_str) };
                    if is_primitive_type(&inner_ty) {
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
                } else if is_primitive_type(field_ty) {
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
            }).collect::<syn::Result<Vec<_>>>()?;

            let setters = fields.named.iter().map(|field| {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;
                let set_field_name = Ident::new(&format!("set_{}", field_name), field_name.span());

                if is_map_type(field_ty) {
                    Ok(quote! { })
                } else if is_option_type(field_ty) {
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

                    if is_map_type(field_ty) {
                        let (_k_ty, _v_ty) = get_map_types(field_ty)?;
                        Ok(quote! {
                            #field_name: self.#field_name().load(ctx)
                        })
                    } else if is_option_type(field_ty) {
                        let inner_ty = get_option_inner_type(field_ty)?;
                        if is_primitive_type(&inner_ty) {
                            Ok(quote! {
                                #field_name: self.#field_name(ctx)
                            })
                        } else {
                            Ok(quote! {
                                #field_name: self.#field_name(ctx).map(|p| p.load(ctx))
                            })
                        }
                    } else if is_primitive_type(field_ty) {
                        Ok(quote! {
                            #field_name: self.#field_name(ctx)
                        })
                    } else {
                        Ok(quote! {
                            #field_name: self.#field_name(ctx).load(ctx)
                        })
                    }
                })
                .collect::<syn::Result<Vec<_>>>()?;

            let result = quote! {
                #[derive(Clone)]
                pub struct #wrapper_name {
                    pub base_path: stdlib::DotPathBuf,
                }

                #[allow(dead_code)]
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

fn is_map_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "Map")
            .unwrap_or(false)
    } else {
        false
    }
}

fn get_map_types(ty: &Type) -> syn::Result<(Type, Type)> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Map"
        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 2
        && let (syn::GenericArgument::Type(k_ty), syn::GenericArgument::Type(v_ty)) =
            (&args.args[0], &args.args[1])
    {
        return Ok((k_ty.clone(), v_ty.clone()));
    }
    Err(Error::new(ty.span(), "Expected Map<K, V> type"))
}

fn is_primitive_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last().map(|s| s.ident.to_string());
        matches!(segment.as_deref(), Some("u64" | "i64" | "String"))
    } else {
        false
    }
}

fn generate_enum_wrapper(
    data_enum: &DataEnum,
    type_name: &Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    let wrapper_name = Ident::new(&format!("{}Wrapper", type_name), type_name.span());

    let wrapper_variants: syn::Result<Vec<_>> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            match &variant.fields {
                Fields::Unit => Ok(quote! { #variant_ident }),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    let inner_ty = &fields.unnamed[0].ty;
                    let inner_wrapper_ty = get_wrapper_ident(inner_ty, variant.ident.span())?;
                    Ok(quote! { #variant_ident(#inner_wrapper_ty) })
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

        Ok(match &variant.fields {
            Fields::Unit => quote! {
                p if p.starts_with(base_path.push(#variant_name).as_ref()) => #wrapper_name::#variant_ident
            },
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let inner_wrapper_ty = get_wrapper_ident(&fields.unnamed[0].ty, variant.ident.span())?;
                quote! {
                    p if p.starts_with(base_path.push(#variant_name).as_ref()) => #wrapper_name::#variant_ident(#inner_wrapper_ty::new(ctx, base_path.push(#variant_name)))
                }
            }
            _ => unreachable!(),
        })
    }).collect::<syn::Result<Vec<_>>>()?;

    let load_arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => quote! {
                #wrapper_name::#variant_ident => #type_name::#variant_ident
            },
            Fields::Unnamed(_) => quote! {
                #wrapper_name::#variant_ident(inner_wrapper) => #type_name::#variant_ident(inner_wrapper.load(ctx))
            },
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

fn get_wrapper_ident(ty: &Type, span: proc_macro2::Span) -> syn::Result<Ident> {
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

fn get_option_inner_type(ty: &Type) -> syn::Result<Type> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Option"
        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let syn::GenericArgument::Type(inner_ty) = &args.args[0]
    {
        return Ok(inner_ty.clone());
    }
    Err(Error::new(ty.span(), "Expected Option<T> type"))
}

#[proc_macro_derive(Root)]
pub fn derive_root(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        syn::Data::Struct(data_struct) => generate_root_struct(data_struct, name),
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
    let expanded = quote! {
        #body
    };

    TokenStream::from(expanded)
}

fn generate_root_struct(
    data_struct: &DataStruct,
    type_name: &Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    match &data_struct.fields {
        Fields::Named(_) => {
            let wrapper_name = Ident::new(&format!("{}Wrapper", type_name), type_name.span());
            Ok(quote! {
                impl #type_name {
                    pub fn init(self, ctx: &impl stdlib::WriteContext) {
                        ctx.__set(stdlib::DotPathBuf::new(), self)
                    }
                }

                pub fn storage(ctx: &impl stdlib::ReadContext) -> #wrapper_name {
                    #wrapper_name::new(ctx, stdlib::DotPathBuf::new())
                }
            })
        }
        _ => Err(Error::new(
            type_name.span(),
            "Root derive only supports structs with named fields",
        )),
    }
}

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = ContractConfig::from_list(&attr_args).unwrap();

    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&to_pascal_case(&config.name)).unwrap();
    let boilerplate = quote! {
        use stdlib::*;

        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
            additional_derives: [stdlib::Store, stdlib::Wrapper],
        });

        use kontor::built_in::*;
        use kontor::built_in::foreign::ContractAddressWrapper;

        impl ReadContext for context::ViewContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl ReadContext for context::ProcContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl WriteContext for context::ProcContext {
            fn __set_str(&self, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn __set_u64(&self, path: &str, value: u64) {
                self.set_u64(path, value)
            }

            fn __set_s64(&self, path: &str, value: i64) {
                self.set_s64(path, value)
            }

            fn __set_void(&self, path: &str) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store>(&self, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }
        }

        impl ReadWriteContext for context::ProcContext {}

        struct #name;
    };

    boilerplate.into()
}
