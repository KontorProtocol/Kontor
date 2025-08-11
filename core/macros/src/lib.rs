extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    DataEnum, DataStruct, DeriveInput, Error, Fields, Ident, PathArguments, Result, Type,
    parse_macro_input,
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
        impl #impl_generics Store for #name #ty_generics #where_clause {
            fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: #name #ty_generics) {
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

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = ContractConfig::from_list(&attr_args).unwrap();

    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&to_pascal_case(&config.name)).unwrap();
    let boilerplate = quote! {
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
        });

        use kontor::built_in::*;

        use stdlib::*;

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

            fn __set<T: Store>(&self, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }
        }

        impl ReadWriteContext for context::ProcContext {}

        impl Store for foreign::ContractAddress {
            fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: foreign::ContractAddress) {
                ctx.__set(base_path.push("name"), value.name);
                ctx.__set(base_path.push("height"), value.height);
                ctx.__set(base_path.push("tx_index"), value.tx_index);
            }
        }

        struct #name;
    };

    boilerplate.into()
}
