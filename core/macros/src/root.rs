use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataStruct, Error, Fields, Ident, Result};

pub fn generate_root_struct(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(_) => {
            let write_model_name =
                Ident::new(&format!("{}WriteModel", type_name), type_name.span());
            let model_name = Ident::new(&format!("{}Model", type_name), type_name.span());
            Ok(quote! {
                impl #type_name {
                    pub fn init(self, ctx: &crate::ProcContext) {
                        stdlib::WriteStorage::__set(&alloc::rc::Rc::new(ctx.storage()),stdlib::KeyPath::new(), self)
                    }
                }

                // The context types are the shared `built-in-types` wrappers
                // (foreign here), so `model()` rides on `stdlib::HasRootModel`
                // instead of an inherent impl — call syntax unchanged; the
                // local root type as the trait parameter is what passes the
                // orphan rule.
                impl stdlib::HasRootModel<#type_name> for crate::ProcContext {
                    type Model = #write_model_name<crate::context::ProcStorage>;
                    fn model(&self) -> Self::Model {
                        #write_model_name::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
                    }
                }

                impl stdlib::HasRootModel<#type_name> for crate::ViewContext {
                    type Model = #model_name<crate::context::ViewStorage>;
                    fn model(&self) -> Self::Model {
                        #model_name::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
                    }
                }
            })
        }
        _ => Err(Error::new(
            type_name.span(),
            "Root derive only supports structs with named fields",
        )),
    }
}
