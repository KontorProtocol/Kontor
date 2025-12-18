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
                        stdlib::WriteStorage::__set(&alloc::rc::Rc::new(ctx.storage()),stdlib::DotPathBuf::new(), self)
                    }
                }

                impl crate::ProcContext {
                    pub fn model(&self) -> #write_model_name {
                        #write_model_name::new(alloc::rc::Rc::new(self.storage()), DotPathBuf::new())
                    }
                }

                impl crate::ViewContext {
                    pub fn model(&self) -> #model_name {
                        #model_name::new(alloc::rc::Rc::new(self.storage()), DotPathBuf::new())
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
