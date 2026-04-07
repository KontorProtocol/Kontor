use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Ident, Token, parse::Parse, parse::ParseStream, punctuated::Punctuated};

pub struct Config {
    modules: Vec<Ident>,
}

impl Parse for Config {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let modules = Punctuated::<Ident, Token![,]>::parse_terminated(input)?;
        Ok(Self {
            modules: modules.into_iter().collect(),
        })
    }
}

pub fn generate(config: Config) -> TokenStream {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let tests_dir = std::path::Path::new(&manifest_dir).join("tests");

    let mut test_fns = Vec::new();

    for module in &config.modules {
        let module_file = tests_dir
            .join("contract_all")
            .join(format!("{}.rs", module));
        if !module_file.exists() {
            return syn::Error::new(
                module.span(),
                format!("Test file not found: {}", module_file.display()),
            )
            .to_compile_error();
        }

        let source = std::fs::read_to_string(&module_file).expect("Failed to read test file");
        let syntax = syn::parse_file(&source).expect("Failed to parse test file");

        for item in &syntax.items {
            if let syn::Item::Fn(func) = item {
                if func.sig.asyncness.is_none() {
                    continue;
                }
                let has_test_attr = func.attrs.iter().any(|attr| {
                    let path = attr.path();
                    let path_str = path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    if path_str != "testlib::test" {
                        return false;
                    }
                    let attr_str = attr.to_token_stream().to_string();
                    !attr_str.contains("local_only")
                });
                if !has_test_attr {
                    continue;
                }

                let fn_name = &func.sig.ident;
                let module_str = module.to_string();
                let test_name = format!("regtest_{module_str}_{fn_name}");
                let test_ident = syn::Ident::new(&test_name, fn_name.span());

                test_fns.push(quote! {
                    #[tokio::test]
                    async fn #test_ident() -> anyhow::Result<()> {
                        if std::env::var("REGTEST").is_err() {
                            return Ok(());
                        }
                        let mut runtime = shared_cluster::new_runtime().await?;
                        #module::#fn_name(&mut runtime).await
                    }
                });
            }
        }
    }

    quote! {
        #(#test_fns)*
    }
}
