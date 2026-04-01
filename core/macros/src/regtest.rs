use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote};
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

    let mut mod_decls = Vec::new();
    let mut test_calls = Vec::new();

    for module in &config.modules {
        let module_file = tests_dir.join(format!("{}.rs", module));
        if !module_file.exists() {
            return syn::Error::new(
                module.span(),
                format!("Test file not found: {}", module_file.display()),
            )
            .to_compile_error();
        }

        let source = std::fs::read_to_string(&module_file).expect("Failed to read test file");
        let syntax = syn::parse_file(&source).expect("Failed to parse test file");

        mod_decls.push(quote! { mod #module; });

        // Find all functions annotated with #[testlib::test(..., shared)] or
        // #[testlib::test(..., regtest_only)]
        for item in &syntax.items {
            if let syn::Item::Fn(func) = item {
                if func.sig.asyncness.is_none() {
                    continue;
                }
                let is_shared = func.attrs.iter().any(|attr| {
                    let path = attr.path();
                    let path_str = quote::quote!(#path).to_string();
                    if !path_str.contains("test") {
                        return false;
                    }
                    let attr_str = attr.to_token_stream().to_string();
                    attr_str.contains("shared") || attr_str.contains("regtest_only")
                });
                if !is_shared {
                    continue;
                }

                let fn_name = &func.sig.ident;
                let test_name = fn_name.to_string();

                test_calls.push(quote! {
                    run_test(#test_name, &filter, async {
                        let mut runtime = new_runtime(reg_tester.clone(), contract_reader.clone());
                        #module::#fn_name(&mut runtime).await
                    }).await;
                });
            }
        }
    }

    let contracts_dir_ident = format_ident!("contracts_dir");

    quote! {
        use anyhow::Result;
        use indexer::reg_tester::RegTesterCluster;
        use testlib::*;

        #(#mod_decls)*

        #[tokio::test]
        #[serial_test::serial]
        async fn regtest_all() -> Result<()> {
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            let cluster = RegTesterCluster::setup(3).await?;
            let #contracts_dir_ident = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../test-contracts")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let contract_reader = ContractReader::new(&#contracts_dir_ident).await?;

            let reg_tester = cluster.reg_tester(0).await?;
            reg_tester.pre_create_identities(100).await?;

            let filter = std::env::var("REGTEST_FILTER").unwrap_or_default();

            #(#test_calls)*

            cluster.teardown().await?;
            Ok(())
        }

        fn new_runtime(
            reg_tester: indexer::reg_tester::RegTester,
            contract_reader: ContractReader,
        ) -> Runtime {
            Runtime::new_regtest_with_reader(contract_reader, reg_tester)
        }

        async fn run_test(name: &str, filter: &str, test: impl std::future::Future<Output = Result<()>>) {
            if !filter.is_empty() && !name.contains(filter) {
                return;
            }
            let start = std::time::Instant::now();
            match test.await {
                Ok(()) => tracing::info!("PASS: {} ({:.1}s)", name, start.elapsed().as_secs_f64()),
                Err(e) => panic!("FAIL: {}: {:?}", name, e),
            }
        }
    }
}
