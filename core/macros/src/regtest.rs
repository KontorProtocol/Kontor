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
    let mut module_tasks = Vec::new();

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

        mod_decls.push(quote! {
            #[allow(dead_code, unused_imports)]
            mod #module;
        });

        // Collect test functions for this module
        let mut test_calls = Vec::new();
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
                    // Exclude local_only tests
                    let attr_str = attr.to_token_stream().to_string();
                    !attr_str.contains("local_only")
                });
                if !has_test_attr {
                    continue;
                }

                let fn_name = &func.sig.ident;
                let test_name = fn_name.to_string();
                let module_str = module.to_string();
                let qualified_name = format!("{}::{}", module_str, test_name);

                test_calls.push(quote! {
                    run_test(#qualified_name, &filter, async {
                        let mut runtime = new_runtime(reg_tester.clone(), contract_reader.clone());
                        #module::#fn_name(&mut runtime).await
                    }).await?;
                });
            }
        }

        if test_calls.is_empty() {
            continue;
        }

        let module_str = module.to_string();

        module_tasks.push(quote! {
            {
                let cluster = cluster.clone();
                let contract_reader = contract_reader.clone();
                let filter = filter.clone();
                tokio::task::spawn_local(async move {
                    if !filter.is_empty()
                        && !#module_str.contains(&*filter)
                        && !has_matching_test(#module_str, &filter)
                    {
                        return Ok::<(), anyhow::Error>(());
                    }
                    let reg_tester = cluster.new_module_reg_tester().await?;
                    let start = std::time::Instant::now();
                    #(#test_calls)*
                    tracing::info!("MODULE DONE: {} ({:.1}s)", #module_str, start.elapsed().as_secs_f64());
                    Ok(())
                })
            }
        });
    }

    let contracts_dir_ident = format_ident!("contracts_dir");

    // Generate per-module filter match arms
    let mut filter_match_arms = Vec::new();
    for module in &config.modules {
        let module_file = tests_dir.join(format!("{}.rs", module));
        let source = std::fs::read_to_string(&module_file).expect("Failed to read test file");
        let syntax = syn::parse_file(&source).expect("Failed to parse test file");
        let module_str = module.to_string();

        let test_names: Vec<String> = syntax
            .items
            .iter()
            .filter_map(|item| {
                if let syn::Item::Fn(func) = item
                    && func.sig.asyncness.is_some()
                    && func.attrs.iter().any(|attr| {
                        let path_str = attr
                            .path()
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::");
                        path_str == "testlib::test"
                            && !attr.to_token_stream().to_string().contains("local_only")
                    })
                {
                    let name = func.sig.ident.to_string();
                    return Some(format!("{}::{}", module_str, name));
                }
                None
            })
            .collect();

        let name_checks: Vec<_> = test_names
            .iter()
            .map(|name| quote! { if #name.contains(filter) { return true; } })
            .collect();
        filter_match_arms.push(quote! {
            if module == #module_str {
                #(#name_checks)*
            }
        });
    }

    quote! {
        use anyhow::Result;
        use indexer::reg_tester::RegTesterCluster;
        use testlib::*;

        #(#mod_decls)*

        #[tokio::test(flavor = "multi_thread")]
        #[serial_test::serial]
        async fn regtest_all() -> Result<()> {
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            let cluster = RegTesterCluster::setup(3, 300, 50).await?;
            let cluster = std::sync::Arc::new(cluster);
            let #contracts_dir_ident = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../test-contracts")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let contract_reader = ContractReader::new(&#contracts_dir_ident).await?;

            let filter = std::env::var("REGTEST_FILTER").unwrap_or_default();

            let local = tokio::task::LocalSet::new();
            let mut failures = local.run_until(async {
                let handles: Vec<_> = vec![#(#module_tasks),*];

                let mut failures = Vec::new();
                for handle in handles {
                    match handle.await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => failures.push(e),
                        Err(e) => failures.push(anyhow::anyhow!("Task panicked: {:?}", e)),
                    }
                }
                failures
            }).await;

            match std::sync::Arc::try_unwrap(cluster) {
                Ok(cluster) => {
                    if let Err(e) = cluster.teardown().await {
                        failures.push(anyhow::anyhow!("cluster teardown failed: {e:?}"));
                    }
                }
                Err(_) => {
                    failures.push(anyhow::anyhow!("cluster still has references after all tasks completed"));
                }
            }

            if !failures.is_empty() {
                eprintln!("\n{} failure(s):", failures.len());
                for e in &failures {
                    eprintln!("  - {e:?}");
                }
                anyhow::bail!("{} failure(s)", failures.len());
            }

            Ok(())
        }

        fn new_runtime(
            reg_tester: indexer::reg_tester::RegTester,
            contract_reader: ContractReader,
        ) -> Runtime {
            Runtime::new_regtest_with_reader(contract_reader, reg_tester)
        }

        async fn run_test(name: &str, filter: &str, test: impl std::future::Future<Output = Result<()>>) -> Result<()> {
            if !filter.is_empty() && !name.contains(filter) {
                return Ok(());
            }
            let start = std::time::Instant::now();
            match test.await {
                Ok(()) => {
                    tracing::info!("PASS: {} ({:.1}s)", name, start.elapsed().as_secs_f64());
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("FAIL: {}: {:?}", name, e);
                    Err(e)
                }
            }
        }

        fn has_matching_test(module: &str, filter: &str) -> bool {
            #(#filter_match_arms)*
            false
        }
    }
}
