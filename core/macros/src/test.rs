use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::ItemFn;

#[derive(FromMeta)]
#[darling(derive_syn_parse)]
pub struct Config {
    pub contracts_dir: Option<String>,
    pub logging: Option<bool>,
    /// When true, generates only a `pub async fn` taking `runtime: &mut Runtime`
    /// with no local test wrapper. For tests that only work against a running node.
    pub regtest_only: Option<bool>,
    /// When true, generates only a local test (no pub async fn).
    /// Excluded from regtest_all discovery.
    pub local_only: Option<bool>,
}

pub fn generate(config: Config, func: ItemFn) -> TokenStream {
    let attrs = func.attrs;
    let fn_name = &func.sig.ident;
    let fn_block = &func.block;
    let abs_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("Failed to canonicalize path");
    let contracts_dir = config.contracts_dir.unwrap_or("../".to_string());
    let path = abs_path.join(&contracts_dir);
    if !path.exists() {
        panic!("Contracts directory does not exist: {}", path.display());
    }
    let regtest_only = config.regtest_only.unwrap_or(false);
    let local_only = config.local_only.unwrap_or(false);

    let logging = if config.logging.unwrap_or(false) {
        quote! {
            logging();
        }
    } else {
        quote! {}
    };

    if local_only {
        // Local-only: standard test, not discoverable by regtest_tests! macro
        quote! {
            #[cfg(not(feature = "regtest-runner"))]
            #[tokio::test]
            #(#attrs)*
            async fn #fn_name() -> Result<()> {
                let abs_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).canonicalize().unwrap();
                let contracts_dir = abs_path.join(#contracts_dir).to_string_lossy().to_string();
                #logging
                let mut runtime = Runtime::new_local(RuntimeConfig::builder().contracts_dir(&contracts_dir).build()).await?;
                let runtime = &mut runtime;
                #fn_block
            }
        }
    } else if regtest_only {
        // Regtest-only: public function, no local test wrapper
        quote! {
            #(#attrs)*
            pub async fn #fn_name(runtime: &mut Runtime) -> Result<()>
            #fn_block
        }
    } else {
        // Default: public reusable function + _local test wrapper
        // The _local wrapper is suppressed when compiled with the regtest-runner feature
        // to avoid duplicate tests in the regtest_all binary.
        let local_test_name = format_ident!("{}_local", fn_name);

        quote! {
            #(#attrs)*
            pub async fn #fn_name(runtime: &mut Runtime) -> Result<()>
            #fn_block

            #[cfg(not(feature = "regtest-runner"))]
            #[tokio::test]
            async fn #local_test_name() -> Result<()> {
                let abs_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).canonicalize().unwrap();
                let contracts_dir = abs_path.join(#contracts_dir).to_string_lossy().to_string();
                #logging
                let mut runtime = Runtime::new_local(RuntimeConfig::builder().contracts_dir(&contracts_dir).build()).await?;
                #fn_name(&mut runtime).await
            }
        }
    }
}
