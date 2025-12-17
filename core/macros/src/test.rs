use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemFn;

#[derive(FromMeta)]
#[darling(derive_syn_parse)]
pub struct Config {
    pub contracts_dir: Option<String>,
    pub mode: Option<String>,
    pub logging: Option<bool>,
}

pub fn generate(config: Config, func: ItemFn) -> TokenStream {
    let attrs = func.attrs;
    let fn_name = &func.sig.ident;
    let fn_generics = &func.sig.generics;
    let fn_inputs = &func.sig.inputs;
    let fn_vis = &func.vis;
    let fn_block = &func.block;
    let abs_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("Failed to canonicalize path");
    let contracts_dir = config.contracts_dir.unwrap_or("../".to_string());
    let path = abs_path.join(&contracts_dir);
    if !path.exists() {
        panic!("Contracts directory does not exist: {}", path.display());
    }
    let mode = config.mode.unwrap_or("local".to_string());

    let body = if mode == "regtest" {
        quote! {
            let (
                _bitcoin_data_dir,
                bitcoin_child,
                bitcoin_client,
                _kontor_data_dir,
                kontor_child,
                kontor_client,
                identity,
            ) = RegTester::setup().await?;
            let result = tokio::spawn({
                let bitcoin_client = bitcoin_client.clone();
                let kontor_client = kontor_client.clone();
                async move {
                    let mut reg_tester = RegTester::new(identity, bitcoin_client, kontor_client).await?;
                    let mut runtime = &mut Runtime::new_regtest(RuntimeConfig::builder().contracts_dir(&contracts_dir).build(), reg_tester.clone()).await?;
                    #fn_block
                }
            })
            .await;
            RegTester::teardown(bitcoin_client, bitcoin_child, kontor_client, kontor_child).await?;
            result?
        }
    } else {
        quote! {
            let mut runtime = &mut Runtime::new_local(RuntimeConfig::builder().contracts_dir(&contracts_dir).build()).await?;
            #fn_block
        }
    };

    let serial = if mode == "regtest" {
        quote! {
            #[serial_test::serial]
        }
    } else {
        quote! {}
    };

    let logging = if config.logging.unwrap_or(false) {
        quote! {
            logging();
        }
    } else {
        quote! {}
    };

    let output = quote! {
        #[tokio::test]
        #serial
        #(#attrs)*
        #fn_vis async fn #fn_name #fn_generics(#fn_inputs) -> Result<()> {
            let abs_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).canonicalize().unwrap();
            let contracts_dir = abs_path.join(#contracts_dir).to_string_lossy().to_string();
            #logging
            #body
        }
    };

    output
}
