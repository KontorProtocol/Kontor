use darling::FromMeta;

#[derive(FromMeta)]
#[darling(derive_syn_parse)]
pub struct Config {
    pub contracts_dir: String,
    pub mode: Option<String>,
}
