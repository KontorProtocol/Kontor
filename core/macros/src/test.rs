use darling::FromMeta;

#[derive(FromMeta)]
#[darling(derive_syn_parse)]
pub struct Config {
    pub contracts_dir: Option<String>,
    pub mode: Option<String>,
    pub logging: Option<bool>,
}
