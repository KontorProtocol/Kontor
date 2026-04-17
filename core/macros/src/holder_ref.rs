use proc_macro::TokenStream;
use quote::quote;
use syn::{Path, parse_macro_input};

pub fn generate(input: TokenStream) -> TokenStream {
    let ty = parse_macro_input!(input as Path);

    let expanded = quote! {
        #[automatically_derived]
        impl core::fmt::Display for #ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    Self::XOnlyPubkey(s) => write!(f, "{s}"),
                    Self::ContractId(s) => write!(f, "{s}"),
                    Self::SignerId(id) => write!(f, "__sid__{id}"),
                    Self::Core => write!(f, "core"),
                    Self::Burner => write!(f, "burn"),
                    Self::Utxo(out_point) => write!(f, "{}:{}", out_point.txid, out_point.vout),
                }
            }
        }

        #[automatically_derived]
        impl core::str::FromStr for #ty {
            type Err = alloc::string::String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(if s == "core" {
                    Self::Core
                } else if s == "burn" {
                    Self::Burner
                } else if let Some(id_str) = s.strip_prefix("__sid__") {
                    let id = id_str.parse::<u64>()
                        .map_err(|e| alloc::format!("invalid signer id: {e}"))?;
                    Self::SignerId(id)
                } else if s.starts_with("__cid__") {
                    Self::ContractId(s.to_string())
                } else if let Some((txid, vout)) = s.rsplit_once(':') {
                    let vout = vout.parse::<u64>()
                        .map_err(|e| alloc::format!("invalid vout: {e}"))?;
                    Self::Utxo(OutPoint { txid: txid.to_string(), vout })
                } else {
                    Self::XOnlyPubkey(s.to_string())
                })
            }
        }

        #[automatically_derived]
        impl core::cmp::PartialEq for #ty {
            fn eq(&self, other: &Self) -> bool {
                match (self, other) {
                    (Self::XOnlyPubkey(a), Self::XOnlyPubkey(b)) => a == b,
                    (Self::ContractId(a), Self::ContractId(b)) => a == b,
                    (Self::SignerId(a), Self::SignerId(b)) => a == b,
                    (Self::Core, Self::Core) => true,
                    (Self::Burner, Self::Burner) => true,
                    (Self::Utxo(a), Self::Utxo(b)) => a.txid == b.txid && a.vout == b.vout,
                    _ => false,
                }
            }
        }

        #[automatically_derived]
        impl core::cmp::Eq for #ty {}
    };

    TokenStream::from(expanded)
}
