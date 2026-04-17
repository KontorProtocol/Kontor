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
