use proc_macro::TokenStream;
use quote::quote;
use syn::{Path, parse_macro_input};

pub fn generate(input: TokenStream) -> TokenStream {
    let ty = parse_macro_input!(input as Path);

    let expanded = quote! {
        #[automatically_derived]
        impl ::core::fmt::Display for #ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}_{}_{}", self.name, self.height, self.tx_index)
            }
        }

        #[automatically_derived]
        impl ::core::str::FromStr for #ty {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let parts: Vec<&str> = s.split('_').collect();
                if parts.len() != 3 {
                    return Err(format!("expected 3 parts separated by '_', got: {s}"));
                }
                let name = parts[0].to_string();
                let height = parts[1].parse::<u64>()
                    .map_err(|e| format!("invalid height: {e}"))?;
                let tx_index = parts[2].parse::<u64>()
                    .map_err(|e| format!("invalid tx_index: {e}"))?;
                Ok(#ty { name, height, tx_index })
            }
        }

        #[automatically_derived]
        impl ::core::cmp::PartialEq for #ty {
            fn eq(&self, other: &Self) -> bool {
                self.name == other.name &&
                self.height == other.height &&
                self.tx_index == other.tx_index
            }
        }

        #[automatically_derived]
        impl ::core::cmp::Eq for #ty {}
    };

    TokenStream::from(expanded)
}
