use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::quote;

#[derive(FromMeta)]
pub struct Config {
    host: Option<bool>,
}

pub fn generate(config: Config) -> TokenStream {
    let host = config.host.unwrap_or_default();
    let signer_and_holder_impls = if host {
        // Host mode: Display is impl'd directly on indexer_types::Signer
        quote! {}
    } else {
        quote! {
            impl core::fmt::Display for kontor::built_in::context::Signer {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", self.key())
                }
            }

            #[automatically_derived]
            impl core::fmt::Display for kontor::built_in::context::Holder {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", self.key())
                }
            }

            impl kontor::built_in::context::Network {
                /// True on the production Bitcoin mainnet chain.
                pub fn is_mainnet(&self) -> bool {
                    matches!(self, kontor::built_in::context::Network::Mainnet)
                }
                /// True on the local regtest chain (dev/test).
                pub fn is_regtest(&self) -> bool {
                    matches!(self, kontor::built_in::context::Network::Regtest)
                }
            }

            #[automatically_derived]
            impl Clone for kontor::built_in::context::Holder {
                fn clone(&self) -> Self {
                    kontor::built_in::context::Holder::from_ref(&self.as_ref()).expect("clone of valid Holder failed")
                }
            }

            #[automatically_derived]
            impl PartialEq for kontor::built_in::context::Holder {
                fn eq(&self, other: &Self) -> bool {
                    self.key() == other.key()
                }
            }

            #[automatically_derived]
            impl Eq for kontor::built_in::context::Holder {}

            #[automatically_derived]
            impl core::str::FromStr for kontor::built_in::context::Holder {
                type Err = alloc::string::String;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    let holder_ref: kontor::built_in::context::HolderRef = s.parse()?;
                    kontor::built_in::context::Holder::from_ref(&holder_ref)
                        .map_err(|e| alloc::format!("{:?}", e))
                }
            }

            #[automatically_derived]
            impl TryFrom<kontor::built_in::context::HolderRef> for kontor::built_in::context::Holder {
                type Error = error::Error;

                fn try_from(holder_ref: kontor::built_in::context::HolderRef) -> Result<Self, Self::Error> {
                    kontor::built_in::context::Holder::from_ref(&holder_ref)
                }
            }

            #[automatically_derived]
            impl TryFrom<&kontor::built_in::context::HolderRef> for kontor::built_in::context::Holder {
                type Error = error::Error;

                fn try_from(holder_ref: &kontor::built_in::context::HolderRef) -> Result<Self, Self::Error> {
                    kontor::built_in::context::Holder::from_ref(holder_ref)
                }
            }

            #[automatically_derived]
            impl From<&kontor::built_in::context::Signer> for kontor::built_in::context::Holder {
                fn from(signer: &kontor::built_in::context::Signer) -> Self {
                    signer.as_holder()
                }
            }

            #[automatically_derived]
            impl From<kontor::built_in::context::Signer> for kontor::built_in::context::Holder {
                fn from(signer: kontor::built_in::context::Signer) -> Self {
                    signer.as_holder()
                }
            }

            #[automatically_derived]
            impl From<&kontor::built_in::context::Signer> for kontor::built_in::context::HolderRef {
                fn from(signer: &kontor::built_in::context::Signer) -> Self {
                    signer.as_ref()
                }
            }

            #[automatically_derived]
            impl From<kontor::built_in::context::Signer> for kontor::built_in::context::HolderRef {
                fn from(signer: kontor::built_in::context::Signer) -> Self {
                    signer.as_ref()
                }
            }

            #[automatically_derived]
            impl From<&kontor::built_in::context::Holder> for kontor::built_in::context::HolderRef {
                fn from(holder: &kontor::built_in::context::Holder) -> Self {
                    holder.as_ref()
                }
            }

            #[automatically_derived]
            impl From<kontor::built_in::context::Holder> for kontor::built_in::context::HolderRef {
                fn from(holder: kontor::built_in::context::Holder) -> Self {
                    holder.as_ref()
                }
            }

            // `SignerRef` is the two real-account arms of `HolderRef`;
            // widening it is total. Lets `detach` turn an op-return
            // recipient into a `HolderRef` (then a `Holder`) directly.
            #[automatically_derived]
            impl From<kontor::built_in::context::SignerRef>
                for kontor::built_in::context::HolderRef
            {
                fn from(signer_ref: kontor::built_in::context::SignerRef) -> Self {
                    match signer_ref {
                        kontor::built_in::context::SignerRef::SignerId(id) => {
                            Self::SignerId(id)
                        }
                        kontor::built_in::context::SignerRef::XOnlyPubkey(pk) => {
                            Self::XOnlyPubkey(pk)
                        }
                    }
                }
            }
        }
    };

    quote! {
        contract_address!(kontor::built_in::context::ContractAddress);
        holder_ref!(kontor::built_in::context::HolderRef);

        #signer_and_holder_impls
    }
}
