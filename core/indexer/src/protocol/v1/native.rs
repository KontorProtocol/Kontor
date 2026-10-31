use anyhow::Result;
use indexer_types::{BuildProvenance, CommitId, Forge, Platform, Source};

use crate::built_info::GIT_COMMIT_HASH;

pub const TOKEN: &[u8] = include_bytes!("../../../../../native-contracts/binaries/token.wasm.br");
pub const FILESTORAGE: &[u8] =
    include_bytes!("../../../../../native-contracts/binaries/filestorage.wasm.br");
pub const STAKING: &[u8] =
    include_bytes!("../../../../../native-contracts/binaries/staking.wasm.br");
pub const SYSTEM: &[u8] = include_bytes!("../../../../../native-contracts/binaries/system.wasm.br");
pub const NFT: &[u8] = include_bytes!("../../../../../native-contracts/binaries/nft.wasm.br");

/// Ordered list of native contracts published at genesis. Publish order
/// determines contract IDs (1-indexed, assigned in iteration order), so
/// treat additions as a protocol-level decision. The test runtime uses
/// `NATIVE_CONTRACTS.len()` to know how many IDs to expect; adding to
/// this list is the only change needed.
pub const NATIVE_CONTRACTS: &[(&str, &[u8])] = &[
    ("token", TOKEN),
    ("filestorage", FILESTORAGE),
    ("staking", STAKING),
    ("system", SYSTEM),
    ("nft", NFT),
];

/// Native contracts get 1-indexed ids in publish order (1..=len). Used by the
/// runtime to select the privileged (native) linker at instantiation.
pub fn is_native_contract_id(contract_id: u64) -> bool {
    contract_id >= 1 && (contract_id as usize) <= NATIVE_CONTRACTS.len()
}

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The 1-indexed contract id a native contract is published at (its position in
/// `NATIVE_CONTRACTS` + 1). `const` so it can't drift from the slice: reorder or
/// rename and the id follows automatically; remove it and this fails to compile.
const fn native_contract_id(name: &[u8]) -> u64 {
    let mut i = 0;
    while i < NATIVE_CONTRACTS.len() {
        if bytes_eq(NATIVE_CONTRACTS[i].0.as_bytes(), name) {
            return (i as u64) + 1;
        }
        i += 1;
    }
    panic!("native contract not found");
}

/// The native token's contract id. Its ledger denominates the storage deposit, so
/// its own storage must be EXEMPT from deposits — else a token-ledger write would
/// owe a token deposit, which is itself a token-ledger write (the recursion that
/// forces the exemption). Bounded instead by gas. DERIVED from `NATIVE_CONTRACTS`
/// (not hardcoded `1`) so reordering the slice can't silently un-exempt the token.
pub const TOKEN_CONTRACT_ID: u64 = native_contract_id(b"token");

/// Whether writes to this contract are exempt from storage deposits. Only the
/// native token (the deposit-denominating ledger) — every other contract, native
/// or user, pays deposits to bound its growth. NOTE: if another core ledger that
/// holds token-denominated balances is added later (e.g. staking), it may need the
/// same recursion exemption — extend this set, don't assume token is the only one.
pub fn is_deposit_exempt(contract_id: u64) -> bool {
    contract_id == TOKEN_CONTRACT_ID
}

pub(crate) fn records_result(contract_id: u64, function: &str) -> bool {
    !(contract_id == TOKEN_CONTRACT_ID && matches!(function, "hold" | "release"))
}

/// Provenance for the native/genesis contracts. `platform` + the pinned `image`
/// come from the committed native-contracts `build.json`; the source is the
/// Kontor repo at the node's build commit — which reproduces the committed
/// binaries (the reproducible-build gate proves that at every commit). A missing
/// git commit (e.g. a tarball build) → an all-zero "unknown" commit.
pub(crate) fn native_provenance() -> Result<BuildProvenance> {
    const BUILD_JSON: &str = include_str!("../../../../../native-contracts/binaries/build.json");

    #[derive(serde::Deserialize)]
    struct BuildMeta {
        platform: String,
        image: String,
    }
    let meta: BuildMeta = serde_json::from_str(BUILD_JSON)?;

    let commit = GIT_COMMIT_HASH
        .and_then(|h| {
            let mut bytes = [0u8; 20];
            hex::decode_to_slice(h, &mut bytes).ok().map(|_| bytes)
        })
        .map(CommitId::Sha1)
        .unwrap_or(CommitId::Sha1([0u8; 20]));

    let provenance = BuildProvenance {
        source: Source {
            forge: Forge::GitHub,
            owner: "KontorProtocol".to_string(),
            repo: "Kontor".to_string(),
            commit,
        },
        image: meta.image,
        platform: Platform::parse(&meta.platform)?,
    };
    provenance.validate()?;
    Ok(provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The deposit exemption is consensus-relevant (exempt rows carry no depositor and
    // never owe a deposit). Pin it: ONLY the token is exempt, its id is derived from
    // the slice (not a hardcoded 1), and every other native contract pays deposits.
    #[test]
    fn only_the_token_is_deposit_exempt() {
        assert_eq!(TOKEN_CONTRACT_ID, native_contract_id(b"token"));
        assert!(is_deposit_exempt(TOKEN_CONTRACT_ID));
        for (name, _) in NATIVE_CONTRACTS {
            let id = native_contract_id(name.as_bytes());
            assert_eq!(
                is_deposit_exempt(id),
                *name == "token",
                "only `token` may be deposit-exempt; `{name}` (id {id}) must not be",
            );
        }
        // A user contract id (above the native range) is never exempt.
        assert!(!is_deposit_exempt(NATIVE_CONTRACTS.len() as u64 + 1));
    }
}
