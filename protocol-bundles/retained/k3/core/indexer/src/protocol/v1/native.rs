use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};
use indexer_types::BuildProvenance;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::storage_identity::CORE_SIGNER_ID;

pub const TOKEN: &[u8] = include_bytes!("native/token.wasm.br");
pub const FILESTORAGE: &[u8] = include_bytes!("native/filestorage.wasm.br");
pub const STAKING: &[u8] = include_bytes!("native/staking.wasm.br");
pub const SYSTEM: &[u8] = include_bytes!("native/system.wasm.br");
pub const NFT: &[u8] = include_bytes!("native/nft.wasm.br");

/// Ordered list of native contracts published at genesis. Publish order
/// determines contract IDs (1-indexed, assigned in iteration order). This
/// retained list and its identity must not change when adding a new protocol.
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
pub(crate) const STAKING_CONTRACT_ID: u64 = native_contract_id(b"staking");

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

// This identity covers only the initial native set, not the Bitcoin network,
// validator committee or sigma-min configuration.
pub(crate) const NATIVE_GENESIS_ID: &str =
    "1770b1018bc787d97f1f93fbe058e516c0d9bb291d12c98840e9bd9f29af3e6f";
pub(crate) const NATIVE_PROVENANCE: &[u8] = include_bytes!("native/provenance.bin");
const MANIFEST: &[u8] = include_bytes!("native/manifest.json");
const METADATA: &[(&str, &[u8])] = &[
    ("build.json", include_bytes!("native/build.json")),
    ("toolchain.json", include_bytes!("native/toolchain.json")),
    ("provenance.json", include_bytes!("native/provenance.json")),
    ("provenance.bin", NATIVE_PROVENANCE),
];

#[derive(Deserialize)]
struct NativeManifest {
    core_signer_id: u64,
    contracts: Vec<NativeContractManifest>,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct NativeContractManifest {
    id: u64,
    signer_id: u64,
    name: String,
    sha256: String,
    privileged: bool,
    deposit_exempt: bool,
    unrecorded_results: Vec<String>,
}

fn verify_digest(bytes: &[u8], expected: &str) -> Result<()> {
    ensure!(
        hex::encode(Sha256::digest(bytes)) == expected,
        "retained native input digest mismatch"
    );
    Ok(())
}

fn validate_inputs(
    manifest: &[u8],
    contracts: &[(&str, &[u8])],
    metadata: &[(&str, &[u8])],
) -> Result<()> {
    verify_digest(manifest, NATIVE_GENESIS_ID)?;
    let manifest: NativeManifest = serde_json::from_slice(manifest)?;
    ensure!(
        manifest.core_signer_id == CORE_SIGNER_ID,
        "retained core signer mismatch"
    );
    ensure!(
        manifest.contracts.len() == contracts.len(),
        "retained native contract count mismatch"
    );
    for (index, (entry, (name, bytes))) in manifest.contracts.iter().zip(contracts).enumerate() {
        let id = index as u64 + 1;
        ensure!(entry.signer_id == id + 1, "retained native signer mismatch");
        ensure!(
            entry.id == id && entry.name == *name,
            "retained native publication order mismatch"
        );
        ensure!(
            entry.privileged == is_native_contract_id(id),
            "retained native privilege mismatch"
        );
        ensure!(
            entry.deposit_exempt == is_deposit_exempt(id),
            "retained native deposit exemption mismatch"
        );
        let suppressed: Vec<&str> = if id == TOKEN_CONTRACT_ID {
            vec!["hold", "release"]
        } else {
            vec![]
        };
        ensure!(
            entry.unrecorded_results == suppressed,
            "retained native result policy mismatch"
        );
        for function in &entry.unrecorded_results {
            ensure!(
                !records_result(id, function),
                "retained native result recording mismatch"
            );
        }
        verify_digest(bytes, &entry.sha256)?;
    }
    ensure!(
        manifest.files.len() == metadata.len(),
        "retained native metadata count mismatch"
    );
    for (name, bytes) in metadata {
        let digest = manifest
            .files
            .get(*name)
            .ok_or_else(|| anyhow!("missing retained native metadata: {name}"))?;
        verify_digest(bytes, digest)?;
    }
    Ok(())
}

pub(crate) fn native_provenance() -> Result<BuildProvenance> {
    validate_inputs(MANIFEST, NATIVE_CONTRACTS, METADATA)?;
    let provenance: BuildProvenance = postcard::from_bytes(NATIVE_PROVENANCE)?;
    provenance.validate()?;
    // Publication uses the ordinary retained codec. Require its exact bytes,
    // including enum discriminants, rather than accepting semantic equality.
    ensure!(
        postcard::to_allocvec(&provenance)? == NATIVE_PROVENANCE,
        "retained native provenance codec mismatch"
    );
    let documented: BuildProvenance =
        serde_json::from_slice(include_bytes!("native/provenance.json"))?;
    ensure!(
        provenance == documented,
        "retained native provenance metadata mismatch"
    );
    Ok(provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_provenance_and_artifacts_match_the_definition() -> Result<()> {
        native_provenance()?;
        Ok(())
    }

    #[test]
    fn tampered_retained_inputs_are_rejected() {
        let mut artifact = TOKEN.to_vec();
        artifact[0] ^= 1;
        let mut contracts = NATIVE_CONTRACTS.to_vec();
        contracts[0].1 = &artifact;
        assert!(validate_inputs(MANIFEST, &contracts, METADATA).is_err());
        let mut provenance = NATIVE_PROVENANCE.to_vec();
        provenance[1] ^= 1;
        let mut metadata = METADATA.to_vec();
        metadata[3].1 = &provenance;
        assert!(validate_inputs(MANIFEST, NATIVE_CONTRACTS, &metadata).is_err());
        let mut reordered = NATIVE_CONTRACTS.to_vec();
        reordered.swap(0, 1);
        assert!(validate_inputs(MANIFEST, &reordered, METADATA).is_err());
        let mut manifest = MANIFEST.to_vec();
        manifest.push(b' ');
        assert!(validate_inputs(&manifest, NATIVE_CONTRACTS, METADATA).is_err());
    }

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
