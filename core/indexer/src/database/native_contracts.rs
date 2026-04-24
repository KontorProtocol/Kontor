pub const TOKEN: &[u8] = include_bytes!("../../../../native-contracts/binaries/token.wasm.br");
pub const FILESTORAGE: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/filestorage.wasm.br");
pub const STAKING: &[u8] = include_bytes!("../../../../native-contracts/binaries/staking.wasm.br");
pub const REGISTRY: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/registry.wasm.br");
pub const NFT: &[u8] = include_bytes!("../../../../native-contracts/binaries/nft.wasm.br");

/// Ordered list of native contracts published at genesis. Publish order
/// determines contract IDs (1-indexed, assigned in iteration order), so
/// treat additions as a protocol-level decision. The test runtime uses
/// `NATIVE_CONTRACTS.len()` to know how many IDs to expect; adding to
/// this list is the only change needed.
pub const NATIVE_CONTRACTS: &[(&str, &[u8])] = &[
    ("token", TOKEN),
    ("filestorage", FILESTORAGE),
    ("staking", STAKING),
    ("registry", REGISTRY),
    ("nft", NFT),
];
