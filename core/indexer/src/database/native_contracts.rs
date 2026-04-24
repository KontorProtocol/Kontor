pub const TOKEN: &[u8] = include_bytes!("../../../../native-contracts/binaries/token.wasm.br");
pub const FILESTORAGE: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/filestorage.wasm.br");
pub const STAKING: &[u8] = include_bytes!("../../../../native-contracts/binaries/staking.wasm.br");
pub const REGISTRY: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/registry.wasm.br");
pub const NFT: &[u8] = include_bytes!("../../../../native-contracts/binaries/nft.wasm.br");

/// Ordered list of native contracts to publish at genesis.
///
/// Order matters: contracts that depend on other contracts must come after them.
/// In particular: `staking` calls `token`, and `nft` calls `filestorage`.
///
/// Used by `Runtime::publish_native_contracts` and the test runtime to drive
/// publication and to know how many native contract IDs to expect.
pub const NATIVE_CONTRACTS: &[(&str, &[u8])] = &[
    ("token", TOKEN),
    ("filestorage", FILESTORAGE),
    ("staking", STAKING),
    ("registry", REGISTRY),
    ("nft", NFT),
];

/// Number of native contracts published at genesis. Use this when you need to
/// iterate over the contract IDs reserved for native contracts (which start at 1).
pub const NATIVE_CONTRACT_COUNT: i64 = NATIVE_CONTRACTS.len() as i64;
