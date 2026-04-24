pub const TOKEN: &[u8] = include_bytes!("../../../../native-contracts/binaries/token.wasm.br");
pub const FILESTORAGE: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/filestorage.wasm.br");
pub const STAKING: &[u8] = include_bytes!("../../../../native-contracts/binaries/staking.wasm.br");
pub const REGISTRY: &[u8] =
    include_bytes!("../../../../native-contracts/binaries/registry.wasm.br");
pub const NFT: &[u8] = include_bytes!("../../../../native-contracts/binaries/nft.wasm.br");

/// Number of native contracts published at genesis. Must match the number of
/// `publish()` calls in `Runtime::publish_native_contracts`. Used by the test
/// runtime to know how many native contract IDs to extract from the cache
/// (IDs start at 1 and are assigned in publish order).
pub const NATIVE_CONTRACT_COUNT: i64 = 5;
