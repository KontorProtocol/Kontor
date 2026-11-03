use std::str::FromStr;

use anyhow::{Result, ensure};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct Text(pub String);
impl TryFrom<String> for Text {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(!value.is_empty(), "empty text");
        Ok(Self(value))
    }
}
impl From<Text> for String {
    fn from(value: Text) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct Hex<const N: usize>(pub String);
impl<const N: usize> TryFrom<String> for Hex<N> {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value.len() == N * 2
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid lowercase hex"
        );
        Ok(Self(value))
    }
}
impl<const N: usize> From<Hex<N>> for String {
    fn from(value: Hex<N>) -> Self {
        value.0
    }
}
pub(super) type Hash = Hex<32>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct Money {
    pub text: String,
    pub units: BigUint,
}
impl TryFrom<String> for Money {
    type Error = anyhow::Error;
    fn try_from(text: String) -> Result<Self> {
        let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
        ensure!(
            !whole.is_empty()
                && whole.bytes().all(|c| c.is_ascii_digit())
                && (whole == "0" || !whole.starts_with('0')),
            "invalid canonical amount"
        );
        ensure!(
            fraction.len() <= 18
                && fraction.bytes().all(|c| c.is_ascii_digit())
                && (!text.contains('.') || (!fraction.is_empty() && !fraction.ends_with('0'))),
            "invalid decimal places"
        );
        let units = BigUint::from_str(&format!(
            "{whole}{fraction}{}",
            "0".repeat(18 - fraction.len())
        ))?;
        ensure!(units.bits() <= 256, "Decimal magnitude overflow");
        Ok(Self { text, units })
    }
}
impl From<Money> for String {
    fn from(value: Money) -> Self {
        value.text
    }
}

macro_rules! record {
    ($name:ident { $( $(#[$attr:meta])* $field:ident : $ty:ty ),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct $name { $( $(#[$attr])* pub $field: $ty, )* }
    };
}
record!(FileRef {
    path: Text,
    sha256: Hash
});
record!(Source {
    kontor_commit: Hex<20>, rustc_verbose: Text, target: Text, profile: Text,
    features: Vec<Text>, core_lockfile: FileRef, wasmtime_revision: Text,
    engine: Text, pulley_stack_bytes: u64, native_fiber_bytes: u64,
});
record!(Artifact { id: Text, compressed: FileRef, raw_sha256: Hash, addresses: Vec<Text> });
record!(Snapshot {
    database: FileRef,
    schema_sha256: Hash,
    anchor_height: u64,
    anchor_hash: Hash,
    checkpoint: Text,
    prune_watermark: u64,
    reset_report: FileRef
});
record!(Operation {
    txid: Hash,
    tx_index: u32,
    input_index: u32,
    op_index: u32,
    contract: Text,
    expression: Text,
    gas_limit: u64
});
record!(BitcoinValidation {
    network: Text,
    bitcoind_version: Text,
    accepted_block_hash: Hash,
    record: FileRef
});
record!(Input {raw_block: FileRef, height: u64, block_hash: Hash, previous_hash: Hash,
    raw_txids: Vec<Hash>, kontor_txids: Vec<Hash>, kontor_input_count: u64, operation_count: u64,
    payer_x_only_pubkey: Hash, operations: [Operation;3], bitcoin_validation: BitcoinValidation });
record!(Execution {
    executor: Text, component_cache: Text, network: Text, prune_enabled: bool, retain_blocks: u64,
    starting_block_height: u64, gas_to_fuel_multiplier: u64, execution_price: Money,
    storage_gas_per_byte: u64, lifecycle_parameters: FileRef, independent_resets: u64, timing_claim: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_retain_blocks: Option<u64>,
});
record!(Decision {
    consensus_height: u64,
    certificate_hex: String,
    value_kind: Text,
    block_height: u64,
    block_hash: Hash,
    certified_txs: ()
});
record!(Manifest { schema_version: u64, kind: Text, case_id: Text, funding_seed_hex: Hex<64>,
    source: Source, artifacts: Vec<Artifact>, snapshot: Snapshot, input: Input,
    execution: Execution, expected_report: FileRef, numeric_check: FileRef, decision: Decision });

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Status {
    Ok,
    ContractErr,
    OutOfFuel,
    Trap,
    Other,
}
record!(Receipt {id: u64, height: u64,
    #[serde(deserialize_with = "Option::deserialize")] tx_index: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")] input_index: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")] op_index: Option<u32>,
    result_index: u32, func: Text, gas: u64, status: Status,
    #[serde(deserialize_with = "Option::deserialize")] value: Option<String>,
    contract: Text,
    #[serde(deserialize_with = "Option::deserialize")] txid: Option<Hash>,
    signer_id: u64,
    #[serde(deserialize_with = "Option::deserialize")] payer_signer_id: Option<u64>,
});
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum UsageKind {
    Transaction,
    Block,
}
record!(Usage {height: u64,
    #[serde(deserialize_with = "Option::deserialize")] tx_index: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")] txid: Option<Hash>,
    user_fuel: u64, system_fuel: u64, deposit_fuel: u64, kind: UsageKind,
});
record!(Account {
    balance: Money,
    floor: Money
});
record!(Accounts {
    payer: Account,
    burner: Account,
    core: Account,
    ordering_pool: Account,
    storage_pool: Account,
    total_supply: Account
});
record!(View {
    address: Text,
    storage_state: [u64; 4]
});
record!(Views {
    #[serde(rename = "A")]
    a: View,
    #[serde(rename = "B")]
    b: View
});
record!(StateVersion {contract: Text, path_hex: String, height: u64, value_hex: String, deleted: bool,
    #[serde(deserialize_with = "Option::deserialize")] depositor: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")] deposited_gas: Option<u64>,
});
record!(TableCount {
    table: Text,
    rows: u64
});
record!(Report {schema_version: u64, height: u64, block_hash: Hash, checkpoint: Text,
    prune_watermark: u64, receipts: Vec<Receipt>, usage: Vec<Usage>, accounts: Accounts,
    contract_views: Views, state_versions: Vec<StateVersion>, table_counts: Vec<TableCount>});
record!(NumericOperation {txid: Hash, tx_index: u32, input_index: u32, op_index: u32,
    contract: Text, expression: Text, status: Status,
    #[serde(deserialize_with = "Option::deserialize")] value: Option<String>,
    gas: u64, user_fuel: u64, system_fuel: u64, deposit_fuel: u64, reserved_deposit_gas: u64,
    payer_before: Money, payer_after: Money, burner_before: Money, burner_after: Money,
    floor_before: Money, floor_after: Money, execution_fee: Money,
    #[serde(deserialize_with = "Option::deserialize")] error_message: Option<String>,
    storage_state: [u64;4],
});
record!(Numeric {schema_version: u64, snapshot_sha256: Hash, raw_block_sha256: Hash,
    source_commit: Hex<20>, operations: [NumericOperation;3]});
