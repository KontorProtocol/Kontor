use anyhow::Result;
use indexer::reactor::types::Inst;
use indexer::runtime::ContractAddress;
use indexer::witness_data::{TokenBalance, WitnessData};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
struct MapWrap {
    map: BTreeMap<String, u64>,
}

fn sample_witness_data() -> WitnessData {
    WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    }
}

fn sample_map_wrap() -> MapWrap {
    let mut map = BTreeMap::new();
    let keys = ["k10", "k2", "k1", "k20", "k11", "k03", "k002", "k100"];
    for (i, k) in keys.iter().enumerate() {
        map.insert((*k).to_string(), (i as u64) + 1);
    }
    MapWrap { map }
}

#[derive(Serialize, Deserialize, Clone)]
struct Nested {
    id: u32,
    title: String,
    notes: Option<String>,
    tags: Vec<String>,
}

fn sample_nested() -> Nested {
    Nested {
        id: 42,
        title: "Example".to_string(),
        notes: Some("hello".to_string()),
        tags: vec!["a".into(), "bb".into(), "ccc".into()],
    }
}

fn size_all<T: Serialize>(value: &T) -> Result<(usize, usize, usize, usize)> {
    let cbor4ii = cbor4ii::serde::to_vec(Vec::new(), value)?.len();
    let dagcbor = serde_ipld_dagcbor::to_vec(value)?.len();
    let bcs = bcs::to_bytes(value)?.len();
    let postcard = postcard::to_allocvec(value)?.len();
    Ok((cbor4ii, dagcbor, bcs, postcard))
}

fn print_row(label: &str, sizes: (usize, usize, usize, usize)) {
    println!(
        "{:<24} | {:>8} | {:>8} | {:>6} | {:>9}",
        label, sizes.0, sizes.1, sizes.2, sizes.3
    );
}

fn print_header() {
    println!(
        "{:<24} | {:>8} | {:>8} | {:>6} | {:>9}",
        "payload", "cbor4ii", "dag-cbor", "bcs", "postcard"
    );
    println!("{}", "-".repeat(24 + 3 + 8 + 3 + 8 + 3 + 6 + 3 + 9));
}

fn main() -> Result<()> {
    let w = sample_witness_data();
    let m = sample_map_wrap();
    let n = sample_nested();
    let bytes_32 = vec![0u8; 32];
    let bytes_256 = vec![0u8; 256];
    let inst = Inst::Call {
        gas_limit: 500_000,
        contract: ContractAddress {
            name: "dex:amm".to_string(),
            height: 12345,
            tx_index: 7,
        },
        expr: "(swap (token A) (token B) 1000)".to_string(),
    };

    print_header();
    print_row("WitnessData", size_all(&w)?);
    print_row("MapWrap (BTreeMap)", size_all(&m)?);
    print_row("Nested struct", size_all(&n)?);
    print_row("Inst::Call", size_all(&inst)?);
    print_row("Vec<u8> (32)", size_all(&bytes_32)?);
    print_row("Vec<u8> (256)", size_all(&bytes_256)?);

    Ok(())
}
