use anyhow::Result;
use bitcoin::{Amount, FeeRate, ScriptBuf};
use indexer::api::compose::{
    build_dummy_tx, estimate_fee_with_dummy_key_witness, split_even_chunks,
};

#[tokio::test]
async fn test_split_even_chunks_roundtrip_and_balance() -> Result<()> {
    let data: Vec<u8> = (0u8..100u8).collect();
    let chunks = split_even_chunks(&data, 3).unwrap();
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 34);
    assert_eq!(chunks[1].len(), 33);
    assert_eq!(chunks[2].len(), 33);
    let reconcat: Vec<u8> = chunks.concat();
    assert_eq!(reconcat, data);

    let single = split_even_chunks(&data, 1).unwrap();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0], data);
    Ok(())
}

#[tokio::test]
async fn test_split_even_chunks_more_parts_than_bytes() -> Result<()> {
    let data: Vec<u8> = (0u8..5u8).collect();
    let parts = 10;
    let chunks = split_even_chunks(&data, parts).unwrap();
    assert_eq!(chunks.len(), parts);
    let non_empty = chunks.iter().filter(|c| !c.is_empty()).count();
    assert_eq!(non_empty, data.len());
    for (i, c) in chunks.iter().enumerate() {
        if i < 5 {
            assert_eq!(c.len(), 1);
        } else {
            assert!(c.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_split_even_chunks_zero_parts_errs() -> Result<()> {
    let res = split_even_chunks(&[1, 2, 3], 0);
    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_split_even_chunks_diff_at_most_one_and_order_preserved() -> Result<()> {
    let data: Vec<u8> = (0..1234u16).map(|i| (i % 251) as u8).collect();
    let parts = 7;
    let chunks = split_even_chunks(&data, parts).unwrap();
    assert_eq!(chunks.len(), parts);
    let lens: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
    let min_len = *lens.iter().min().unwrap();
    let max_len = *lens.iter().max().unwrap();
    assert!(max_len - min_len <= 1);
    let reconcat: Vec<u8> = chunks.concat();
    assert_eq!(reconcat, data);
    Ok(())
}

#[tokio::test]

async fn test_estimate_commit_delta_fee_monotonic() -> Result<()> {
    let base = build_dummy_tx(vec![], vec![]);
    let fr = FeeRate::from_sat_per_vb(5).unwrap();
    let d1 = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let d2 = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d2 > d1);

    let small_spk = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let large_spk = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(large_spk >= small_spk);

    let d0 = {
        let mut temp = base.clone();
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d0 > 0);
    Ok(())
}

#[tokio::test]
async fn test_estimate_commit_delta_fee_increases_with_each_spk_len_independently() -> Result<()> {
    let base = build_dummy_tx(vec![], vec![]);
    let fr = FeeRate::from_sat_per_vb(3).unwrap();
    // Vary script_spk_len
    let a = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let b = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(b >= a);
    // Vary change_spk_len
    let c = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let d = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d >= c);
    Ok(())
}
