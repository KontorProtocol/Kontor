use indexer::witness_data::{TokenBalance, WitnessData};

#[test]
fn test_cbor4ii_and_dagcbor_determinism_and_size() {
    let payload = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    // cbor4ii
    let cbor4ii_bytes_1 = cbor4ii::serde::to_vec(Vec::new(), &payload).expect("cbor4ii serialize");
    let cbor4ii_bytes_2 = cbor4ii::serde::to_vec(Vec::new(), &payload).expect("cbor4ii serialize");
    assert_eq!(
        cbor4ii_bytes_1, cbor4ii_bytes_2,
        "cbor4ii not deterministic"
    );

    let decoded_cbor4ii: WitnessData =
        cbor4ii::serde::from_slice(&cbor4ii_bytes_1).expect("cbor4ii deserialize");
    assert_eq!(decoded_cbor4ii, payload);

    // dag-cbor (canonical/deterministic by spec)
    let dagcbor_bytes_1 = serde_ipld_dagcbor::to_vec(&payload).expect("dag-cbor serialize");
    let dagcbor_bytes_2 = serde_ipld_dagcbor::to_vec(&payload).expect("dag-cbor serialize");
    assert_eq!(
        dagcbor_bytes_1, dagcbor_bytes_2,
        "dag-cbor not deterministic"
    );

    let decoded_dagcbor: WitnessData =
        serde_ipld_dagcbor::from_slice(&dagcbor_bytes_1).expect("dag-cbor deserialize");
    assert_eq!(decoded_dagcbor, payload);

    // bcs (Binary Canonical Serialization)
    let bcs_bytes_1 = bcs::to_bytes(&payload).expect("bcs serialize");
    let bcs_bytes_2 = bcs::to_bytes(&payload).expect("bcs serialize");
    assert_eq!(bcs_bytes_1, bcs_bytes_2, "bcs not deterministic");

    let decoded_bcs: WitnessData = bcs::from_bytes(&bcs_bytes_1).expect("bcs deserialize");
    assert_eq!(decoded_bcs, payload);

    // postcard (deterministic given fixed field order; no maps here)
    let postcard_bytes_1 = postcard::to_allocvec(&payload).expect("postcard serialize");
    let postcard_bytes_2 = postcard::to_allocvec(&payload).expect("postcard serialize");
    assert_eq!(
        postcard_bytes_1, postcard_bytes_2,
        "postcard not deterministic"
    );

    let decoded_postcard: WitnessData =
        postcard::from_bytes(&postcard_bytes_1).expect("postcard deserialize");
    assert_eq!(decoded_postcard, payload);

    // Size compare (printed for human inspection during test runs)
    println!(
        "cbor4ii size: {} bytes, dag-cbor size: {} bytes, bcs size: {} bytes, postcard size: {} bytes",
        cbor4ii_bytes_1.len(),
        dagcbor_bytes_1.len(),
        bcs_bytes_1.len(),
        postcard_bytes_1.len()
    );
}
