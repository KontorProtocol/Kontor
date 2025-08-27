use anyhow::Result;
use bitcoin::key::Secp256k1;
use bitcoin::script::Instruction;
use bitcoin::transaction::Version;
use bitcoin::{Network, Psbt, Transaction, TxOut, absolute::LockTime};
use bitcoin::{Sequence, TapSighashType};
use clap::Parser;
use indexer::config::TestConfig;
use indexer::multi_psbt_test_utils::{
    add_node_input_and_output_to_reveal_psbt, add_portal_input_and_output_to_psbt,
    add_portal_input_and_output_to_reveal_psbt, add_single_node_input_and_output_to_psbt,
    build_tap_script_and_script_address_helper, estimate_single_input_single_output_reveal_vbytes,
    get_node_addresses, mock_fetch_utxos_for_addresses, tx_vbytes,
};

fn find_single_output_index(outputs: &[TxOut], script: &bitcoin::script::ScriptBuf) -> usize {
    let matches: Vec<usize> = outputs
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            if &o.script_pubkey == script {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    // Each node must have exactly one tapscript output; multiple/zero breaks deterministic mapping
    // and can hide value redirection.
    assert!(
        matches.len() == 1,
        "expected exactly one matching output; found {}",
        matches.len()
    );
    matches[0]
}

#[test]
fn test_commit_psbt_security_invariants() -> Result<()> {
    // Setup (deterministic environment)
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    // Build commit PSBT as portal would
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());

    for (idx, s) in signups.iter().enumerate() {
        let (_node_reveal_fee, input_index, script_vout) =
            add_single_node_input_and_output_to_psbt(
                &mut commit_psbt,
                &node_utxos,
                idx,
                min_sat_per_vb,
                s,
                dust_limit_sat,
            )?;
        node_input_indices.push(input_index);
        node_script_vouts.push(script_vout);
    }

    // Add portal input/output
    let (_portal_info, _portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Prepare prevouts for validation
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();

    // Validate for each node
    for (i, s) in signups.iter().enumerate() {
        let input_index = node_input_indices[i];

        // PSBT hygiene: others not finalized
        for (j, inp) in commit_psbt.inputs.iter().enumerate() {
            if j != input_index {
                // No other commit input should be finalized; prevents pre-binding/pinning and ensures
                // each node signs in isolation without being constrained by others.
                assert!(
                    inp.final_script_witness.is_none(),
                    "commit PSBT input {} unexpectedly finalized before node {} signs",
                    j,
                    i
                );
            }
        }

        // Prevout integrity and ownership
        let node_prevout = commit_psbt.inputs[input_index]
            .witness_utxo
            .as_ref()
            .expect("node commit prevout missing");
        // Node must own the prevout being spent; prevents the portal from spending a foreign input
        // on behalf of the node.
        assert_eq!(
            node_prevout.script_pubkey,
            s.address.script_pubkey(),
            "commit prevout script does not belong to node {}",
            i
        );
        // Amount must match the independently gathered prevouts snapshot to prevent deceptive
        // fee/accounting manipulation.
        assert_eq!(
            node_prevout.value, all_prevouts_c[input_index].value,
            "commit prevout amount mismatch for node {}",
            i
        );
        // Script must also match the snapshot (defensive double-check against tampering).
        assert_eq!(
            node_prevout.script_pubkey, all_prevouts_c[input_index].script_pubkey,
            "commit prevout script mismatch for node {}",
            i
        );

        // Node script output must exist and be sufficiently funded (dust + estimated reveal)
        let (tap_script, tap_info, script_addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
        // Bound tapscript size to remain within policy/fee budgets and avoid DoS via oversized data.
        assert!(
            tap_script.as_bytes().len() <= 2048,
            "tapscript too large ({} bytes)",
            tap_script.as_bytes().len()
        );
        let reveal_vb = estimate_single_input_single_output_reveal_vbytes(
            &tap_script,
            &tap_info,
            s.address.script_pubkey().len(),
            dust_limit_sat,
        );
        let expected_script_value =
            dust_limit_sat.saturating_add(reveal_vb.saturating_mul(min_sat_per_vb));

        let script_vout = find_single_output_index(
            &commit_psbt.unsigned_tx.output,
            &script_addr.script_pubkey(),
        );
        let script_value = commit_psbt.unsigned_tx.output[script_vout].value.to_sat();
        // Ensure script output funds dust envelope plus estimated reveal fee to avoid reveal
        // underfunding.
        assert!(
            script_value >= expected_script_value,
            "node script value too low: have={} expected>={}",
            script_value,
            expected_script_value
        );

        // Change: at most one and > dust
        let change_matches: Vec<usize> = commit_psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(k, o)| {
                if o.script_pubkey == s.address.script_pubkey() {
                    Some(k)
                } else {
                    None
                }
            })
            .collect();
        // At most one change output back to the node; multiple change outputs can obscure value
        // movement and complicate accounting.
        assert!(
            change_matches.len() <= 1,
            "more than one change output to node address"
        );
        let change_value = change_matches
            .first()
            .map(|k| commit_psbt.unsigned_tx.output[*k].value.to_sat())
            .unwrap_or(0);
        if change_value > 0 {
            // Change should be economically spendable; disallow dust change to prevent waste/pinning.
            assert!(
                change_value > dust_limit_sat,
                "node change output must be dust-filtered (> {} sat)",
                dust_limit_sat
            );
        }

        // Commit fee fairness: base share + witness delta
        let mut base_no_wit = commit_psbt.unsigned_tx.clone();
        for inp in &mut base_no_wit.input {
            inp.witness = bitcoin::Witness::new();
        }
        let base_vb = tx_vbytes(&base_no_wit);
        let inputs_n = commit_psbt.unsigned_tx.input.len() as u64;
        let base_share = if inputs_n > 0 { base_vb / inputs_n } else { 0 };
        let mut with_dummy = commit_psbt.unsigned_tx.clone();
        let mut dw = bitcoin::Witness::new();
        dw.push(vec![0u8; 65]);
        with_dummy.input[input_index].witness = dw;
        let witness_delta = tx_vbytes(&with_dummy).saturating_sub(base_vb);
        let required_min_fee = base_share
            .saturating_add(witness_delta)
            .saturating_mul(min_sat_per_vb);
        let paid_by_node = node_prevout
            .value
            .to_sat()
            .saturating_sub(script_value.saturating_add(change_value));
        // Allow small slack to account for rounding/modeling differences between fairness heuristic
        // and the builder's full-delta fee accounting (e.g., dummy change sizing, varints).
        let slack_vb: u64 = 8;
        let allowed_shortfall = slack_vb.saturating_mul(min_sat_per_vb);
        // Enforce that the node covers at least its fair share (base bytes + its witness delta),
        // allowing a small slack for modeling/rounding differences.
        assert!(
            paid_by_node.saturating_add(allowed_shortfall) >= required_min_fee,
            "node {} underpays commit fee: paid={} < required_min={} (allowed_shortfall={})",
            i,
            paid_by_node,
            required_min_fee,
            allowed_shortfall
        );
    }

    Ok(())
}

#[test]
fn test_reveal_psbt_security_invariants() -> Result<()> {
    // Setup (deterministic environment)
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    // Build commit PSBT
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());

    for (idx, s) in signups.iter().enumerate() {
        let (_node_reveal_fee, input_index, script_vout) =
            add_single_node_input_and_output_to_psbt(
                &mut commit_psbt,
                &node_utxos,
                idx,
                min_sat_per_vb,
                s,
                dust_limit_sat,
            )?;
        node_input_indices.push(input_index);
        node_script_vouts.push(script_vout);
    }

    let (portal_info, portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Build reveal PSBT
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }

    let nodes_length = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_length,
    );

    // Validate mapping and hygiene for each node
    for (i, s) in signups.iter().enumerate() {
        // Recompute tapscript/address
        let (tap_script, _tap_info, addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
        assert!(
            tap_script.as_bytes().len() <= 2048,
            "tapscript too large ({} bytes)",
            tap_script.as_bytes().len()
        );

        // Input mapping
        let wutxo = reveal_psbt.inputs[i]
            .witness_utxo
            .as_ref()
            .expect("reveal prevout missing");
        assert_eq!(
            wutxo.script_pubkey,
            addr.script_pubkey(),
            "reveal input {} does not spend node's script output",
            i
        );

        // Output mapping
        let out = &reveal_psbt.unsigned_tx.output[i];
        assert_eq!(
            out.script_pubkey,
            s.address.script_pubkey(),
            "reveal output script at index {} does not pay node address",
            i
        );
        assert!(
            out.value.to_sat() == dust_limit_sat,
            "reveal envelope must equal dust: have={} expected={}",
            out.value.to_sat(),
            dust_limit_sat
        );

        // PSBT hygiene
        for (j, inp) in reveal_psbt.inputs.iter().enumerate() {
            if j != i {
                assert!(
                    inp.final_script_witness.is_none(),
                    "reveal PSBT input {} unexpectedly finalized before node {} signs",
                    j,
                    i
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_inputs_sequences_are_rbf() -> Result<()> {
    // Setup
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    // Commit PSBT
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_fee, _in_idx, script_vout) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_script_vouts.push(script_vout);
    }
    let (portal_info, portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Reveal PSBT
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_length = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_length,
    );

    // Assert all inputs are RBF-enabled (pinning resistance, replaceable for fee-bumps)
    for inp in &commit_psbt.unsigned_tx.input {
        assert_eq!(
            inp.sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            "commit input not RBF-enabled"
        );
    }
    for inp in &reveal_psbt.unsigned_tx.input {
        assert_eq!(
            inp.sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            "reveal input not RBF-enabled"
        );
    }

    Ok(())
}

#[test]
fn test_commit_outputs_whitelist_including_portal() -> Result<()> {
    // Setup
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    for (idx, s) in signups.iter().enumerate() {
        let _ = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
    }
    let (portal_info, _portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Build whitelist of allowed script_pubkeys
    let mut allowed = std::collections::HashSet::new();
    for s in &signups {
        let (_ts, _ti, node_script_addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
        allowed.insert(node_script_addr.script_pubkey());
        allowed.insert(s.address.script_pubkey());
    }
    let (_pts, _pti, portal_script_addr) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
    )?;
    allowed.insert(portal_script_addr.script_pubkey());
    allowed.insert(portal_info.address.script_pubkey());

    // Assert every commit output is one of: node script, node change, portal script, portal change
    for o in &commit_psbt.unsigned_tx.output {
        assert!(
            allowed.contains(&o.script_pubkey),
            "commit output script not in whitelist"
        );
    }

    Ok(())
}

#[test]
fn test_sighash_default_encoding_for_signatures() -> Result<()> {
    // Setup and build commit/reveal PSBTs
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_node_reveal_fee, input_index, script_vout) =
            add_single_node_input_and_output_to_psbt(
                &mut commit_psbt,
                &node_utxos,
                idx,
                min_sat_per_vb,
                s,
                dust_limit_sat,
            )?;
        node_input_indices.push(input_index);
        node_script_vouts.push(script_vout);
    }
    let (_portal_info, _portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();

    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }

    // Sign one node's commit input and reveal input using SIGHASH_DEFAULT and inspect witnesses
    let (_, secrets) = get_node_addresses(&secp, &test_cfg)?;
    let node_index = 0;
    let input_index = node_input_indices[node_index];
    let keypair = secrets[node_index].keypair;

    // Commit signature
    let mut commit_tx_local = commit_psbt.unsigned_tx.clone();
    indexer::test_utils::sign_key_spend(
        &secp,
        &mut commit_tx_local,
        &all_prevouts_c,
        &keypair,
        input_index,
        Some(TapSighashType::Default),
    )?;
    let sig_bytes = commit_tx_local.input[input_index]
        .witness
        .iter()
        .next()
        .expect("sig")
        .to_vec();
    assert!(
        sig_bytes.len() == 64 || sig_bytes.len() == 65,
        "unexpected sig size"
    );
    if sig_bytes.len() == 65 {
        assert_eq!(
            sig_bytes[64], 0x00,
            "non-default sighash flag present in commit sig"
        );
    }

    // Reveal signature
    let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
        signups[node_index].internal_key,
        b"node-data".to_vec(),
        Network::Testnet4,
    )?;
    let prevouts_reveal: Vec<TxOut> = reveal_psbt
        .inputs
        .iter()
        .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
        .collect();
    let mut reveal_tx_local = reveal_psbt.unsigned_tx.clone();
    indexer::test_utils::sign_script_spend_with_sighash(
        &secp,
        &tap_info,
        &tap_script,
        &mut reveal_tx_local,
        &prevouts_reveal,
        &keypair,
        node_index,
        TapSighashType::Default,
    )?;
    let sig_bytes_r = reveal_tx_local.input[node_index]
        .witness
        .iter()
        .next()
        .expect("sig")
        .to_vec();
    assert!(
        sig_bytes_r.len() == 64 || sig_bytes_r.len() == 65,
        "unexpected sig size"
    );
    if sig_bytes_r.len() == 65 {
        assert_eq!(
            sig_bytes_r[64], 0x00,
            "non-default sighash flag present in reveal sig"
        );
    }

    Ok(())
}

#[test]
fn test_script_address_hrp_matches_network() -> Result<()> {
    // Ensure the script address HRP matches the configured network (prevents UI/ops confusion)
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let (tap_script, _tap_info, addr) = build_tap_script_and_script_address_helper(
        signups[0].internal_key,
        b"node-data".to_vec(),
        Network::Testnet4,
    )?;
    assert!(!tap_script.is_empty(), "tap script must not be empty");
    let s = addr.to_string();
    assert!(
        s.starts_with("tb1"),
        "expected testnet HRP tb1..., got {}",
        s
    );
    Ok(())
}

#[test]
fn test_reveal_outputs_whitelist_and_counts() -> Result<()> {
    // Build commit and reveal as usual
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_, _, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_script_vouts.push(sv);
    }
    let (portal_info, portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_n = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_n,
    );

    // Expected: exactly N+1 outputs (N nodes + 1 portal), all to node addresses or portal address
    assert_eq!(
        reveal_psbt.unsigned_tx.output.len(),
        nodes_n + 1,
        "unexpected reveal outputs count"
    );
    let mut allowed = std::collections::HashSet::new();
    for s in &signups {
        allowed.insert(s.address.script_pubkey());
    }
    allowed.insert(portal_info.address.script_pubkey());
    for o in &reveal_psbt.unsigned_tx.output {
        assert!(
            allowed.contains(&o.script_pubkey),
            "reveal output not in whitelist"
        );
    }
    Ok(())
}

#[test]
fn test_portal_reveal_fairness_base_plus_witness() -> Result<()> {
    // Build commit and reveal
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_, _, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_script_vouts.push(sv);
    }
    let (portal_info, portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_n = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_n,
    );

    // Prepare base and then sign portal reveal to measure delta
    let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
    )?;
    let prevouts: Vec<TxOut> = reveal_psbt
        .inputs
        .iter()
        .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
        .collect();

    // Before: all known witnesses applied (none for portal yet)
    let mut reveal_before = reveal_psbt.unsigned_tx.clone();
    for j in 0..reveal_before.input.len() {
        if let Some(w) = &reveal_psbt.inputs[j].final_script_witness {
            reveal_before.input[j].witness = w.clone();
        }
    }
    let before_vb = tx_vbytes(&reveal_before);

    // After: portal witness applied
    let mut reveal_after = reveal_before.clone();
    let mut reveal_tx_local = reveal_psbt.unsigned_tx.clone();
    indexer::test_utils::sign_script_spend_with_sighash(
        &secp,
        &tap_info,
        &tap_script,
        &mut reveal_tx_local,
        &prevouts,
        &portal_info.keypair,
        nodes_n,
        TapSighashType::Default,
    )?;
    reveal_after.input[nodes_n].witness = reveal_tx_local.input[nodes_n].witness.clone();
    let after_vb = tx_vbytes(&reveal_after);

    let delta_vb = after_vb.saturating_sub(before_vb);
    let in_val = reveal_psbt.inputs[nodes_n]
        .witness_utxo
        .as_ref()
        .expect("wutxo")
        .value
        .to_sat();
    let out_val = reveal_psbt.unsigned_tx.output[nodes_n].value.to_sat();
    let paid = in_val.saturating_sub(out_val);

    // Base share + witness delta fairness for portal
    let mut base_no_witness = reveal_psbt.unsigned_tx.clone();
    for inp in &mut base_no_witness.input {
        inp.witness = bitcoin::Witness::new();
    }
    let base_vb = tx_vbytes(&base_no_witness);
    let inputs_n = reveal_psbt.unsigned_tx.input.len() as u64;
    let base_share = if inputs_n > 0 { base_vb / inputs_n } else { 0 };
    let required = base_share
        .saturating_add(delta_vb)
        .saturating_mul(min_sat_per_vb);
    let slack_vb: u64 = 8;
    let allowed_shortfall = slack_vb.saturating_mul(min_sat_per_vb);
    assert!(
        paid.saturating_add(allowed_shortfall) >= required,
        "portal underpays reveal fee: paid={} < required={} (allowed_shortfall={})",
        paid,
        required,
        allowed_shortfall
    );

    Ok(())
}

#[test]
fn test_psbt_hygiene_and_witness_utxo_presence() -> Result<()> {
    // Build commit and reveal
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_, _, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_script_vouts.push(sv);
    }
    let (portal_info, portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_n = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_n,
    );

    // Hygiene: no final witnesses should be present before signing
    for (i, inp) in commit_psbt.inputs.iter().enumerate() {
        assert!(
            inp.final_script_witness.is_none(),
            "commit input {} unexpectedly finalized",
            i
        );
        assert!(
            inp.witness_utxo.is_some(),
            "commit input {} missing witness_utxo",
            i
        );
    }
    for (i, inp) in reveal_psbt.inputs.iter().enumerate() {
        assert!(
            inp.final_script_witness.is_none(),
            "reveal input {} unexpectedly finalized",
            i
        );
        assert!(
            inp.witness_utxo.is_some(),
            "reveal input {} missing witness_utxo",
            i
        );
    }

    Ok(())
}

#[test]
fn test_tapscript_prefix_structure_pubkey_then_op_checksig() -> Result<()> {
    // For each node and the portal, ensure tapscript begins with pubkey push then OP_CHECKSIG.
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;

    for s in &signups {
        let (tap_script, _tap_info, _addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
        let mut it = tap_script.instructions();
        match (it.next(), it.next()) {
            (Some(Ok(Instruction::PushBytes(bytes))), Some(Ok(Instruction::Op(op)))) => {
                assert_eq!(
                    bytes.as_bytes(),
                    &s.internal_key.serialize(),
                    "tapscript first element must be node xonly pubkey"
                );
                assert_eq!(
                    op.to_u8(),
                    bitcoin::opcodes::all::OP_CHECKSIG.to_u8(),
                    "tapscript second element must be OP_CHECKSIG"
                );
            }
            _ => panic!("unexpected tapscript prefix structure"),
        }
    }

    // Portal
    let portal_info = indexer::multi_psbt_test_utils::get_portal_info(&secp, &test_cfg)?;
    let (tap_script_p, _tap_info_p, _addr_p) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
    )?;
    let mut itp = tap_script_p.instructions();
    match (itp.next(), itp.next()) {
        (Some(Ok(Instruction::PushBytes(bytes))), Some(Ok(Instruction::Op(op)))) => {
            assert_eq!(
                bytes.as_bytes(),
                &portal_info.internal_key.serialize(),
                "tapscript first element must be portal xonly pubkey"
            );
            assert_eq!(
                op.to_u8(),
                bitcoin::opcodes::all::OP_CHECKSIG.to_u8(),
                "tapscript second element must be OP_CHECKSIG"
            );
        }
        _ => panic!("unexpected tapscript prefix structure (portal)"),
    }

    Ok(())
}

#[tokio::test]
async fn test_async_node_sign_and_merge_flows() -> Result<()> {
    // End-to-end async signing by nodes and merge back into the portal PSBTs
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, secrets) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    // Build commit
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_fee, input_index, script_vout) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_input_indices.push(input_index);
        node_script_vouts.push(script_vout);
    }
    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Prevouts for commit signatures
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();

    // Build reveal
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_len = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_len,
    );

    // Async node signing and merge
    let node_sign_futs: Vec<_> = signups
        .iter()
        .enumerate()
        .map(|(index, node_info)| {
            indexer::multi_psbt_test_utils::node_sign_commit_and_reveal(
                node_info,
                index,
                (commit_psbt.clone(), reveal_psbt.clone()),
                &all_prevouts_c,
                &node_input_indices,
                min_sat_per_vb,
                &secrets,
            )
        })
        .collect();

    indexer::multi_psbt_test_utils::merge_node_signatures(
        node_sign_futs,
        &node_input_indices,
        &mut commit_psbt,
        &mut reveal_psbt,
    )
    .await?;

    // Assert node witnesses present
    for (i, input_index) in node_input_indices.iter().enumerate() {
        assert!(
            commit_psbt.inputs[*input_index]
                .final_script_witness
                .is_some(),
            "missing commit witness for node {}",
            i
        );
        assert!(
            reveal_psbt.inputs[i].final_script_witness.is_some(),
            "missing reveal witness for node {}",
            i
        );
    }

    // Portal signs and final checks
    indexer::multi_psbt_test_utils::portal_signs_commit_and_reveal(
        &mut commit_psbt,
        &mut reveal_psbt,
        &portal_info,
        &all_prevouts_c,
        portal_input_index,
        min_sat_per_vb,
        nodes_len,
    )?;

    indexer::multi_psbt_test_utils::verify_x_only_pubkeys(
        &signups,
        &reveal_psbt,
        &commit_psbt,
        min_sat_per_vb,
    );

    Ok(())
}

#[test]
fn test_tapscript_builder_rejects_empty_data() -> Result<()> {
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let res = indexer::multi_psbt_test_utils::build_tap_script_and_script_address_helper(
        signups[0].internal_key,
        Vec::new(),
        Network::Testnet4,
    );
    assert!(
        res.is_err(),
        "empty data must be rejected by tapscript builder"
    );
    Ok(())
}

#[test]
fn test_script_address_hrp_across_networks() -> Result<()> {
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let ikey = signups[0].internal_key;

    let (_s1, _i1, a_main) =
        indexer::multi_psbt_test_utils::build_tap_script_and_script_address_helper(
            ikey,
            b"node-data".to_vec(),
            Network::Bitcoin,
        )?;
    let (_s2, _i2, a_test) =
        indexer::multi_psbt_test_utils::build_tap_script_and_script_address_helper(
            ikey,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
    let (_s3, _i3, a_reg) =
        indexer::multi_psbt_test_utils::build_tap_script_and_script_address_helper(
            ikey,
            b"node-data".to_vec(),
            Network::Regtest,
        )?;

    let sm = a_main.to_string();
    let st = a_test.to_string();
    let sr = a_reg.to_string();
    assert!(
        sm.starts_with("bc1p"),
        "mainnet HRP must be bc1p..., got {}",
        sm
    );
    assert!(
        st.starts_with("tb1p"),
        "testnet HRP must be tb1p..., got {}",
        st
    );
    assert!(
        sr.starts_with("bcrt1p"),
        "regtest HRP must be bcrt1p..., got {}",
        sr
    );
    Ok(())
}

#[test]
fn test_script_output_funds_dust_plus_reveal_fee_estimate() -> Result<()> {
    // Each script output should fund exactly (or at least) dust + reveal fee estimate
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_node_reveal_fee, _in_idx, script_vout) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_script_vouts.push(script_vout);
    }

    let (portal_info, _portal_change_value, _portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Nodes
    for (i, s) in signups.iter().enumerate() {
        let (tap_script, tap_info, addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
        )?;
        let est_vb = estimate_single_input_single_output_reveal_vbytes(
            &tap_script,
            &tap_info,
            s.address.script_pubkey().len(),
            dust_limit_sat,
        );
        let est_fee = est_vb.saturating_mul(min_sat_per_vb);
        let expected_min = dust_limit_sat.saturating_add(est_fee);
        let sv = node_script_vouts[i];
        let actual = commit_psbt.unsigned_tx.output[sv].value.to_sat();
        assert!(
            actual >= expected_min,
            "node {} script output underfunded: have={} expected_min={} (vb={}, feerate={})",
            i,
            actual,
            expected_min,
            est_vb,
            min_sat_per_vb
        );
        assert_eq!(
            commit_psbt.unsigned_tx.output[sv].script_pubkey,
            addr.script_pubkey(),
            "node {} script output script mismatch",
            i
        );
    }

    // Portal
    let (ptap, ptap_info, paddr) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
    )?;
    let est_vb_p = estimate_single_input_single_output_reveal_vbytes(
        &ptap,
        &ptap_info,
        portal_info.address.script_pubkey().len(),
        dust_limit_sat,
    );
    let est_fee_p = est_vb_p.saturating_mul(min_sat_per_vb);
    let expected_min_p = dust_limit_sat.saturating_add(est_fee_p);
    // Portal script output is last, or last-1 if portal change exists; find by script
    let found_idx = commit_psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == paddr.script_pubkey())
        .expect("portal script output missing");
    let actual_p = commit_psbt.unsigned_tx.output[found_idx].value.to_sat();
    assert!(
        actual_p >= expected_min_p,
        "portal script output underfunded: have={} expected_min={} (vb={}, feerate={})",
        actual_p,
        expected_min_p,
        est_vb_p,
        min_sat_per_vb
    );

    Ok(())
}

#[test]
fn test_pre_sign_estimated_commit_fee_is_covered() -> Result<()> {
    // Participant contributions sum to commit fee paid (pre-sign accounting consistency)
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_node_reveal_fee, in_idx, script_vout) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_input_indices.push(in_idx);
        node_script_vouts.push(script_vout);
    }

    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Overall commit fee paid
    let commit_in_total: u64 = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum();
    let commit_out_total: u64 = commit_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let commit_paid_total = commit_in_total.saturating_sub(commit_out_total);
    assert!(commit_paid_total > 0, "commit must pay some fee");

    // Sum contributions by nodes
    let mut sum_contrib = 0u64;
    for (i, s) in signups.iter().enumerate() {
        let prevout_val = commit_psbt.inputs[node_input_indices[i]]
            .witness_utxo
            .as_ref()
            .unwrap()
            .value
            .to_sat();
        let script_value = commit_psbt.unsigned_tx.output[node_script_vouts[i]]
            .value
            .to_sat();
        let change_value = commit_psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter(|(k, o)| {
                *k != node_script_vouts[i] && o.script_pubkey == s.address.script_pubkey()
            })
            .map(|(_, o)| o.value.to_sat())
            .sum::<u64>();
        let contrib = prevout_val.saturating_sub(script_value.saturating_add(change_value));
        assert!(contrib > 0, "node {} must contribute positive fee", i);
        sum_contrib = sum_contrib.saturating_add(contrib);
    }

    // Portal contribution
    let portal_prevout_val = commit_psbt.inputs[portal_input_index]
        .witness_utxo
        .as_ref()
        .unwrap()
        .value
        .to_sat();
    let (_pts, _pti, paddr) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
    )?;
    let portal_script_value = commit_psbt
        .unsigned_tx
        .output
        .iter()
        .find(|o| o.script_pubkey == paddr.script_pubkey())
        .map(|o| o.value.to_sat())
        .expect("portal script output missing");
    let portal_change_actual = if portal_change_value > 0 {
        portal_change_value
    } else {
        0
    };
    let portal_contrib =
        portal_prevout_val.saturating_sub(portal_script_value.saturating_add(portal_change_actual));
    assert!(portal_contrib > 0, "portal must contribute positive fee");
    sum_contrib = sum_contrib.saturating_add(portal_contrib);

    assert_eq!(
        sum_contrib, commit_paid_total,
        "sum of participant contributions must equal commit fee paid"
    );

    Ok(())
}

#[tokio::test]
async fn test_commit_shortfall_is_offset_by_reveal_surplus_after_signing() -> Result<()> {
    // After signing, total (commit_paid + reveal_paid) should cover (commit_req + reveal_req)
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, secrets) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_rf, in_idx, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_input_indices.push(in_idx);
        node_script_vouts.push(sv);
    }
    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();

    // Reveal
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_n = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_n,
    );

    // Nodes sign asynchronously
    let node_sign_futs: Vec<_> = signups
        .iter()
        .enumerate()
        .map(|(index, node_info)| {
            indexer::multi_psbt_test_utils::node_sign_commit_and_reveal(
                node_info,
                index,
                (commit_psbt.clone(), reveal_psbt.clone()),
                &all_prevouts_c,
                &node_input_indices,
                min_sat_per_vb,
                &secrets,
            )
        })
        .collect();
    indexer::multi_psbt_test_utils::merge_node_signatures(
        node_sign_futs,
        &node_input_indices,
        &mut commit_psbt,
        &mut reveal_psbt,
    )
    .await?;

    // Portal signs
    indexer::multi_psbt_test_utils::portal_signs_commit_and_reveal(
        &mut commit_psbt,
        &mut reveal_psbt,
        &portal_info,
        &all_prevouts_c,
        portal_input_index,
        min_sat_per_vb,
        nodes_n,
    )?;

    // Compute actual vs required for commit and reveal
    let mut commit_tx_f = commit_psbt.unsigned_tx.clone();
    for i in 0..commit_psbt.inputs.len() {
        if let Some(w) = &commit_psbt.inputs[i].final_script_witness {
            commit_tx_f.input[i].witness = w.clone();
        }
    }
    let commit_vb_actual = tx_vbytes(&commit_tx_f);
    let commit_req_fee = commit_vb_actual.saturating_mul(min_sat_per_vb);
    let commit_in_total: u64 = commit_psbt
        .inputs
        .iter()
        .map(|inp| inp.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum();
    let commit_out_total: u64 = commit_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let commit_paid = commit_in_total.saturating_sub(commit_out_total);

    let mut reveal_tx_f = reveal_psbt.unsigned_tx.clone();
    for i in 0..reveal_psbt.inputs.len() {
        if let Some(w) = &reveal_psbt.inputs[i].final_script_witness {
            reveal_tx_f.input[i].witness = w.clone();
        }
    }
    let reveal_vb_actual = tx_vbytes(&reveal_tx_f);
    let reveal_req_fee = reveal_vb_actual.saturating_mul(min_sat_per_vb);
    let reveal_in_total: u64 = reveal_psbt
        .inputs
        .iter()
        .map(|inp| inp.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum();
    let reveal_out_total: u64 = reveal_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let reveal_paid = reveal_in_total.saturating_sub(reveal_out_total);

    let required_total = commit_req_fee.saturating_add(reveal_req_fee);
    let paid_total = commit_paid.saturating_add(reveal_paid);

    let slack_vb: u64 = 8;
    let allowed_shortfall = slack_vb.saturating_mul(min_sat_per_vb);
    assert!(
        paid_total.saturating_add(allowed_shortfall) >= required_total,
        "overall payments insufficient: paid={} < required={} (allowed_shortfall={})",
        paid_total,
        required_total,
        allowed_shortfall
    );

    Ok(())
}

#[tokio::test]
async fn test_tap_internal_key_set_on_commit_and_reveal_inputs() -> Result<()> {
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, secrets) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    // Build commit
    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_fee, in_idx, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_input_indices.push(in_idx);
        node_script_vouts.push(sv);
        assert_eq!(
            commit_psbt.inputs[in_idx].tap_internal_key,
            Some(s.internal_key),
            "commit tap_internal_key missing/mismatch for node {}",
            idx
        );
    }
    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;
    assert_eq!(
        commit_psbt.inputs[portal_input_index].tap_internal_key,
        Some(portal_info.internal_key),
        "commit tap_internal_key missing/mismatch for portal"
    );

    // Build reveal
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
        assert_eq!(
            reveal_psbt.inputs[idx].tap_internal_key,
            Some(s.internal_key),
            "reveal tap_internal_key missing/mismatch for node {}",
            idx
        );
    }
    let nodes_len = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_len,
    );
    assert_eq!(
        reveal_psbt.inputs[nodes_len].tap_internal_key,
        Some(portal_info.internal_key),
        "reveal tap_internal_key missing/mismatch for portal"
    );

    // Sign to produce witnesses for the next test to assert shapes
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();
    let node_sign_futs: Vec<_> = signups
        .iter()
        .enumerate()
        .map(|(index, node_info)| {
            indexer::multi_psbt_test_utils::node_sign_commit_and_reveal(
                node_info,
                index,
                (commit_psbt.clone(), reveal_psbt.clone()),
                &all_prevouts_c,
                &node_input_indices,
                min_sat_per_vb,
                &secrets,
            )
        })
        .collect();
    indexer::multi_psbt_test_utils::merge_node_signatures(
        node_sign_futs,
        &node_input_indices,
        &mut commit_psbt,
        &mut reveal_psbt,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_witness_stack_shapes_commit_and_reveal() -> Result<()> {
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;
    let min_sat_per_vb: u64 = 3;

    let (signups, secrets) = get_node_addresses(&secp, &test_cfg)?;
    let node_utxos = mock_fetch_utxos_for_addresses(&signups);

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    for (idx, s) in signups.iter().enumerate() {
        let (_fee, in_idx, sv) = add_single_node_input_and_output_to_psbt(
            &mut commit_psbt,
            &node_utxos,
            idx,
            min_sat_per_vb,
            s,
            dust_limit_sat,
        )?;
        node_input_indices.push(in_idx);
        node_script_vouts.push(sv);
    }
    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("wutxo"))
        .collect();

    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;
    for (idx, s) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            s,
            &commit_psbt,
        );
    }
    let nodes_len = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_len,
    );

    // Sign nodes and portal
    let node_sign_futs: Vec<_> = signups
        .iter()
        .enumerate()
        .map(|(index, node_info)| {
            indexer::multi_psbt_test_utils::node_sign_commit_and_reveal(
                node_info,
                index,
                (commit_psbt.clone(), reveal_psbt.clone()),
                &all_prevouts_c,
                &node_input_indices,
                min_sat_per_vb,
                &secrets,
            )
        })
        .collect();
    indexer::multi_psbt_test_utils::merge_node_signatures(
        node_sign_futs,
        &node_input_indices,
        &mut commit_psbt,
        &mut reveal_psbt,
    )
    .await?;
    indexer::multi_psbt_test_utils::portal_signs_commit_and_reveal(
        &mut commit_psbt,
        &mut reveal_psbt,
        &portal_info,
        &all_prevouts_c,
        portal_input_index,
        min_sat_per_vb,
        nodes_len,
    )?;

    // Assert shapes: commit key-spend = 1 element; reveal script-spend = 3 elements
    for (i, input_idx) in node_input_indices.iter().enumerate() {
        let cw = commit_psbt.inputs[*input_idx]
            .final_script_witness
            .as_ref()
            .expect("commit witness");
        assert_eq!(
            cw.len(),
            1,
            "commit witness must have 1 element for node {}",
            i
        );
        let rw = reveal_psbt.inputs[i]
            .final_script_witness
            .as_ref()
            .expect("reveal witness");
        assert_eq!(
            rw.len(),
            3,
            "reveal witness must have 3 elements for node {}",
            i
        );
    }
    // Portal indices
    let cwp = commit_psbt.inputs[portal_input_index]
        .final_script_witness
        .as_ref()
        .expect("commit witness portal");
    assert_eq!(
        cwp.len(),
        1,
        "commit witness must have 1 element for portal"
    );
    let rwp = reveal_psbt.inputs[nodes_len]
        .final_script_witness
        .as_ref()
        .expect("reveal witness portal");
    assert_eq!(
        rwp.len(),
        3,
        "reveal witness must have 3 elements for portal"
    );

    Ok(())
}
