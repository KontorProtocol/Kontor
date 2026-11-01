use indexer_types::{OpWithResult, Transaction};
use libsql::Connection;

use crate::database::storage_inspection_v1::inspection_callbacks;
use crate::protocol::v1::inspection;
pub use crate::protocol::v1::transactions::{
    OpMetadataBase, TransactionFilterMap, TxWalker, filter_map, materialize_op,
};

pub async fn inspect(conn: &Connection, tx: &Transaction) -> anyhow::Result<Vec<OpWithResult>> {
    inspection::inspect(&inspection_callbacks(conn), tx).await
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::key::{Keypair, Secp256k1, rand};
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN};
    use bitcoin::opcodes::{OP_0, OP_FALSE};
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use indexer_types::{
        AggregateInfo, AggregateSigner, ContractAddress, Inst, InstKind, Insts, SignerRef,
        serialize,
    };

    use super::filter_map;
    use crate::test_utils::{PublicKey as TestPublicKey, build_inscription};

    fn tx_with_taproot_script_witness(
        tap_script: ScriptBuf,
        internal_key: bitcoin::XOnlyPublicKey,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .expect("add_leaf")
            .finalize(&secp, internal_key)
            .expect("finalize");
        let control_block = spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .expect("control_block");
        let mut witness = Witness::new();
        witness.push(vec![0u8; 64]);
        witness.push(tap_script.as_bytes());
        witness.push(control_block.serialize());
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn random_xonly() -> bitcoin::XOnlyPublicKey {
        let secp = Secp256k1::new();
        Keypair::new(&secp, &mut rand::thread_rng())
            .x_only_public_key()
            .0
    }

    #[test]
    fn filter_map_parses_valid_aggregate_envelope() {
        let xonly = random_xonly();
        let contract = ContractAddress {
            name: "c".to_string(),
            height: 1,
            tx_index: 2,
        };
        let op = Inst {
            gas_limit: 123,
            kind: InstKind::Call {
                contract,
                expr: "noop()".to_string(),
            },
        };
        let insts = Insts {
            ops: vec![op.clone()],
            aggregate: Some(AggregateInfo {
                signers: vec![AggregateSigner {
                    identity: SignerRef::SignerId(7),
                    nonce: 0,
                    sponsored: false,
                }],
                signature: vec![9u8; 48],
            }),
        };
        let payload = serialize(&insts).expect("serialize Insts");
        let tap_script =
            build_inscription(payload, TestPublicKey::Taproot(&xonly)).expect("build tap script");
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        let parsed = filter_map((0, tx)).expect("expected tx to be recognized as Kontor tx");
        assert_eq!(parsed.inputs.len(), 1);
        let input = &parsed.inputs[0];
        assert_eq!(input.x_only_pubkey, xonly);
        assert_eq!(input.insts, insts);
    }

    #[test]
    fn filter_map_captures_full_multi_push_op_return() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
        let tap_script =
            build_inscription(payload, TestPublicKey::Taproot(&xonly)).expect("build tap script");
        let mut tx = tx_with_taproot_script_witness(tap_script, xonly);

        // OP_RETURN carrying two pushes: a marker then a 32-byte payload. The
        // capture must expose everything after the opcode, not just "kon".
        let op_return = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"kon")
            .push_slice([0xABu8; 32])
            .into_script();
        tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: op_return.clone(),
        });

        let parsed = filter_map((0, tx)).expect("recognized Kontor tx");
        // The whole script after the single OP_RETURN opcode byte.
        assert_eq!(
            parsed.op_return_raw,
            Some(op_return.as_bytes()[1..].to_vec())
        );
        // The second push must be present — the old first-push-only capture
        // would have dropped it.
        assert!(
            parsed
                .op_return_raw
                .unwrap()
                .windows(32)
                .any(|w| w == [0xABu8; 32])
        );
    }

    #[test]
    fn filter_map_rejects_wrong_marker() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kor")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_rejects_trailing_instructions_after_endif() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_0)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_concatenates_multi_push_payload() {
        let xonly = random_xonly();
        let inst = Inst {
            gas_limit: 7,
            kind: InstKind::Call {
                contract: ContractAddress {
                    name: "arith".to_string(),
                    height: 1,
                    tx_index: 0,
                },
                expr: "eval(10, id)".to_string(),
            },
        };
        let payload = serialize(&Insts::single(inst)).expect("serialize");
        let mid = payload.len() / 2;
        let (p0, p1) = payload.split_at(mid);
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(p0.to_vec()).expect("pushbytes"))
            .push_slice(PushBytesBuf::try_from(p1.to_vec()).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        let parsed = filter_map((0, tx)).expect("expected tx to be recognized");
        assert_eq!(parsed.inputs.len(), 1);
        let input = &parsed.inputs[0];
        assert_eq!(input.x_only_pubkey, xonly);
        assert_eq!(input.insts.ops.len(), 1);
        match &input.insts.ops[0] {
            Inst {
                gas_limit,
                kind: InstKind::Call { contract, expr },
            } => {
                assert_eq!(*gas_limit, 7);
                assert_eq!(contract.name, "arith");
                assert_eq!(expr, "eval(10, id)");
            }
            other => panic!("expected Inst::Call, got {other:?}"),
        }
    }

    #[test]
    fn filter_map_rejects_non_pushbytes_inside_envelope() {
        let xonly = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
        let tap_script = Builder::new()
            .push_slice(xonly.serialize())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ADD)
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, xonly);
        assert!(filter_map((0, tx)).is_none());
    }

    #[test]
    fn filter_map_rejects_invalid_xonly_pubkey_bytes() {
        let internal_key = random_xonly();
        let payload = serialize(&Insts::single(Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        }))
        .expect("serialize");
        let tap_script = Builder::new()
            .push_slice([0u8; 32])
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(b"kon")
            .push_opcode(OP_0)
            .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
            .push_opcode(OP_ENDIF)
            .into_script();
        let tx = tx_with_taproot_script_witness(tap_script, internal_key);
        assert!(filter_map((0, tx)).is_none());
    }

    // -----------------------------------------------------------------------
    // materialize_op — payer + gas_limit resolution
    // -----------------------------------------------------------------------

    use super::{OpMetadataBase, materialize_op};
    use indexer_types::{OpKind, Payment};

    fn dummy_call_inst(gas_limit: u64) -> Inst {
        Inst {
            gas_limit,
            kind: InstKind::Call {
                contract: ContractAddress {
                    name: "c".into(),
                    height: 1,
                    tx_index: 0,
                },
                expr: "noop()".into(),
            },
        }
    }

    fn dummy_base(signer_id: u64) -> OpMetadataBase {
        OpMetadataBase {
            previous_output: bitcoin::OutPoint::null(),
            input_index: 0,
            op_index: 0,
            signer_id,
        }
    }

    #[test]
    fn materialize_uses_input_signer_and_inst_gas_limit_with_no_override() {
        let inst = dummy_call_inst(123);
        let op = materialize_op(inst, dummy_base(42), None).unwrap();
        assert!(matches!(op.kind, OpKind::Call { .. }));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 42,
                gas_limit: 123,
            }
        );
    }

    #[test]
    fn materialize_override_replaces_both_signer_and_cap() {
        // Used for both the cross-input Sponsor case (override = sponsor's
        // payment) and the aggregate-sponsored case (override = publisher's
        // payment + inst.gas_limit). One mechanism.
        let inst = dummy_call_inst(123);
        let override_payment = Payment {
            signer_id: 99,
            gas_limit: 9_999,
        };
        let op = materialize_op(inst, dummy_base(42), Some(override_payment)).unwrap();
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 99,
                gas_limit: 9_999,
            }
        );
        // The op's *signer* (the input's signer) is unchanged — override
        // only redirects the payer.
        assert_eq!(op.metadata.signer_id, 42);
    }

    #[test]
    fn materialize_sponsor_uses_its_own_payment_ignoring_override() {
        // Sponsor materializes as OpKind::Sponsor; metadata.payment
        // captures the sponsorship terms (input signer + inst.gas_limit).
        // An incoming override does NOT apply to Sponsor itself — its own
        // Payment is what the reactor reads back to drive the next input.
        let inst = Inst {
            gas_limit: 5_000,
            kind: InstKind::Sponsor,
        };
        let unrelated_override = Payment {
            signer_id: 99,
            gas_limit: 9_999,
        };
        let op = materialize_op(inst, dummy_base(42), Some(unrelated_override)).unwrap();
        assert!(matches!(op.kind, OpKind::Sponsor));
        assert_eq!(
            op.metadata.payment,
            Payment {
                signer_id: 42,
                gas_limit: 5_000,
            }
        );
    }

    // -----------------------------------------------------------------------
    // TxWalker: Sponsor state machine + payment-override precedence
    // -----------------------------------------------------------------------

    use super::TxWalker;
    use indexer_types::{Input, Op};

    fn direct_input(insts: Insts) -> Input {
        Input {
            previous_output: bitcoin::OutPoint::null(),
            input_index: 0,
            x_only_pubkey: random_xonly(),
            insts,
        }
    }

    fn aggregate_input(insts: Vec<Inst>, sponsored_flags: Vec<bool>) -> Input {
        let signers = sponsored_flags
            .into_iter()
            .map(|sponsored| AggregateSigner {
                identity: SignerRef::SignerId(0),
                nonce: 0,
                sponsored,
            })
            .collect();
        let bundle = Insts {
            ops: insts,
            aggregate: Some(AggregateInfo {
                signers,
                signature: vec![0u8; 48],
            }),
        };
        direct_input(bundle)
    }

    #[test]
    fn walker_payment_override_is_none_with_no_active_and_direct_input() {
        let walker = TxWalker::new();
        let input = direct_input(Insts::single(dummy_call_inst(123)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn walker_payment_override_uses_publisher_for_aggregate_sponsored() {
        let walker = TxWalker::new();
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![true]);
        let got = walker
            .payment_override(&input, 0, Some(7), &input.insts.ops[0])
            .unwrap()
            .expect("sponsored aggregate op → publisher override");
        assert_eq!(
            got,
            Payment {
                signer_id: 7,
                gas_limit: 123,
            }
        );
    }

    #[test]
    fn walker_payment_override_errors_when_sponsored_but_publisher_missing() {
        // Mirrors the old PaymentIntent::Sponsored-without-offer reject:
        // a sponsored aggregate op with no resolved publisher must not
        // silently fall back to the co-signer self-paying.
        let walker = TxWalker::new();
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![true]);
        let err = walker
            .payment_override(&input, 0, None, &input.insts.ops[0])
            .expect_err("missing publisher must error, not silent self-pay");
        assert!(
            err.to_string().contains("publisher"),
            "error should mention the missing publisher: {err}"
        );
    }

    #[test]
    fn walker_payment_override_is_none_for_aggregate_non_sponsored() {
        let walker = TxWalker::new();
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![false]);
        assert!(
            walker
                .payment_override(&input, 0, Some(7), &input.insts.ops[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn walker_active_beats_publisher_offer() {
        let mut walker = TxWalker::new();
        let sponsor_op = Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 42,
                    gas_limit: 5_000,
                },
            },
            kind: OpKind::Sponsor,
        };
        walker.capture(&sponsor_op);
        walker.next_input();
        // Even with publisher_signer_id provided, active (cross-input
        // Sponsor) wins.
        let input = aggregate_input(vec![dummy_call_inst(123)], vec![true]);
        let got = walker
            .payment_override(&input, 0, Some(7), &input.insts.ops[0])
            .unwrap()
            .expect("active sponsor present");
        assert_eq!(
            got,
            Payment {
                signer_id: 42,
                gas_limit: 5_000,
            }
        );
    }

    #[test]
    fn walker_capture_then_next_input_promotes_pending_to_active() {
        let mut walker = TxWalker::new();
        let sponsor_op = Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 99,
                    gas_limit: 1_000,
                },
            },
            kind: OpKind::Sponsor,
        };
        walker.capture(&sponsor_op);
        // Before the input boundary, active is still None.
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .unwrap()
                .is_none()
        );
        walker.next_input();
        // After the boundary, active reflects the captured Sponsor.
        let got = walker
            .payment_override(&input, 0, None, &input.insts.ops[0])
            .unwrap()
            .expect("active promoted from pending");
        assert_eq!(
            got,
            Payment {
                signer_id: 99,
                gas_limit: 1_000,
            }
        );
    }

    #[test]
    fn walker_capture_ignores_non_sponsor_ops() {
        let mut walker = TxWalker::new();
        let call_op = materialize_op(dummy_call_inst(123), dummy_base(42), None).unwrap();
        walker.capture(&call_op);
        walker.next_input();
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn walker_next_input_clears_active_if_no_sponsor_this_round() {
        let mut walker = TxWalker::new();
        // First input: capture a Sponsor → active for input 2.
        walker.capture(&Op {
            metadata: indexer_types::OpMetadata {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                op_index: 0,
                signer_id: 0,
                payment: Payment {
                    signer_id: 99,
                    gas_limit: 1_000,
                },
            },
            kind: OpKind::Sponsor,
        });
        walker.next_input();
        // Input 2: no new Sponsor captured.
        walker.next_input();
        // Input 3: active is gone — Sponsor only sponsors the immediately
        // following input.
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        assert!(
            walker
                .payment_override(&input, 0, None, &input.insts.ops[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn walker_capture_last_sponsor_wins_within_one_input() {
        let mut walker = TxWalker::new();
        for &signer_id in &[1u64, 2, 3] {
            walker.capture(&Op {
                metadata: indexer_types::OpMetadata {
                    previous_output: bitcoin::OutPoint::null(),
                    input_index: 0,
                    op_index: 0,
                    signer_id: 0,
                    payment: Payment {
                        signer_id,
                        gas_limit: 100 * signer_id,
                    },
                },
                kind: OpKind::Sponsor,
            });
        }
        walker.next_input();
        let input = direct_input(Insts::single(dummy_call_inst(50)));
        let got = walker
            .payment_override(&input, 0, None, &input.insts.ops[0])
            .unwrap()
            .expect("last Sponsor's payment is active");
        assert_eq!(
            got,
            Payment {
                signer_id: 3,
                gas_limit: 300,
            }
        );
    }
}
