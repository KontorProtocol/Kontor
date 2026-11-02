use malachitebft_signing_ed25519::PrivateKey;
use serde_json::Value;

use super::{
    Approval, ApprovalSigner, AuthenticatedReference, ControlAction, ControlError,
    ControlOperation, ControlState, UpgradeControl,
};
use crate::consensus::Address;
use crate::protocol::canonical_codec::CodecError;
use crate::protocol::coordinator::certified_decision::{AuthorityMember, CommitteeRecord};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::identity::{
    ChainId, ExecutionDefinitionId, MigrationDefinitionId, PlanId, ProtocolId,
};

fn manifest(number: u64, predecessor: ProtocolId) -> ProtocolManifest {
    ProtocolManifest {
        chain: ChainId([1; 32]),
        protocol_number: number,
        predecessor,
        executor: ExecutionDefinitionId([2; 32]),
        consensus: [3; 32],
        transaction_formats: vec![1, 2],
        host_abis: vec![1],
        bridge_schema: 1,
        state_schema: 1,
        certificate_codec: 1,
        control_codec: 1,
        parameters_root: [4; 32],
        native_contracts_root: [5; 32],
        migration: MigrationDefinitionId([6; 32]),
        input_state_schema: 1,
        output_state_schema: 1,
    }
}

fn state() -> ControlState {
    let current_manifest = manifest(1, ProtocolId([0; 32]));
    let context = EraContext {
        chain: current_manifest.chain,
        era: [7; 32],
        protocol: current_manifest.id().unwrap(),
        codec: 1,
    };
    ControlState {
        context,
        current_manifest,
        head: [8; 32],
        nonce: 0,
        pending: None,
    }
}

fn reference() -> AuthenticatedReference {
    AuthenticatedReference {
        height: 9,
        decision: [9; 32],
        bitcoin_height: 100,
    }
}

fn member(seed: u8, power: u64, generation: u8) -> AuthorityMember {
    let key = PrivateKey::from([seed; 32]).public_key();
    AuthorityMember {
        holder: format!("holder-{seed}"),
        generation: [generation; 32],
        address: Address::from_public_key(&key).into_inner(),
        key: *key.as_bytes(),
        power,
    }
}

fn make_committee(state: &ControlState, powers: &[(u8, u64)]) -> CommitteeRecord {
    CommitteeRecord {
        context: state.context,
        height: 10,
        decision: [10; 32],
        stage: 1,
        lineage: [11; 32],
        members: powers
            .iter()
            .map(|(seed, power)| member(*seed, *power, *seed + 20))
            .collect(),
    }
}

fn schedule(state: &ControlState) -> ControlAction {
    ControlAction {
        context: state.context,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: state.pending.as_ref().map(|plan| plan.id),
        reference_height: 9,
        reference_decision: [9; 32],
        expires_at: 244,
        operation: ControlOperation::Schedule {
            manifest: manifest(2, state.context.protocol),
            activation: 1_108,
        },
    }
}

fn signed(action: ControlAction, members: &[AuthorityMember], seeds: &[u8]) -> UpgradeControl {
    let mut approvals: Vec<Approval> = seeds
        .iter()
        .map(|seed| {
            let member = members
                .iter()
                .find(|member| member.key == *PrivateKey::from([*seed; 32]).public_key().as_bytes())
                .unwrap();
            ApprovalSigner::new(PrivateKey::from([*seed; 32]))
                .sign(&action, member.generation)
                .unwrap()
        })
        .collect();
    approvals.sort_by_key(|entry| entry.key);
    UpgradeControl { action, approvals }
}

fn pending(state: &ControlState, committee: &CommitteeRecord) -> ControlState {
    signed(schedule(state), &committee.members, &[1, 2])
        .verify(state, committee, reference(), 100, 0)
        .unwrap()
        .next
}

#[test]
fn exact_thresholds_and_inclusion_power_changes() {
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let control = signed(schedule(&state), &committee.members, &[1]);
    let accepted = control
        .verify(&state, &committee, reference(), 100, 0)
        .unwrap();
    assert_eq!((accepted.signed_power, accepted.total_power), (5, 6));
    assert_eq!(accepted.next.pending.unwrap().id, PlanId(accepted.action));
    let drift = make_committee(&state, &[(1, 4), (2, 2)]);
    assert!(matches!(
        control.verify(&state, &drift, reference(), 100, 0),
        Err(ControlError::Threshold)
    ));
    let mut state = pending(&state, &committee);
    let target = state.pending.as_ref().unwrap().manifest.id().unwrap();
    let activation = state.pending.as_ref().unwrap().activation;
    let cancel = ControlAction {
        context: state.context,
        head: state.head,
        nonce: 2,
        expected_pending: state.pending.as_ref().map(|plan| plan.id),
        reference_height: 9,
        reference_decision: [9; 32],
        expires_at: 244,
        operation: ControlOperation::Cancel { target, activation },
    };
    assert!(matches!(
        signed(cancel.clone(), &committee.members, &[1]).verify(
            &state,
            &committee,
            reference(),
            100,
            0
        ),
        Ok(_)
    ));
    assert!(matches!(
        signed(cancel.clone(), &drift.members, &[1]).verify(&state, &drift, reference(), 100, 0),
        Err(ControlError::Threshold)
    ));
    state.pending.as_mut().unwrap().consumed = true;
    assert!(matches!(
        signed(cancel, &committee.members, &[1]).verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Plan)
    ));
}

#[test]
fn cancel_requires_strictly_more_than_two_thirds() {
    let original = state();
    let committee = make_committee(&original, &[(1, 4), (2, 2)]);
    let schedule_committee = make_committee(&original, &[(1, 5), (2, 1)]);
    let state = pending(&original, &schedule_committee);
    let plan = state.pending.as_ref().unwrap();
    let cancel = ControlAction {
        context: state.context,
        head: state.head,
        nonce: 2,
        expected_pending: Some(plan.id),
        reference_height: 9,
        reference_decision: [9; 32],
        expires_at: 244,
        operation: ControlOperation::Cancel {
            target: plan.manifest.id().unwrap(),
            activation: plan.activation,
        },
    };
    assert!(matches!(
        signed(cancel.clone(), &committee.members, &[1]).verify(
            &state,
            &committee,
            reference(),
            100,
            0
        ),
        Err(ControlError::Threshold)
    ));
    assert!(
        signed(cancel, &committee.members, &[1, 2])
            .verify(&state, &committee, reference(), 100, 0)
            .unwrap()
            .next
            .pending
            .is_none()
    );
}

#[test]
fn approvals_bind_exact_action_key_generation_and_domain() {
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let mut control = signed(schedule(&state), &committee.members, &[1]);
    control.approvals[0].signature[0] ^= 1;
    assert!(matches!(
        control.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Signature)
    ));
    let mut control = signed(schedule(&state), &committee.members, &[1]);
    control.approvals[0].signature = PrivateKey::from([1; 32])
        .sign(&control.action.id().unwrap())
        .to_bytes();
    assert!(matches!(
        control.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Signature)
    ));
    let leading = make_committee(&state, &[(1, 1), (2, 5)]);
    let mut control = signed(schedule(&state), &leading.members, &[1, 2]);
    control.approvals[1].signature[0] ^= 1;
    assert!(matches!(
        control.verify(&state, &leading, reference(), 100, 0),
        Err(ControlError::Signature)
    ));
    let mut control = signed(schedule(&state), &committee.members, &[1]);
    control.action.expires_at -= 1;
    assert!(matches!(
        control.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Signature)
    ));
    let mut control = signed(schedule(&state), &committee.members, &[1]);
    control.approvals[0].generation = [99; 32];
    assert!(matches!(
        control.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Approval)
    ));
    let mut control = signed(schedule(&state), &committee.members, &[1]);
    control.approvals[0].key = *PrivateKey::from([3; 32]).public_key().as_bytes();
    assert!(matches!(
        control.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Approval)
    ));
    let control = signed(schedule(&state), &committee.members, &[1]);
    let mut duplicate = control.clone();
    duplicate.approvals.push(control.approvals[0].clone());
    assert_eq!(duplicate.encode(), Err(CodecError::UnorderedSet));
    assert!(matches!(
        duplicate.verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Codec(CodecError::UnorderedSet))
    ));
}

#[test]
fn registration_reuse_rejects_old_consent_but_unrelated_churn_does_not() {
    let state = state();
    let original = make_committee(&state, &[(1, 5), (2, 1)]);
    let control = signed(schedule(&state), &original.members, &[1]);
    let mut reused = original.clone();
    reused.members[0].generation = [88; 32];
    assert!(matches!(
        control.verify(&state, &reused, reference(), 100, 0),
        Err(ControlError::Approval)
    ));
    let mut unrelated = original.clone();
    unrelated.members[1].generation = [77; 32];
    assert!(
        control
            .verify(&state, &unrelated, reference(), 100, 0)
            .is_ok()
    );
    let accepted = control
        .verify(&state, &original, reference(), 100, 0)
        .unwrap();
    assert_eq!(accepted.next.pending.unwrap().id, PlanId(accepted.action));
}

#[test]
fn state_cas_reference_expiry_and_notice_are_checked() {
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let control = signed(schedule(&state), &committee.members, &[1]);
    let mut changed = state.clone();
    changed.head[0] ^= 1;
    assert!(matches!(
        control.verify(&changed, &committee, reference(), 100, 0),
        Err(ControlError::Stale)
    ));
    changed = state.clone();
    changed.nonce = 1;
    assert!(matches!(
        control.verify(&changed, &committee, reference(), 100, 0),
        Err(ControlError::Stale)
    ));
    assert!(matches!(
        control.verify(&state, &committee, reference(), 245, 0),
        Err(ControlError::Reference)
    ));
    let mut wrong = reference();
    wrong.decision[0] ^= 1;
    assert!(matches!(
        control.verify(&state, &committee, wrong, 100, 0),
        Err(ControlError::Reference)
    ));
    let mut future_bitcoin = reference();
    future_bitcoin.bitcoin_height = 101;
    assert!(matches!(
        control.verify(&state, &committee, future_bitcoin, 100, 0),
        Err(ControlError::Reference)
    ));
    wrong = reference();
    wrong.height = 10;
    assert!(matches!(
        control.verify(&state, &committee, wrong, 100, 0),
        Err(ControlError::Reference)
    ));
    let mut action = schedule(&state);
    action.reference_height = 10;
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(&state, &committee, wrong, 100, 0),
        Err(ControlError::Reference)
    ));
    let mut action = schedule(&state);
    if let ControlOperation::Schedule { activation, .. } = &mut action.operation {
        *activation -= 1;
    }
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Plan)
    ));
    let mut overflow = state.clone();
    overflow.nonce = u64::MAX;
    assert!(matches!(
        control.verify(&overflow, &committee, reference(), 100, 0),
        Err(ControlError::Overflow)
    ));
    let near_max = state.clone();
    let mut near_max_ref = reference();
    near_max_ref.bitcoin_height = u64::MAX - 1_008;
    let mut action = schedule(&near_max);
    action.expires_at = u64::MAX - 864;
    if let ControlOperation::Schedule { activation, .. } = &mut action.operation {
        *activation = u64::MAX;
    }
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(
            &near_max,
            &committee,
            near_max_ref,
            u64::MAX - 1_007,
            0
        ),
        Err(ControlError::Overflow)
    ));
    near_max_ref.bitcoin_height = u64::MAX - 100;
    let mut action = schedule(&near_max);
    action.expires_at = u64::MAX;
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(
            &near_max,
            &committee,
            near_max_ref,
            near_max_ref.bitcoin_height,
            0
        ),
        Err(ControlError::Overflow)
    ));
}

#[test]
fn conflicting_plan_and_postpone_target_are_rejected() {
    let original = state();
    let committee = make_committee(&original, &[(1, 5), (2, 1)]);
    let state = pending(&original, &committee);
    assert!(matches!(
        signed(schedule(&state), &committee.members, &[1]).verify(
            &state,
            &committee,
            reference(),
            100,
            0
        ),
        Err(ControlError::Plan)
    ));
    let plan = state.pending.as_ref().unwrap();
    let mut action = ControlAction {
        context: state.context,
        head: state.head,
        nonce: 2,
        expected_pending: Some(plan.id),
        reference_height: 9,
        reference_decision: [9; 32],
        expires_at: 244,
        operation: ControlOperation::Postpone {
            target: plan.manifest.id().unwrap(),
            previous_activation: plan.activation,
            activation: plan.activation + 1,
        },
    };
    let postponed = signed(action.clone(), &committee.members, &[1])
        .verify(&state, &committee, reference(), 100, 0)
        .unwrap();
    assert_eq!(postponed.next.pending.unwrap().activation, 1_109);
    if let ControlOperation::Postpone { target, .. } = &mut action.operation {
        *target = ProtocolId([55; 32]);
    }
    assert!(matches!(
        signed(action.clone(), &committee.members, &[1]).verify(
            &state,
            &committee,
            reference(),
            100,
            0
        ),
        Err(ControlError::Plan)
    ));
    if let ControlOperation::Postpone {
        target, activation, ..
    } = &mut action.operation
    {
        *target = plan.manifest.id().unwrap();
        *activation = plan.activation;
    }
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Plan)
    ));
}

#[test]
fn canonical_codec_rejects_all_truncations_and_trailing_bytes() {
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let control = signed(schedule(&state), &committee.members, &[1]);
    let action = control.action.encode().unwrap();
    let bytes = control.encode().unwrap();
    assert_eq!(ControlAction::decode(&action).unwrap(), control.action);
    assert_eq!(UpgradeControl::decode(&bytes).unwrap(), control);
    for length in 0..action.len() {
        assert!(
            ControlAction::decode(&action[..length]).is_err(),
            "action {length}"
        );
    }
    for length in 0..bytes.len() {
        assert!(
            UpgradeControl::decode(&bytes[..length]).is_err(),
            "control {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        UpgradeControl::decode(&trailing),
        Err(CodecError::TrailingBytes)
    );
    let mut bad_tag = bytes;
    bad_tag[3] = b'2';
    assert_eq!(
        UpgradeControl::decode(&bad_tag),
        Err(CodecError::InvalidTag)
    );
    let mut unsorted = signed(schedule(&state), &committee.members, &[1, 2]);
    unsorted.approvals.reverse();
    assert_eq!(unsorted.encode(), Err(CodecError::UnorderedSet));
}

#[test]
fn k6_wire_and_signature_match_independent_golden_vector() {
    let vector: Value = serde_json::from_str(include_str!("test-vector.json")).unwrap();
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let control = signed(schedule(&state), &committee.members, &[1]);
    assert_eq!(
        hex::encode(control.action.encode().unwrap()),
        vector["action_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(control.action.id().unwrap()),
        vector["action_id"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(control.approvals[0].key),
        vector["approval_key"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(
            super::approval_digest(
                control.action.id().unwrap(),
                control.approvals[0].key,
                control.approvals[0].generation
            )
            .unwrap()
        ),
        vector["approval_digest"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(control.approvals[0].signature),
        vector["approval_signature"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(control.encode().unwrap()),
        vector["control_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(control.id().unwrap()),
        vector["control_id"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(state.encode().unwrap()),
        vector["state_empty_hex"].as_str().unwrap()
    );
    let accepted = control
        .verify(&state, &committee, reference(), 100, 0)
        .unwrap();
    assert_eq!(
        hex::encode(accepted.next.encode().unwrap()),
        vector["state_pending_hex"].as_str().unwrap()
    );
}

#[test]
fn k6_wire_wide_postpone_and_cancel_match_cross_language_vectors() {
    let vector: Value = serde_json::from_str(include_str!("test-vector.json")).unwrap();
    let state = state();
    let target = manifest(2, state.context.protocol).id().unwrap();
    let mut action = schedule(&state);
    action.head = hex::decode(vector["control_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    action.nonce = u64::MAX;
    action.expected_pending = Some(PlanId(
        hex::decode(vector["action_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    ));
    action.reference_height = (1_u64 << 53) + 1;
    action.expires_at = u64::MAX - 1;
    for entry in vector["wide_actions"].as_array().unwrap() {
        action.operation = match entry["kind"].as_str().unwrap() {
            "postpone" => ControlOperation::Postpone {
                target,
                previous_activation: 1108,
                activation: u64::MAX,
            },
            "cancel" => ControlOperation::Cancel {
                target,
                activation: 1108,
            },
            kind => panic!("unknown vector kind {kind}"),
        };
        let bytes = action.encode().unwrap();
        assert_eq!(hex::encode(&bytes), entry["action_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(action.id().unwrap()),
            entry["action_id"].as_str().unwrap()
        );
        assert_eq!(ControlAction::decode(&bytes).unwrap(), action);
    }
}

#[test]
fn accepted_schedule_does_not_reauthorize_after_committee_change() {
    let original = state();
    let committee = make_committee(&original, &[(1, 5), (2, 1)]);
    let accepted = signed(schedule(&original), &committee.members, &[1])
        .verify(&original, &committee, reference(), 100, 0)
        .unwrap();
    let changed = make_committee(&original, &[(1, 1), (2, 5)]);
    assert_eq!(accepted.next.pending.unwrap().id, PlanId(accepted.action));
    assert_eq!(changed.members[0].power, 1);
}

#[test]
fn schedule_checks_predecessor_and_schema_without_needing_target_installation() {
    let state = state();
    let committee = make_committee(&state, &[(1, 5), (2, 1)]);
    let mut action = schedule(&state);
    if let ControlOperation::Schedule { manifest, .. } = &mut action.operation {
        manifest.executor = ExecutionDefinitionId([99; 32]);
    }
    assert!(
        signed(action.clone(), &committee.members, &[1])
            .verify(&state, &committee, reference(), 100, 0)
            .is_ok()
    );
    if let ControlOperation::Schedule { manifest, .. } = &mut action.operation {
        manifest.predecessor = ProtocolId([99; 32]);
    }
    assert!(matches!(
        signed(action.clone(), &committee.members, &[1]).verify(
            &state,
            &committee,
            reference(),
            100,
            0
        ),
        Err(ControlError::Plan)
    ));
    if let ControlOperation::Schedule { manifest, .. } = &mut action.operation {
        manifest.predecessor = state.context.protocol;
        manifest.input_state_schema = 99;
    }
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Plan)
    ));
    let mut action = schedule(&state);
    if let ControlOperation::Schedule { manifest, .. } = &mut action.operation {
        manifest.output_state_schema = 99;
    }
    assert!(matches!(
        signed(action, &committee.members, &[1]).verify(&state, &committee, reference(), 100, 0),
        Err(ControlError::Plan)
    ));
    let mut differently_migrated = state.clone();
    differently_migrated.current_manifest.output_state_schema = 3;
    differently_migrated.context.protocol = differently_migrated.current_manifest.id().unwrap();
    let action = schedule(&differently_migrated);
    let matching_committee = make_committee(&differently_migrated, &[(1, 5), (2, 1)]);
    assert!(
        signed(action, &matching_committee.members, &[1])
            .verify(
                &differently_migrated,
                &matching_committee,
                reference(),
                100,
                0
            )
            .is_ok()
    );
}

#[test]
fn old_cancel_and_postpone_approvals_cannot_replay_after_postponement() {
    let original = state();
    let committee = make_committee(&original, &[(1, 5), (2, 1)]);
    let pending = pending(&original, &committee);
    let plan = pending.pending.as_ref().unwrap();
    let target = plan.manifest.id().unwrap();
    let old_cancel = signed(
        ControlAction {
            context: pending.context,
            head: pending.head,
            nonce: pending.nonce + 1,
            expected_pending: Some(plan.id),
            reference_height: 9,
            reference_decision: [9; 32],
            expires_at: 244,
            operation: ControlOperation::Cancel {
                target,
                activation: plan.activation,
            },
        },
        &committee.members,
        &[1, 2],
    );
    assert!(
        old_cancel
            .verify(&pending, &committee, reference(), 244, 0)
            .is_ok()
    );
    let mut stale_plan = old_cancel.action.clone();
    stale_plan.expected_pending = Some(PlanId([44; 32]));
    assert!(matches!(
        signed(stale_plan, &committee.members, &[1, 2]).verify(
            &pending,
            &committee,
            reference(),
            100,
            0
        ),
        Err(ControlError::Stale)
    ));
    let postpone = signed(
        ControlAction {
            operation: ControlOperation::Postpone {
                target,
                previous_activation: plan.activation,
                activation: plan.activation + 1,
            },
            ..old_cancel.action.clone()
        },
        &committee.members,
        &[1],
    );
    let after = postpone
        .verify(&pending, &committee, reference(), 100, 0)
        .unwrap()
        .next;
    assert!(matches!(
        old_cancel.verify(&after, &committee, reference(), 100, 0),
        Err(ControlError::Stale)
    ));
    assert!(matches!(
        postpone.verify(&after, &committee, reference(), 100, 0),
        Err(ControlError::Stale)
    ));
    let current = after.pending.as_ref().unwrap();
    assert!(
        signed(
            ControlAction {
                context: after.context,
                head: after.head,
                nonce: after.nonce + 1,
                expected_pending: Some(current.id),
                reference_height: 9,
                reference_decision: [9; 32],
                expires_at: 244,
                operation: ControlOperation::Cancel {
                    target,
                    activation: current.activation,
                },
            },
            &committee.members,
            &[1, 2],
        )
        .verify(&after, &committee, reference(), 100, 0)
        .unwrap()
        .next
        .pending
        .is_none()
    );
}

#[test]
fn rollback_floor_rejects_old_and_alternate_consent_after_state_restore() {
    let restored = state();
    let mut inclusion = make_committee(&restored, &[(1, 5), (2, 1)]);
    inclusion.height = 13;
    let old = signed(schedule(&restored), &inclusion.members, &[1]);
    let mut alternative_action = schedule(&restored);
    alternative_action.expires_at = 243;
    let alternative = signed(alternative_action, &inclusion.members, &[1]);
    assert!(
        old.verify(&restored, &inclusion, reference(), 100, 0)
            .is_ok()
    );
    for consent in [&old, &alternative] {
        assert!(matches!(
            consent.verify(&restored, &inclusion, reference(), 100, 12),
            Err(ControlError::Reference)
        ));
    }
    let fresh_reference = AuthenticatedReference {
        height: 12,
        decision: [12; 32],
        bitcoin_height: 80,
    };
    let mut fresh_action = schedule(&restored);
    fresh_action.reference_height = fresh_reference.height;
    fresh_action.reference_decision = fresh_reference.decision;
    fresh_action.expires_at = 224;
    if let ControlOperation::Schedule { activation, .. } = &mut fresh_action.operation {
        *activation = 1_098;
    }
    let fresh = signed(fresh_action, &inclusion.members, &[1]);
    let accepted = fresh
        .verify(&restored, &inclusion, fresh_reference, 90, 12)
        .unwrap();
    assert_eq!(accepted.next.pending.unwrap().activation, 1_098);
    assert!(matches!(
        fresh.verify(&restored, &inclusion, fresh_reference, 90, 13),
        Err(ControlError::Reference)
    ));
}

#[test]
fn changing_signed_reference_requires_new_approval_signatures() {
    let restored = state();
    let mut inclusion = make_committee(&restored, &[(1, 5), (2, 1)]);
    inclusion.height = 13;
    let mut old = signed(schedule(&restored), &inclusion.members, &[1]);
    old.action.reference_height = 12;
    old.action.reference_decision = [12; 32];
    let changed_reference = AuthenticatedReference {
        height: 12,
        decision: [12; 32],
        bitcoin_height: 100,
    };
    assert!(matches!(
        old.verify(&restored, &inclusion, changed_reference, 100, 12),
        Err(ControlError::Signature)
    ));
}

#[test]
fn reversible_control_state_codec_roundtrips_and_rejects_malformed_snapshots() {
    let empty = state();
    let empty_bytes = empty.encode().unwrap();
    assert!(empty_bytes.starts_with(b"KUS1"));
    assert_eq!(ControlState::decode(&empty_bytes), Ok(empty.clone()));
    let committee = make_committee(&empty, &[(1, 5), (2, 1)]);
    let mut with_pending = pending(&empty, &committee);
    for consumed in [false, true] {
        with_pending.pending.as_mut().unwrap().consumed = consumed;
        let bytes = with_pending.encode().unwrap();
        assert_eq!(ControlState::decode(&bytes), Ok(with_pending.clone()));
        for length in 0..bytes.len() {
            assert!(ControlState::decode(&bytes[..length]).is_err(), "{length}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            ControlState::decode(&trailing),
            Err(CodecError::TrailingBytes)
        );
        let mut bad_consumed = bytes;
        *bad_consumed.last_mut().unwrap() = 2;
        assert_eq!(
            ControlState::decode(&bad_consumed),
            Err(CodecError::InvalidTag)
        );
    }
    let mut invalid = empty_bytes.clone();
    invalid[3] = b'2';
    assert_eq!(ControlState::decode(&invalid), Err(CodecError::InvalidTag));
    invalid = empty_bytes.clone();
    *invalid.last_mut().unwrap() = 2;
    assert_eq!(ControlState::decode(&invalid), Err(CodecError::InvalidTag));
    invalid = empty_bytes.clone();
    invalid[68] ^= 1;
    assert_eq!(
        ControlState::decode(&invalid),
        Err(CodecError::InvalidValue)
    );
    invalid = empty_bytes.clone();
    invalid[104..108].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(ControlState::decode(&invalid).is_err());
    assert_eq!(
        ControlState::decode(&vec![0; super::MAX_BATCH_BYTES + 1]),
        Err(CodecError::LengthOverflow)
    );
}
