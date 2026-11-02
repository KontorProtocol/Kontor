use super::*;
use crate::protocol::coordinator::control::PendingPlan;
use crate::protocol::identity::{ExecutionDefinitionId, MigrationDefinitionId};

fn manifest(number: u64, predecessor: ProtocolId) -> ProtocolManifest {
    ProtocolManifest {
        chain: ChainId([1; 32]),
        protocol_number: number,
        predecessor,
        executor: ExecutionDefinitionId([number as u8; 32]),
        consensus: [number as u8; 32],
        transaction_formats: vec![1],
        host_abis: vec![1],
        bridge_schema: 1,
        state_schema: number as u32,
        certificate_codec: 1,
        control_codec: 1,
        parameters_root: [2; 32],
        native_contracts_root: [3; 32],
        migration: MigrationDefinitionId([number as u8; 32]),
        input_state_schema: number.saturating_sub(1).max(1) as u32,
        output_state_schema: number as u32,
    }
}

fn scheduled() -> ControlState {
    let first = manifest(1, ProtocolId([0; 32]));
    let protocol = first.id().unwrap();
    ControlState {
        context: EraContext {
            chain: first.chain,
            era: [4; 32],
            protocol,
            codec: 1,
        },
        current_manifest: first,
        head: [5; 32],
        nonce: 1,
        pending: Some(PendingPlan {
            id: PlanId([6; 32]),
            manifest: manifest(2, protocol),
            activation: 1_100,
            consumed: false,
        }),
    }
}

#[test]
fn descriptor_requires_the_surviving_exact_boundary() -> Result<()> {
    let state = scheduled();
    assert!(TransitionDescriptor::expected(&state, 1_099, [7; 32], 200)?.is_none());
    let descriptor = TransitionDescriptor::expected(&state, 1_100, [7; 32], 200)?.unwrap();
    assert_eq!(descriptor.start_height, 201);
    assert_eq!(descriptor.plan, state.pending.as_ref().unwrap().id);
    assert_eq!(descriptor.source, state.context.protocol);
    assert_eq!(
        descriptor.target,
        state.pending.as_ref().unwrap().manifest.id()?
    );
    assert_eq!(
        TransitionDescriptor::decode(&descriptor.encode()?)?,
        descriptor
    );
    assert!(TransitionDescriptor::expected(&state, 1_101, [7; 32], 200).is_err());
    assert!(TransitionDescriptor::expected(&state, 1_100, [7; 32], u64::MAX).is_err());

    let mut removed = state.clone();
    removed.pending = None;
    assert!(TransitionDescriptor::expected(&removed, 1_100, [7; 32], 200)?.is_none());
    let mut consumed = state.clone();
    consumed.pending.as_mut().unwrap().consumed = true;
    assert!(TransitionDescriptor::expected(&consumed, 1_101, [7; 32], 201)?.is_none());
    let mut stale = state.clone();
    stale.pending.as_mut().unwrap().manifest.predecessor = ProtocolId([8; 32]);
    assert!(TransitionDescriptor::expected(&stale, 1_100, [7; 32], 200).is_err());
    let mut wrong_schema = state.clone();
    wrong_schema
        .pending
        .as_mut()
        .unwrap()
        .manifest
        .input_state_schema = 3;
    assert!(TransitionDescriptor::expected(&wrong_schema, 1_100, [7; 32], 200).is_err());
    Ok(())
}

#[test]
fn completed_selection_not_the_proposal_determines_handoff() -> Result<()> {
    let state = scheduled();
    assert!(TransitionDescriptor::expected(&state, 1_100, [7; 32], 200)?.is_some());
    // H's due finality may remove its schedule. The old protocol then remains
    // selected even though the original certified Block carried a descriptor.
    assert!(
        EraTransition::derive(
            state.context,
            200,
            [8; 32],
            [9; 32],
            &state.current_manifest
        )?
        .is_none()
    );
    let target = &state.pending.as_ref().unwrap().manifest;
    let next = EraTransition::derive(state.context, 200, [8; 32], [9; 32], target)?.unwrap();
    assert_eq!(next.next.protocol, target.id()?);
    assert_eq!(next.start_height()?, 201);
    assert_eq!(next.next.codec, 1);
    assert_ne!(next.next.era, state.context.era);
    assert!(EraTransition::derive(next.next, 201, [10; 32], [11; 32], target)?.is_none());
    Ok(())
}

#[test]
fn rollback_to_old_protocol_gets_a_fresh_era_and_monotonic_height() -> Result<()> {
    let state = scheduled();
    let target = &state.pending.as_ref().unwrap().manifest;
    let forward = EraTransition::derive(state.context, 200, [8; 32], [9; 32], target)?.unwrap();
    let restored = EraTransition::derive(
        forward.next,
        210,
        [10; 32],
        [11; 32],
        &state.current_manifest,
    )?
    .unwrap();
    assert_eq!(restored.next.protocol, state.context.protocol);
    assert_eq!(restored.start_height()?, 211);
    assert_ne!(restored.next.era, state.context.era);
    assert_ne!(restored.next.era, forward.next.era);
    let retry = EraTransition::derive(restored.next, 220, [12; 32], [13; 32], target)?.unwrap();
    assert_ne!(retry.next.era, forward.next.era);
    let changed_lineage = EraTransition::derive(
        forward.next,
        210,
        [10; 32],
        [14; 32],
        &state.current_manifest,
    )?
    .unwrap();
    assert_ne!(changed_lineage.next.era, restored.next.era);
    assert_eq!(EraTransition::decode(&restored.encode()?)?, restored);
    Ok(())
}

#[test]
fn persisted_transition_rejects_tampering_truncation_and_overflow() -> Result<()> {
    let state = scheduled();
    let target = &state.pending.as_ref().unwrap().manifest;
    let transition = EraTransition::derive(state.context, 200, [8; 32], [9; 32], target)?.unwrap();
    let bytes = transition.encode()?;
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            EraTransition::decode(&changed).is_err(),
            "unbound byte {index}"
        );
        assert!(EraTransition::decode(&bytes[..index]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(EraTransition::decode(&trailing).is_err());
    assert!(EraTransition::derive(state.context, u64::MAX, [8; 32], [9; 32], target).is_err());
    let mut wrong_chain = target.clone();
    wrong_chain.chain = ChainId([15; 32]);
    assert!(EraTransition::derive(state.context, 200, [8; 32], [9; 32], &wrong_chain).is_err());
    Ok(())
}
