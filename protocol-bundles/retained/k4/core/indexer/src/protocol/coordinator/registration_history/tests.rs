use super::*;
use crate::consensus::signing::PrivateKey;
use crate::protocol::coordinator::certified_decision::tests::fixture;

fn observation() -> RegistrationObservation {
    let (authority, _, _, _) = fixture();
    let committee = authority
        .members
        .iter()
        .map(|member| (member.address, member.key, member.power))
        .collect();
    let mut entries: Vec<_> = authority
        .members
        .iter()
        .map(|member| (member.holder.clone(), Some((member.key.to_vec(), 1, 10, 0))))
        .collect();
    entries.sort();
    (committee, entries)
}

fn genesis() -> Result<RegistrationSnapshot> {
    let (authority, _, _, _) = fixture();
    RegistrationSnapshot::observe(
        None,
        ObservationPosition {
            context: authority.context,
            height: 0,
            decision: [3; 32],
            stage: 0,
            lineage: [4; 32],
        },
        observation(),
    )
}

fn next(
    previous: &RegistrationSnapshot,
    observed: RegistrationObservation,
) -> Result<RegistrationSnapshot> {
    let mut position = previous.position;
    if position.height == 0 {
        position.height = 1;
        position.decision = [5; 32];
    }
    position.stage += 1;
    RegistrationSnapshot::observe(Some(previous), position, observed)
}

#[test]
fn generations_survive_power_changes_and_other_membership_churn() -> Result<()> {
    let initial = genesis()?;
    let mut observed = observation();
    observed.0.reverse();
    observed.0[0].2 += 1;
    let changed = next(&initial, observed)?;
    assert_eq!(initial.entries, changed.entries);
    assert_eq!(
        changed.authority()?.members[0].key,
        initial.committee.last().unwrap().1
    );
    let mut exit = observation();
    exit.1[0].1.as_mut().unwrap().1 = 3;
    exit.1[0].1.as_mut().unwrap().3 = 50;
    let exiting = next(&changed, exit)?;
    assert_eq!(exiting.entries[0].generation, initial.entries[0].generation);
    let restored = next(&exiting, observation())?;
    assert_eq!(restored.entries, initial.entries);
    Ok(())
}

#[test]
fn intermediate_exit_and_same_height_rejoin_change_only_that_generation() -> Result<()> {
    let initial = genesis()?;
    let mut exited = observation();
    let key = exited.1[0].1.as_ref().unwrap().0.clone();
    exited.1[0].1 = None;
    exited.0.retain(|member| member.1.as_slice() != key);
    let after_rollback = next(&initial, exited)?;
    assert!(after_rollback.entries[0].generation.is_none());
    let replayed = next(&after_rollback, observation())?;
    assert_eq!(replayed.entries[0].value, initial.entries[0].value);
    assert_ne!(
        replayed.entries[0].generation,
        initial.entries[0].generation
    );
    assert_eq!(replayed.entries[1..], initial.entries[1..]);
    assert_eq!(
        RegistrationSnapshot::decode(&after_rollback.encode()?)?,
        after_rollback
    );
    replayed.verify_successor(Some(&after_rollback))?;
    let mut forged = replayed.clone();
    forged.entries[0].generation = initial.entries[0].generation;
    assert!(forged.verify_successor(Some(&after_rollback)).is_err());
    Ok(())
}

#[test]
fn replacement_activation_and_key_cannot_reuse_consent() -> Result<()> {
    let initial = genesis()?;
    let mut observed = observation();
    observed.1[0].1.as_mut().unwrap().2 += 1;
    assert_ne!(
        next(&initial, observed)?.entries[0].generation,
        initial.entries[0].generation
    );
    let mut observed = observation();
    let old = observed.1[0].1.as_ref().unwrap().0.clone();
    let public = PrivateKey::from([79; 32]).public_key();
    observed.1[0].1.as_mut().unwrap().0 = public.as_bytes().to_vec();
    let member = observed
        .0
        .iter_mut()
        .find(|member| member.1.as_slice() == old)
        .unwrap();
    member.0 = Address::from_public_key(&public).into_inner();
    member.1 = *public.as_bytes();
    assert_ne!(
        next(&initial, observed)?.entries[0].generation,
        initial.entries[0].generation
    );
    Ok(())
}

#[test]
fn zero_authority_is_observable_but_cannot_start_next_height() -> Result<()> {
    let initial = genesis()?;
    let mut observed = observation();
    observed.0.clear();
    for (_, value) in &mut observed.1 {
        value.as_mut().unwrap().1 = 0;
    }
    observed
        .1
        .push(("stake-only".into(), Some((vec![], 0, 0, 0))));
    observed.1.sort();
    let empty = next(&initial, observed)?;
    assert!(empty.entries.iter().all(|entry| entry.generation.is_none()));
    assert!(empty.authority().is_err());
    empty.verify_successor(Some(&initial))?;
    Ok(())
}

#[test]
fn malformed_observations_and_position_gaps_are_rejected() -> Result<()> {
    let initial = genesis()?;
    for mutate in 0..5 {
        let mut observed = observation();
        match mutate {
            0 => {
                observed.1.remove(0);
            }
            1 => observed.1.swap(0, 1),
            2 => observed.0.push(observed.0[0]),
            3 => observed.1[0].1.as_mut().unwrap().1 = 9,
            _ => observed.0[0].0 = [0; 20],
        }
        assert!(next(&initial, observed).is_err());
    }
    let mut position = initial.position;
    position.height = 2;
    position.stage = 1;
    assert!(RegistrationSnapshot::observe(Some(&initial), position, observation()).is_err());
    let bytes = initial.encode()?;
    for length in 0..bytes.len() {
        assert!(RegistrationSnapshot::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RegistrationSnapshot::decode(&trailing).is_err());
    assert_eq!(RegistrationSnapshot::decode(&bytes)?, initial);
    initial.verify_successor(None)?;
    Ok(())
}
