use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValidatorStart {
    #[default]
    Resume,
    Bootstrap,
    Join {
        minimum_closed_height: NonZeroU64,
    },
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(any(kontor_managed, test))]
pub(super) struct RecoveryState {
    pub retained_signer: bool,
    pub highest_signed_height: Option<u64>,
    pub authorization_height: Option<u64>,
    pub wal_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(kontor_managed, test))]
pub(super) enum StartRole {
    Validator,
    Follower { promotion_floor: Option<u64> },
}

#[cfg(any(kontor_managed, test))]
impl ValidatorStart {
    // These are summaries of validated durable records, not peer-advertised tips.
    pub(super) fn select(
        self,
        closed_height: u64,
        member: bool,
        retained: RecoveryState,
    ) -> Result<StartRole, &'static str> {
        let next = closed_height
            .checked_add(1)
            .ok_or("consensus height exhausted")?;
        if !retained.retained_signer
            && (retained.highest_signed_height.is_some()
                || retained.authorization_height.is_some()
                || retained.wal_height.is_some_and(|height| height > 0))
        {
            return Err("validator WAL or signing history exists without its retained signer");
        }
        let signed = retained.highest_signed_height.unwrap_or(0);
        let authorized = retained.authorization_height.unwrap_or(0);
        let wal = retained.wal_height.unwrap_or(0);
        match self {
            Self::Bootstrap => {
                if closed_height != 0 || retained.retained_signer || wal != 0 {
                    return Err(
                        "bootstrap requires initial genesis without retained validator state; use resume or join",
                    );
                }
                if !member {
                    return Err("bootstrap key is not in the genesis committee");
                }
                Ok(StartRole::Validator)
            }
            Self::Resume => {
                if !retained.retained_signer {
                    return Err(
                        "resume requires retained validator state; explicitly bootstrap genesis or join verified history",
                    );
                }
                if signed > next || authorized > next || wal > next {
                    return Err(
                        "validator state is ahead of completed history; join to reconstruct before signing",
                    );
                }
                // Recreating an unfinished signed WAL loses round/lock state even
                // when the signer still refuses conflicting individual signatures.
                if signed == next && retained.wal_height != Some(next) {
                    return Err(
                        "unfinished signed height lacks its WAL; join through that height before signing",
                    );
                }
                Ok(if member {
                    StartRole::Validator
                } else {
                    StartRole::Follower {
                        promotion_floor: None,
                    }
                })
            }
            Self::Join {
                minimum_closed_height,
            } => {
                let floor = minimum_closed_height
                    .get()
                    .max(signed)
                    .max(wal)
                    .max(authorized.saturating_sub(1));
                Ok(if closed_height >= floor && member {
                    StartRole::Validator
                } else {
                    StartRole::Follower {
                        promotion_floor: Some(floor),
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RecoveryState, StartRole, ValidatorStart};
    use std::num::NonZeroU64;

    fn retained(signed: Option<u64>, authorization: u64, wal: Option<u64>) -> RecoveryState {
        RecoveryState {
            retained_signer: true,
            highest_signed_height: signed,
            authorization_height: Some(authorization),
            wal_height: wal,
        }
    }

    fn join(floor: u64) -> ValidatorStart {
        ValidatorStart::Join {
            minimum_closed_height: NonZeroU64::new(floor).unwrap(),
        }
    }

    #[test]
    fn genesis_requires_explicit_bootstrap_and_membership() {
        let fresh = RecoveryState::default();
        assert!(ValidatorStart::Resume.select(0, true, fresh).is_err());
        assert_eq!(
            ValidatorStart::Bootstrap.select(0, true, fresh),
            Ok(StartRole::Validator)
        );
        assert!(ValidatorStart::Bootstrap.select(0, false, fresh).is_err());
        assert!(ValidatorStart::Bootstrap.select(1, true, fresh).is_err());
        assert!(
            ValidatorStart::Bootstrap
                .select(0, true, retained(None, 1, None))
                .is_err()
        );
    }

    #[test]
    fn all_validators_can_resume_the_same_unfinished_height() {
        for signed in [None, Some(7)] {
            assert_eq!(
                ValidatorStart::Resume.select(6, true, retained(signed, 7, Some(7))),
                Ok(StartRole::Validator)
            );
        }
    }

    #[test]
    fn authorization_before_wal_crash_does_not_require_a_new_decision() {
        assert_eq!(
            ValidatorStart::Resume.select(6, true, retained(Some(6), 7, None)),
            Ok(StartRole::Validator)
        );
        assert_eq!(
            ValidatorStart::Resume.select(0, true, retained(None, 1, None)),
            Ok(StartRole::Validator)
        );
    }

    #[test]
    fn signed_height_requires_matching_wal_until_closed() {
        for wal in [None, Some(5), Some(6)] {
            assert!(
                ValidatorStart::Resume
                    .select(6, true, retained(Some(7), 7, wal))
                    .is_err()
            );
            assert_eq!(
                join(1).select(6, true, retained(Some(7), 7, wal)),
                Ok(StartRole::Follower {
                    promotion_floor: Some(7)
                })
            );
            assert_eq!(
                join(1).select(7, true, retained(Some(7), 7, wal)),
                Ok(StartRole::Validator)
            );
        }
    }

    #[test]
    fn ahead_state_never_resets_backwards() {
        for state in [
            retained(Some(8), 8, Some(8)),
            retained(None, 9, None),
            retained(None, 7, Some(8)),
        ] {
            assert!(ValidatorStart::Resume.select(6, true, state).is_err());
            assert_eq!(
                join(1).select(7, true, state),
                Ok(StartRole::Follower {
                    promotion_floor: Some(8)
                })
            );
            assert_eq!(join(1).select(8, true, state), Ok(StartRole::Validator));
        }
    }

    #[test]
    fn join_requires_both_verified_progress_and_next_committee_membership() {
        let state = retained(Some(5), 7, Some(8));
        assert_eq!(
            join(9).select(8, true, state),
            Ok(StartRole::Follower {
                promotion_floor: Some(9)
            })
        );
        assert_eq!(
            join(9).select(9, false, state),
            Ok(StartRole::Follower {
                promotion_floor: Some(9)
            })
        );
        assert_eq!(join(9).select(9, true, state), Ok(StartRole::Validator));
        assert_eq!(
            join(1).select(0, true, RecoveryState::default()),
            Ok(StartRole::Follower {
                promotion_floor: Some(1)
            })
        );
    }

    #[test]
    fn completed_history_allows_forward_wal_reset_but_never_height_overflow() {
        let state = retained(Some(5), 5, Some(5));
        assert_eq!(
            ValidatorStart::Resume.select(8, true, state),
            Ok(StartRole::Validator)
        );
        assert!(
            ValidatorStart::Resume
                .select(u64::MAX, true, state)
                .is_err()
        );
        assert!(join(1).select(u64::MAX, true, state).is_err());
    }

    #[test]
    fn absent_signer_with_validator_wal_is_not_fresh_state() {
        let state = RecoveryState {
            wal_height: Some(3),
            ..RecoveryState::default()
        };
        assert!(join(1).select(4, true, state).is_err());
    }
}
