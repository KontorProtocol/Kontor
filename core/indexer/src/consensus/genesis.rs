use crate::consensus::ValidatorSet;

#[derive(Clone, Debug)]
pub struct Genesis {
    pub validator_set: ValidatorSet,
}
