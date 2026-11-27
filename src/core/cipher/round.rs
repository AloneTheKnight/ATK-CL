use super::permutation::apply_permutation;
use super::state::CipherState;

pub const DEFAULT_ROUNDS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundError {
    ZeroRounds,
    PermutationFailure,
}

pub fn apply_rounds(state: &mut CipherState, rounds: usize) -> Result<(), RoundError> {
    if rounds == 0 {
        return Err(RoundError::ZeroRounds);
    }

    for _ in 0..rounds {
        if !apply_permutation(state) {
            return Err(RoundError::PermutationFailure);
        }
    }

    Ok(())
}
