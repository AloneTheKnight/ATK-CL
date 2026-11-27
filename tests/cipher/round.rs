use atk_cl::core::cipher::round::{DEFAULT_ROUNDS, RoundError, apply_rounds};
use atk_cl::core::cipher::state::{CipherState, STATE_WORDS};

#[test]
fn rounds_change_nonzero_state() {
    let mut state = CipherState::new([1; STATE_WORDS]);

    assert_eq!(apply_rounds(&mut state, 1), Ok(()));
    assert_ne!(state, CipherState::new([1; STATE_WORDS]));
}

#[test]
fn zero_rounds_are_rejected() {
    let mut state = CipherState::zeroed();

    assert_eq!(apply_rounds(&mut state, 0), Err(RoundError::ZeroRounds));
}

#[test]
fn rounds_are_deterministic() {
    let mut first = CipherState::new([0x12345678; STATE_WORDS]);
    let mut second = CipherState::new([0x12345678; STATE_WORDS]);

    apply_rounds(&mut first, 10).unwrap();
    apply_rounds(&mut second, 10).unwrap();

    assert_eq!(first, second);
}

#[test]
fn default_round_count_is_defined() {
    assert_eq!(DEFAULT_ROUNDS, 10);
}
