use atk_cl::core::cipher::permutation::apply_permutation;
use atk_cl::core::cipher::state::{CipherState, STATE_WORDS};

#[test]
fn permutation_changes_nonzero_state() {
    let mut state = CipherState::new([1; STATE_WORDS]);

    assert!(apply_permutation(&mut state));
    assert_ne!(state, CipherState::new([1; STATE_WORDS]));
}

#[test]
fn permutation_is_deterministic() {
    let mut first = CipherState::new([0x12345678; STATE_WORDS]);
    let mut second = CipherState::new([0x12345678; STATE_WORDS]);

    apply_permutation(&mut first);
    apply_permutation(&mut second);

    assert_eq!(first, second);
}

#[test]
fn permutation_preserves_state_size() {
    let mut state = CipherState::zeroed();

    assert!(apply_permutation(&mut state));

    for index in 0..STATE_WORDS {
        assert!(state.get(index).is_some());
    }
}

#[test]
fn permutation_handles_zero_state() {
    let mut state = CipherState::zeroed();
    assert!(apply_permutation(&mut state));
}

#[test]
fn repeated_permutations_are_deterministic() {
    let mut first = CipherState::new([0x12345678; STATE_WORDS]);
    let mut second = CipherState::new([0x12345678; STATE_WORDS]);

    for _ in 0..2 {
        assert!(apply_permutation(&mut first));
        assert!(apply_permutation(&mut second));
    }

    assert_eq!(first, second);
}

#[test]
fn permutation_changes_state_on_second_application() {
    let mut state = CipherState::new([0x12345678; STATE_WORDS]);

    assert!(apply_permutation(&mut state));

    let mut expected = CipherState::new([0x12345678; STATE_WORDS]);
    assert!(apply_permutation(&mut expected));

    assert!(apply_permutation(&mut state));
    assert_ne!(state, expected);
}
