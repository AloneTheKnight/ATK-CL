use atk_cl::core::cipher::state::{CipherState, STATE_WORDS};
use atk_cl::core::cipher::transform::apply_arx;

#[test]
fn transformation_changes_nonzero_state() {
    let mut state = CipherState::new([1; STATE_WORDS]);

    assert!(apply_arx(&mut state, 0, 1, 2, 3));
    assert_ne!(state, CipherState::new([1; STATE_WORDS]));
}

#[test]
fn transformation_rejects_invalid_index() {
    let mut state = CipherState::new([1; STATE_WORDS]);
    let original = state.to_bytes_le();

    assert!(!apply_arx(&mut state, 0, 1, 2, 16));
    assert_eq!(state.to_bytes_le(), original);
}

#[test]
fn transformation_is_deterministic() {
    let mut first = CipherState::new([0x12345678; STATE_WORDS]);
    let mut second = CipherState::new([0x12345678; STATE_WORDS]);

    assert!(apply_arx(&mut first, 0, 1, 2, 3));
    assert!(apply_arx(&mut second, 0, 1, 2, 3));

    assert_eq!(first, second);
}

#[test]
fn transformation_preserves_state_access() {
    let mut state = CipherState::zeroed();

    assert!(apply_arx(&mut state, 0, 1, 2, 3));

    for index in 0..STATE_WORDS {
        assert!(state.get(index).is_some());
    }
}
