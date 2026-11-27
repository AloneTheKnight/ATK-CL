use atk_cl::core::cipher::state::{CipherState, STATE_SIZE, STATE_WORDS};

#[test]
fn state_has_expected_size() {
    assert_eq!(STATE_SIZE, 64);
}

#[test]
fn state_preserves_words() {
    let words = [0x12345678; STATE_WORDS];
    let state = CipherState::new(words);

    for (index, expected) in words.iter().enumerate() {
        assert_eq!(state.get(index), Some(*expected));
    }
}

#[test]
fn state_contains_sixteen_words() {
    let state = CipherState::zeroed();

    for index in 0..STATE_WORDS {
        assert_eq!(state.get(index), Some(0));
    }
}

#[test]
fn state_get_returns_word() {
    let state = CipherState::new([0x12345678; STATE_WORDS]);
    assert_eq!(state.get(0), Some(0x12345678));
}

#[test]
fn state_get_rejects_invalid_index() {
    let state = CipherState::zeroed();
    assert_eq!(state.get(16), None);
}

#[test]
fn state_set_updates_word() {
    let mut state = CipherState::zeroed();

    assert!(state.set(3, 0xAABBCCDD));
    assert_eq!(state.get(3), Some(0xAABBCCDD));
}

#[test]
fn state_set_rejects_invalid_index() {
    let mut state = CipherState::zeroed();
    assert!(!state.set(16, 123));
}

#[test]
fn state_serialization_roundtrip() {
    let original = CipherState::new([
        0x12345678, 0xAABBCCDD, 0x01020304, 0xFFFFFFFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ]);

    let bytes = original.to_bytes_le();
    let restored = CipherState::from_bytes_le(&bytes);

    assert_eq!(original, restored);
}

#[test]
fn zeroed_state_contains_only_zeroes() {
    let state = CipherState::zeroed();

    for index in 0..STATE_WORDS {
        assert_eq!(state.get(index), Some(0));
    }
}
