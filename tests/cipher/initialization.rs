use atk_cl::core::cipher::constants::{KEY_SIZE, NONCE_SIZE};
use atk_cl::core::cipher::initialization::{InitializationError, initialize_state};

#[test]
fn valid_key_and_nonce_initialize_state() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    assert!(initialize_state(&key, &nonce).is_ok());
}

#[test]
fn incorrect_key_length_is_rejected() {
    let key = [0x11; KEY_SIZE - 1];
    let nonce = [0x22; NONCE_SIZE];

    assert_eq!(
        initialize_state(&key, &nonce),
        Err(InitializationError::InvalidKeyLength)
    );
}

#[test]
fn incorrect_nonce_length_is_rejected() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE - 1];

    assert_eq!(
        initialize_state(&key, &nonce),
        Err(InitializationError::InvalidNonceLength)
    );
}

#[test]
fn initialization_is_deterministic() {
    let key = [0xAB; KEY_SIZE];
    let nonce = [0xCD; NONCE_SIZE];

    assert_eq!(
        initialize_state(&key, &nonce).unwrap(),
        initialize_state(&key, &nonce).unwrap()
    );
}

#[test]
fn different_nonces_produce_different_states() {
    let key = [0x11; KEY_SIZE];
    let nonce_a = [0x22; NONCE_SIZE];
    let nonce_b = [0x33; NONCE_SIZE];

    assert_ne!(
        initialize_state(&key, &nonce_a).unwrap(),
        initialize_state(&key, &nonce_b).unwrap()
    );
}

#[test]
fn key_and_nonce_are_mapped_in_little_endian_order() {
    let mut key = [0u8; KEY_SIZE];
    key[0] = 0x78;
    key[1] = 0x56;
    key[2] = 0x34;
    key[3] = 0x12;

    let nonce = [0u8; NONCE_SIZE];
    let state = initialize_state(&key, &nonce).unwrap();

    assert_eq!(state.get(0), Some(0x12345678));
}
