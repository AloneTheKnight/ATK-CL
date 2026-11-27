use atk_cl::core::cipher::constants::{KEY_SIZE, NONCE_SIZE};
use atk_cl::core::cipher::state::{CipherState, STATE_WORDS};
use atk_cl::core::cipher::stream::{StreamCipher, StreamCipherError};

fn test_state() -> CipherState {
    CipherState::new([0x12345678; STATE_WORDS])
}

#[test]
fn new_cipher_starts_at_position_zero() {
    let cipher = StreamCipher::new(test_state());
    assert_eq!(cipher.position(), 0);
}

#[test]
fn cipher_preserves_initial_state_behavior() {
    let input = b"ATK-CL state preservation";

    let mut first = StreamCipher::new(test_state());
    let mut second = StreamCipher::new(test_state());

    assert_eq!(
        first.process(input).unwrap(),
        second.process(input).unwrap()
    );
}

#[test]
fn processing_updates_position() {
    let mut cipher = StreamCipher::new(test_state());
    let input = b"Hello, ATK-CL!";

    cipher.process(input).unwrap();

    assert_eq!(cipher.position(), input.len());
}

#[test]
fn processing_empty_input_changes_nothing() {
    let mut cipher = StreamCipher::new(test_state());
    let output = cipher.process(b"").unwrap();

    assert!(output.is_empty());
    assert_eq!(cipher.position(), 0);
}

#[test]
fn processing_same_data_twice_restores_original() {
    let input = b"ATK-CL stream test";

    let mut encryptor = StreamCipher::new(test_state());
    let encrypted = encryptor.process(input).unwrap();

    let mut decryptor = StreamCipher::new(test_state());
    let decrypted = decryptor.process(&encrypted).unwrap();

    assert_eq!(decrypted, input);
}

#[test]
fn processing_in_chunks_matches_single_processing() {
    let input = vec![0x42; 150];

    let mut whole_cipher = StreamCipher::new(test_state());
    let whole_output = whole_cipher.process(&input).unwrap();

    let mut chunk_cipher = StreamCipher::new(test_state());
    let mut chunk_output = Vec::new();

    for chunk in input.chunks(13) {
        chunk_output.extend(chunk_cipher.process(chunk).unwrap());
    }

    assert_eq!(whole_output, chunk_output);
}

#[test]
fn position_tracks_multiple_calls() {
    let mut cipher = StreamCipher::new(test_state());

    cipher.process(b"Hello").unwrap();
    cipher.process(b" world").unwrap();

    assert_eq!(cipher.position(), 11);
}

#[test]
fn from_key_nonce_creates_cipher() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    assert!(StreamCipher::from_key_nonce(&key, &nonce).is_ok());
}

#[test]
fn from_key_nonce_rejects_invalid_key() {
    let key = [0x11; 16];
    let nonce = [0x22; NONCE_SIZE];

    assert!(matches!(
        StreamCipher::from_key_nonce(&key, &nonce),
        Err(StreamCipherError::InvalidInitialization)
    ));
}

#[test]
fn from_key_nonce_supports_encryption_and_decryption() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    let input = b"ATK-CL integration test";

    let mut encryptor = StreamCipher::from_key_nonce(&key, &nonce).unwrap();
    let encrypted = encryptor.process(input).unwrap();

    let mut decryptor = StreamCipher::from_key_nonce(&key, &nonce).unwrap();
    let decrypted = decryptor.process(&encrypted).unwrap();

    assert_eq!(decrypted, input);
}
