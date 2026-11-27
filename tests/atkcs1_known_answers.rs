use atk_cl::core::cipher::StreamCipher;
use atk_cl::core::cipher::constants::{KEY_SIZE, NONCE_SIZE};

fn encrypt_to_hex(plaintext: &[u8]) -> String {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let mut cipher = StreamCipher::from_key_nonce(&key, &nonce).unwrap();

    let ciphertext = cipher.process(plaintext).unwrap();

    ciphertext
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect()
}

#[test]
fn kat_initial_vector() {
    let plaintext = b"ATK-SC-1 known answer test";

    assert_eq!(
        encrypt_to_hex(plaintext),
        "9040B1798257D765F17F943BA67ADA355494D23148C7D1314993"
    );
}

#[test]
fn kat_empty_input() {
    assert_eq!(encrypt_to_hex(b""), "");
}

#[test]
fn kat_single_byte() {
    assert_eq!(encrypt_to_hex(&[0x41]), "90");
}

#[test]
fn kat_full_block() {
    let plaintext = [0x41; 64];

    assert_eq!(
        encrypt_to_hex(&plaintext),
        "9055BB159055BB159055BB159055BB157BA6E4157BA6E4157BA6E4157BA6E415840F86FF840F86FF840F86FF840F86FF56A94ED856A94ED856A94ED856A94ED8"
    );
}
