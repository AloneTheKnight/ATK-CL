use atk_cl::core::cipher::StreamCipher;
use atk_cl::core::integrity::{compute_tag, verify_tag};

const CIPHER_KEY: [u8; 32] = [0x42; 32];
const INTEGRITY_KEY: [u8; 32] = [0x24; 32];
const NONCE: [u8; 16] = [0x11; 16];

const PLAINTEXT: &[u8] = b"ATK-CL: cipher and integrity KAT";

const EXPECTED_CIPHERTEXT: [u8; 32] = [
    0x4d, 0xf6, 0x8c, 0x84, 0x4f, 0xee, 0xfd, 0x89, 0x6f, 0xcb, 0xb7, 0xc1, 0x69, 0xd0, 0xe7, 0xc8,
    0xa5, 0x28, 0xaa, 0x81, 0xa5, 0x38, 0xef, 0x8f, 0xb9, 0x25, 0xfe, 0x91, 0xeb, 0x07, 0xcb, 0xbc,
];

const EXPECTED_TAG: [u8; 32] = [
    0x94, 0x91, 0xf9, 0x1c, 0x4d, 0x99, 0x70, 0xe5, 0xc2, 0x78, 0x27, 0x8e, 0x85, 0x88, 0x54, 0x85,
    0xe8, 0x90, 0xae, 0xf5, 0x15, 0xb3, 0x2d, 0x88, 0xf2, 0x1a, 0x4c, 0x96, 0x57, 0xdb, 0x94, 0xbb,
];

#[test]
fn atk_crypto_primitives_known_answer_001() {
    let mut cipher = StreamCipher::from_key_nonce(&CIPHER_KEY, &NONCE).unwrap();

    let ciphertext = cipher.process(PLAINTEXT).unwrap();

    assert_eq!(ciphertext.as_slice(), EXPECTED_CIPHERTEXT);

    let tag = compute_tag(&INTEGRITY_KEY, &NONCE, &ciphertext).unwrap();

    assert_eq!(tag, EXPECTED_TAG);

    assert!(verify_tag(&INTEGRITY_KEY, &NONCE, &ciphertext, &EXPECTED_TAG).unwrap());

    let mut decryptor = StreamCipher::from_key_nonce(&CIPHER_KEY, &NONCE).unwrap();

    let decrypted = decryptor.process(&ciphertext).unwrap();

    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn atk_crypto_primitives_modified_ciphertext_is_rejected() {
    let mut cipher = StreamCipher::from_key_nonce(&CIPHER_KEY, &NONCE).unwrap();

    let mut ciphertext = cipher.process(PLAINTEXT).unwrap();

    let tag = compute_tag(&INTEGRITY_KEY, &NONCE, &ciphertext).unwrap();

    ciphertext[0] ^= 0x01;

    assert!(!verify_tag(&INTEGRITY_KEY, &NONCE, &ciphertext, &tag).unwrap());
}
