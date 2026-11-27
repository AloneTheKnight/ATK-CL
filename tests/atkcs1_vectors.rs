#[test]
fn vector_block_boundary_lengths() {
    use atk_cl::core::cipher::StreamCipher;
    use atk_cl::core::cipher::constants::{KEY_SIZE, NONCE_SIZE};

    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let lengths = [63, 64, 65, 127, 128];

    for length in lengths {
        let plaintext = vec![0x41; length];

        let mut encryptor = StreamCipher::from_key_nonce(&key, &nonce).unwrap();

        let ciphertext = encryptor.process(&plaintext).unwrap();

        assert_eq!(
            ciphertext.len(),
            length,
            "Incorrect ciphertext length for input of {} bytes",
            length
        );

        let mut decryptor = StreamCipher::from_key_nonce(&key, &nonce).unwrap();

        let decrypted = decryptor.process(&ciphertext).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Roundtrip failed for input of {} bytes",
            length
        );
    }
}
