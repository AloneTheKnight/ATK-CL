use atk_cl::core::crypto::{decrypt, encrypt};
use atk_cl::core::key::password::Password;
use atk_cl::format::container::Container;

#[test]
fn encryption_and_decryption_round_trip() {
    let password = Password::new(b"test-password".to_vec()).unwrap();
    let plaintext = b"ATK-CL integration test";

    let container = encrypt(plaintext, &password).unwrap();
    let decrypted = decrypt(&container, &password).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_password_is_rejected() {
    let password = Password::new(b"correct-password".to_vec()).unwrap();
    let wrong_password = Password::new(b"wrong-password".to_vec()).unwrap();

    let container = encrypt(b"Secret message", &password).unwrap();

    assert!(decrypt(&container, &wrong_password).is_err());
}

#[test]
fn modified_ciphertext_is_rejected() {
    let password = Password::new(b"test-password".to_vec()).unwrap();

    let mut container = encrypt(b"Integrity test", &password).unwrap();
    container.payload[0] ^= 0x01;

    assert!(decrypt(&container, &password).is_err());
}

#[test]
fn empty_data_can_be_encrypted_and_decrypted() {
    let password = Password::new(b"test-password".to_vec()).unwrap();

    let container = encrypt(b"", &password).unwrap();
    let decrypted = decrypt(&container, &password).unwrap();

    assert!(decrypted.is_empty());
}

#[test]
fn encoded_container_can_be_decoded_and_decrypted() {
    let password = Password::new(b"test-password".to_vec()).unwrap();

    let container = encrypt(b"Serialization test", &password).unwrap();
    let encoded = container.encode().unwrap();
    let decoded = Container::decode(&encoded).unwrap();

    let decrypted = decrypt(&decoded, &password).unwrap();

    assert_eq!(decrypted, b"Serialization test");
}
