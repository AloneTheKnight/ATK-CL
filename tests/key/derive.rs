use atk_cl::core::key::derive::derive_key;
use atk_cl::core::key::password::Password;
use atk_cl::core::key::salt::Salt;

#[test]
fn same_password_and_salt_produce_same_key() {
    let password = Password::new(b"test-password".to_vec()).unwrap();
    let salt = Salt::from_bytes([0x42; 16]);

    let first = derive_key(&password, &salt).unwrap();
    let second = derive_key(&password, &salt).unwrap();

    assert_eq!(first.as_bytes(), second.as_bytes());
}

#[test]
fn different_salts_produce_different_keys() {
    let password = Password::new(b"test-password".to_vec()).unwrap();

    let salt_a = Salt::from_bytes([0x11; 16]);
    let salt_b = Salt::from_bytes([0x22; 16]);

    let key_a = derive_key(&password, &salt_a).unwrap();
    let key_b = derive_key(&password, &salt_b).unwrap();

    assert_ne!(key_a.as_bytes(), key_b.as_bytes());
}

#[test]
fn different_passwords_produce_different_keys() {
    let password_a = Password::new(b"password-a".to_vec()).unwrap();
    let password_b = Password::new(b"password-b".to_vec()).unwrap();
    let salt = Salt::from_bytes([0x42; 16]);

    let key_a = derive_key(&password_a, &salt).unwrap();
    let key_b = derive_key(&password_b, &salt).unwrap();

    assert_ne!(key_a.as_bytes(), key_b.as_bytes());
}

#[test]
fn derived_key_has_expected_size() {
    let password = Password::new(b"test".to_vec()).unwrap();
    let salt = Salt::from_bytes([0x42; 16]);

    let key = derive_key(&password, &salt).unwrap();

    assert_eq!(key.as_bytes().len(), 32);
}

#[test]
fn atk_kdf1_kat_001() {
    let password = Password::new(b"ATK-KDF-1 KAT".to_vec()).unwrap();
    let salt = Salt::from_bytes([0x11; 16]);

    let key = derive_key(&password, &salt).unwrap();

    let expected: [u8; 32] = [
        0x7F, 0x6E, 0xA2, 0x1B, 0x52, 0x05, 0x7C, 0x16, 0x05, 0xBB, 0xED, 0xBF, 0xCC, 0xC3, 0xBC,
        0xE4, 0x30, 0x9C, 0x7A, 0x96, 0x2A, 0x63, 0xA4, 0x3E, 0xE6, 0x4F, 0x3D, 0xA5, 0x7C, 0xCF,
        0x3B, 0xF2,
    ];

    assert_eq!(key.as_bytes(), &expected);
}
