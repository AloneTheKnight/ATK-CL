use atk_cl::core::key::salt::{SALT_SIZE, Salt};

#[test]
fn salt_has_expected_size() {
    let salt = Salt::generate().unwrap();

    assert_eq!(salt.as_bytes().len(), SALT_SIZE);
}

#[test]
fn salt_from_bytes_preserves_data() {
    let bytes = [42u8; SALT_SIZE];
    let salt = Salt::from_bytes(bytes);

    assert_eq!(salt.as_bytes(), &bytes);
}
