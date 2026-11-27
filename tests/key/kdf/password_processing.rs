use atk_cl::core::key::kdf::password_processing::process_password;

#[test]
fn preserves_password_bytes() {
    let password = b"ATK-CL password";

    assert_eq!(&*process_password(password), password);
}

#[test]
fn supports_binary_password() {
    let password = [0x00, 0xFF, 0x80, 0x41];

    assert_eq!(process_password(&password).as_slice(), &password[..]);
}

#[test]
fn supports_empty_input() {
    assert!(process_password(&[]).is_empty());
}
