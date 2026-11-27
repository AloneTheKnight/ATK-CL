use atk_cl::core::key::password::Password;

#[test]
fn empty_password_is_rejected() {
    assert!(Password::new(Vec::new()).is_err());
}

#[test]
fn non_empty_password_is_accepted() {
    let password = Password::new(b"test-password".to_vec());
    assert!(password.is_ok());
}

#[test]
fn binary_password_is_accepted() {
    let password =
        Password::new(vec![0x00, 0xFF, 0x80, 0x41]).expect("Binary password should be accepted");

    assert_eq!(password.as_bytes(), &[0x00, 0xFF, 0x80, 0x41]);
}

#[test]
fn password_bytes_are_preserved() {
    let input = b"ATK-CL password".to_vec();
    let password = Password::new(input.clone()).unwrap();

    assert_eq!(password.as_bytes(), input.as_slice());
}
