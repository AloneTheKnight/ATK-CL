use atk_cl::core::key::kdf::salt_processing::process_salt;
use atk_cl::core::key::salt::{SALT_SIZE, Salt};

#[test]
fn preserves_salt_bytes() {
    let bytes = [42u8; SALT_SIZE];
    let salt = Salt::from_bytes(bytes);

    assert_eq!(&process_salt(&salt)[..], &bytes[..]);
}
