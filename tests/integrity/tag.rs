use atk_cl::core::integrity::constants::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use atk_cl::core::integrity::tag::{compute_tag, verify_tag};

#[test]
fn tag_has_expected_size() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let tag = compute_tag(&key, &nonce, b"ATK-INT-1 test").unwrap();

    assert_eq!(tag.len(), TAG_SIZE);
}

#[test]
fn same_input_produces_same_tag() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    let data = b"ATK-INT-1 deterministic test";

    let first = compute_tag(&key, &nonce, data).unwrap();
    let second = compute_tag(&key, &nonce, data).unwrap();

    assert_eq!(first, second);
}

#[test]
fn changed_data_changes_tag() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let first = compute_tag(&key, &nonce, b"message A").unwrap();
    let second = compute_tag(&key, &nonce, b"message B").unwrap();

    assert_ne!(first, second);
}

#[test]
fn valid_tag_is_accepted() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    let data = b"integrity test";

    let tag = compute_tag(&key, &nonce, data).unwrap();

    assert!(verify_tag(&key, &nonce, data, &tag).unwrap());
}

#[test]
fn modified_data_is_rejected() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let tag = compute_tag(&key, &nonce, b"original").unwrap();

    assert!(!verify_tag(&key, &nonce, b"modified", &tag).unwrap());
}

#[test]
fn empty_data_is_supported() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    let tag = compute_tag(&key, &nonce, b"").unwrap();

    assert_eq!(tag.len(), TAG_SIZE);
}

#[test]
fn atk_int1_kat_001() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    let data = b"ATK-INT-1 known answer test";

    let expected = [
        0xCA, 0x9A, 0x52, 0xFE, 0x52, 0x48, 0x8B, 0x0E, 0x1A, 0xD4, 0x8A, 0xF4, 0xF5, 0xB5, 0x9C,
        0x9E, 0x1C, 0x1C, 0x45, 0x5D, 0xC0, 0x02, 0x69, 0x51, 0xBA, 0x05, 0xFF, 0x41, 0x98, 0x05,
        0x04, 0x31,
    ];

    let actual = compute_tag(&key, &nonce, data).unwrap();

    assert_eq!(actual, expected);
}
