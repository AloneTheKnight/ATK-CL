use atk_cl::format::constants::{MAX_ID_LENGTH, MAX_PAYLOAD_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use atk_cl::format::container::{Container, FormatError};

fn sample_container() -> Container {
    Container::new(
        "ATK-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0x22; NONCE_SIZE],
        vec![0x10, 0x20, 0x30, 0x40],
        vec![0xCC; TAG_SIZE],
    )
    .unwrap()
}

#[test]
fn container_round_trip_works() {
    let original = sample_container();
    let encoded = original.encode().unwrap();
    let decoded = Container::decode(&encoded).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn invalid_magic_is_rejected() {
    let mut encoded = sample_container().encode().unwrap();
    encoded[0] = 0;

    assert_eq!(Container::decode(&encoded), Err(FormatError::InvalidMagic));
}

#[test]
fn truncated_header_is_rejected() {
    let encoded = vec![0; 10];

    assert_eq!(Container::decode(&encoded), Err(FormatError::TruncatedData));
}

#[test]
fn truncated_data_is_rejected() {
    let mut encoded = sample_container().encode().unwrap();
    encoded.pop();

    assert_eq!(Container::decode(&encoded), Err(FormatError::TruncatedData));
}

#[test]
fn trailing_data_is_rejected() {
    let mut encoded = sample_container().encode().unwrap();
    encoded.push(0xFF);

    assert_eq!(Container::decode(&encoded), Err(FormatError::TrailingData));
}

#[test]
fn invalid_salt_length_is_rejected_by_constructor() {
    let result = Container::new(
        "ATK-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0; 8],
        vec![0x22; NONCE_SIZE],
        vec![],
        vec![0xCC; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidSaltLength));
}

#[test]
fn invalid_salt_length_is_rejected_during_decoding() {
    let mut encoded = sample_container().encode().unwrap();

    encoded[11] = (SALT_SIZE - 1) as u8;

    assert_eq!(
        Container::decode(&encoded),
        Err(FormatError::InvalidSaltLength)
    );
}

#[test]
fn invalid_nonce_length_is_rejected() {
    let result = Container::new(
        "ATK-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0; 8],
        vec![],
        vec![0xCC; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidNonceLength));
}

#[test]
fn invalid_tag_length_is_rejected() {
    let result = Container::new(
        "ATK-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0x22; NONCE_SIZE],
        vec![],
        vec![0; 16],
    );

    assert_eq!(result, Err(FormatError::InvalidTagLength));
}

#[test]
fn oversized_payload_is_rejected_during_encoding() {
    let mut container = sample_container();
    container.payload = vec![0; MAX_PAYLOAD_SIZE + 1];

    assert_eq!(container.encode(), Err(FormatError::PayloadTooLarge));
}

#[test]
fn unsupported_version_is_rejected() {
    let mut encoded = sample_container().encode().unwrap();
    encoded[8] = 3;

    assert_eq!(
        Container::decode(&encoded),
        Err(FormatError::UnsupportedVersion(3))
    );
}

#[test]
fn empty_cipher_identifier_is_rejected() {
    let result = Container::new(
        String::new(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0x22; NONCE_SIZE],
        vec![0x10],
        vec![0xCC; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidIdentifier));
}

#[test]
fn lowercase_identifier_is_rejected() {
    let result = Container::new(
        "atk-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0x22; NONCE_SIZE],
        vec![0x10],
        vec![0xCC; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidIdentifier));
}

#[test]
fn invalid_identifier_is_rejected_during_decoding() {
    let mut encoded = sample_container().encode().unwrap();

    encoded[20] = b'a';

    assert_eq!(
        Container::decode(&encoded),
        Err(FormatError::InvalidIdentifier)
    );
}

#[test]
fn empty_identifier_is_rejected_during_decoding() {
    let mut encoded = sample_container().encode().unwrap();

    encoded[9] = 0;

    assert_eq!(
        Container::decode(&encoded),
        Err(FormatError::InvalidIdentifier)
    );
}

#[test]
fn oversized_identifier_is_rejected_during_decoding() {
    let mut encoded = sample_container().encode().unwrap();

    encoded[9] = (MAX_ID_LENGTH + 1) as u8;

    assert_eq!(
        Container::decode(&encoded),
        Err(FormatError::InvalidIdentifier)
    );
}

#[test]
fn empty_payload_round_trip_works() {
    let original = Container::new(
        "ATK-SC-1".to_string(),
        "ATK-KDF-1".to_string(),
        vec![0xAB; SALT_SIZE],
        vec![0x22; NONCE_SIZE],
        vec![],
        vec![0xCC; TAG_SIZE],
    )
    .unwrap();

    let encoded = original.encode().unwrap();
    let decoded = Container::decode(&encoded).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn incorrect_payload_length_is_rejected() {
    let mut encoded = sample_container().encode().unwrap();
    encoded[12..20].copy_from_slice(&5u64.to_be_bytes());

    assert_eq!(Container::decode(&encoded), Err(FormatError::TruncatedData));
}
