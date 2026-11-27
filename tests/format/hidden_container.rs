use atk_cl::format::constants::{MAX_PAYLOAD_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use atk_cl::format::container::FormatError;
use atk_cl::format::hidden_container::HiddenContainer;

fn sample_hidden_container() -> HiddenContainer {
    HiddenContainer::new(
        vec![1; SALT_SIZE],
        vec![2; NONCE_SIZE],
        vec![3; 128],
        vec![4; TAG_SIZE],
    )
    .unwrap()
}

#[test]
fn hidden_container_roundtrip() {
    let container = sample_hidden_container();

    let encoded = container.encode().unwrap();
    let decoded = HiddenContainer::decode(&encoded).unwrap();

    assert_eq!(decoded, container);
}

#[test]
fn hidden_container_empty_payload() {
    let container = HiddenContainer::new(
        vec![1; SALT_SIZE],
        vec![2; NONCE_SIZE],
        Vec::new(),
        vec![4; TAG_SIZE],
    )
    .unwrap();

    let encoded = container.encode().unwrap();
    let decoded = HiddenContainer::decode(&encoded).unwrap();

    assert_eq!(decoded, container);
    assert!(decoded.payload.is_empty());
}

#[test]
fn hidden_container_rejects_truncated_data() {
    let data = vec![0; SALT_SIZE + NONCE_SIZE + TAG_SIZE - 1];

    assert_eq!(
        HiddenContainer::decode(&data),
        Err(FormatError::TruncatedData)
    );
}

#[test]
fn hidden_container_rejects_oversized_payload() {
    let data = vec![0; SALT_SIZE + NONCE_SIZE + MAX_PAYLOAD_SIZE + TAG_SIZE + 1];

    assert_eq!(
        HiddenContainer::decode(&data),
        Err(FormatError::PayloadTooLarge)
    );
}

#[test]
fn hidden_container_rejects_invalid_salt_length() {
    let result = HiddenContainer::new(
        vec![0; SALT_SIZE - 1],
        vec![0; NONCE_SIZE],
        Vec::new(),
        vec![0; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidSaltLength));
}

#[test]
fn hidden_container_rejects_invalid_nonce_length() {
    let result = HiddenContainer::new(
        vec![0; SALT_SIZE],
        vec![0; NONCE_SIZE - 1],
        Vec::new(),
        vec![0; TAG_SIZE],
    );

    assert_eq!(result, Err(FormatError::InvalidNonceLength));
}

#[test]
fn hidden_container_rejects_invalid_tag_length() {
    let result = HiddenContainer::new(
        vec![0; SALT_SIZE],
        vec![0; NONCE_SIZE],
        Vec::new(),
        vec![0; TAG_SIZE - 1],
    );

    assert_eq!(result, Err(FormatError::InvalidTagLength));
}

#[test]
fn hidden_container_encode_rejects_mutated_salt_length() {
    let mut container = sample_hidden_container();
    container.salt.pop();

    assert_eq!(container.encode(), Err(FormatError::InvalidSaltLength));
}

#[test]
fn hidden_container_encode_rejects_mutated_nonce_length() {
    let mut container = sample_hidden_container();
    container.nonce.pop();

    assert_eq!(container.encode(), Err(FormatError::InvalidNonceLength));
}

#[test]
fn hidden_container_encode_rejects_mutated_tag_length() {
    let mut container = sample_hidden_container();
    container.tag.pop();

    assert_eq!(container.encode(), Err(FormatError::InvalidTagLength));
}

#[test]
fn hidden_container_encode_rejects_oversized_payload() {
    let mut container = sample_hidden_container();
    container.payload = vec![0; MAX_PAYLOAD_SIZE + 1];

    assert_eq!(container.encode(), Err(FormatError::PayloadTooLarge));
}
