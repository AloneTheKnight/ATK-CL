use atk_cl::utils::encoding::{EncodingError, from_base64, from_hex, to_base64, to_hex};

#[test]
fn hex_encoding_works() {
    assert_eq!(to_hex(b"ATK"), "41544B");
}

#[test]
fn base64_encoding_works() {
    assert_eq!(to_base64(b"ATK"), "QVRL");
}

#[test]
fn hex_decoding_works() {
    assert_eq!(from_hex("41544B").unwrap(), b"ATK");
}

#[test]
fn hex_decoding_accepts_lowercase_and_whitespace() {
    assert_eq!(from_hex("41 54\n4b").unwrap(), b"ATK");
}

#[test]
fn base64_decoding_works() {
    assert_eq!(from_base64("QVRL").unwrap(), b"ATK");
}

#[test]
fn base64_decoding_accepts_whitespace() {
    assert_eq!(from_base64("QVRL\n").unwrap(), b"ATK");
}

#[test]
fn invalid_hex_length_is_rejected() {
    assert_eq!(from_hex("ABC"), Err(EncodingError::InvalidHexLength));
}

#[test]
fn invalid_hex_character_is_rejected() {
    assert_eq!(from_hex("GG"), Err(EncodingError::InvalidHexCharacter));
}

#[test]
fn invalid_base64_is_rejected() {
    assert_eq!(from_base64("%%%"), Err(EncodingError::InvalidBase64));
}

#[test]
fn empty_input_works() {
    assert_eq!(to_hex(&[]), "");
    assert_eq!(to_base64(&[]), "");
    assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    assert_eq!(from_base64("").unwrap(), Vec::<u8>::new());
}
