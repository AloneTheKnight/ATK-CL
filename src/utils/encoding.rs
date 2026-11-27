use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    InvalidHexLength,
    InvalidHexCharacter,
    InvalidBase64,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexLength => write!(f, "HEX input has an odd length"),
            Self::InvalidHexCharacter => write!(f, "HEX input contains invalid characters"),
            Self::InvalidBase64 => write!(f, "Invalid Base64 input"),
        }
    }
}

impl std::error::Error for EncodingError {}

pub fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(data.len().saturating_mul(2));

    for &byte in data {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0F) as usize] as char);
    }

    result
}

pub fn from_hex(input: &str) -> Result<Vec<u8>, EncodingError> {
    let mut result = from_hex_zeroizing(input)?;
    Ok(std::mem::take(&mut *result))
}

pub fn from_hex_zeroizing(input: &str) -> Result<Zeroizing<Vec<u8>>, EncodingError> {
    let cleaned = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );

    if !cleaned.len().is_multiple_of(2) {
        return Err(EncodingError::InvalidHexLength);
    }

    let mut result = Zeroizing::new(Vec::with_capacity(cleaned.len() / 2));

    for pair in cleaned.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(EncodingError::InvalidHexCharacter)?;

        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(EncodingError::InvalidHexCharacter)?;

        result.push(((high << 4) | low) as u8);
    }

    Ok(result)
}

pub fn to_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn from_base64(input: &str) -> Result<Vec<u8>, EncodingError> {
    let mut result = from_base64_zeroizing(input)?;
    Ok(std::mem::take(&mut *result))
}

pub fn from_base64_zeroizing(input: &str) -> Result<Zeroizing<Vec<u8>>, EncodingError> {
    let cleaned = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );

    STANDARD
        .decode(cleaned.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| EncodingError::InvalidBase64)
}

pub fn format_both(data: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = Zeroizing::new(String::new());

    result.push_str("\n========== ENCODED OUTPUT ==========\n");
    result.push_str("HEX:\n");

    for &byte in data {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0F) as usize] as char);
    }

    result.push_str("\n\nBase64:\n");
    STANDARD.encode_string(data, &mut result);
    result.push_str("\n==================================\n");

    result
}
