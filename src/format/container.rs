use super::constants::{
    FIXED_HEADER_SIZE, FORMAT_VERSION, MAGIC, MAX_ID_LENGTH, MAX_PAYLOAD_SIZE, NONCE_SIZE,
    SALT_SIZE, TAG_SIZE,
};
use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidIdentifier,
    InvalidSaltLength,
    InvalidNonceLength,
    InvalidTagLength,
    InvalidLength,
    TruncatedData,
    TrailingData,
    PayloadTooLarge,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid ATK container signature."),
            Self::UnsupportedVersion(v) => {
                write!(f, "Unsupported format version: {v}")
            }
            Self::InvalidIdentifier => write!(f, "Invalid algorithm identifier."),
            Self::InvalidSaltLength => write!(f, "Invalid salt length."),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length."),
            Self::InvalidTagLength => write!(f, "Invalid integrity tag length."),
            Self::InvalidLength => write!(f, "Invalid container length."),
            Self::TruncatedData => write!(f, "Container data is incomplete."),
            Self::TrailingData => write!(f, "Unexpected trailing data."),
            Self::PayloadTooLarge => {
                write!(f, "Container payload exceeds the maximum allowed size.")
            }
        }
    }
}

impl std::error::Error for FormatError {}

#[derive(Debug, PartialEq, Eq)]
pub struct Container {
    pub cipher_id: String,
    pub kdf_id: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    pub tag: Vec<u8>,
}

impl Container {
    pub fn new(
        cipher_id: String,
        kdf_id: String,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        payload: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Self, FormatError> {
        validate_id(&cipher_id)?;
        validate_id(&kdf_id)?;

        if salt.len() != SALT_SIZE {
            return Err(FormatError::InvalidSaltLength);
        }

        if nonce.len() != NONCE_SIZE {
            return Err(FormatError::InvalidNonceLength);
        }

        if tag.len() != TAG_SIZE {
            return Err(FormatError::InvalidTagLength);
        }

        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FormatError::PayloadTooLarge);
        }

        Ok(Self {
            cipher_id,
            kdf_id,
            salt,
            nonce,
            payload,
            tag,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        validate_id(&self.cipher_id)?;
        validate_id(&self.kdf_id)?;

        if self.salt.len() != SALT_SIZE {
            return Err(FormatError::InvalidSaltLength);
        }

        if self.nonce.len() != NONCE_SIZE {
            return Err(FormatError::InvalidNonceLength);
        }

        if self.tag.len() != TAG_SIZE {
            return Err(FormatError::InvalidTagLength);
        }

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FormatError::PayloadTooLarge);
        }

        let cipher_len =
            u8::try_from(self.cipher_id.len()).map_err(|_| FormatError::InvalidLength)?;

        let kdf_len = u8::try_from(self.kdf_id.len()).map_err(|_| FormatError::InvalidLength)?;

        let payload_len =
            u64::try_from(self.payload.len()).map_err(|_| FormatError::InvalidLength)?;

        let capacity = FIXED_HEADER_SIZE
            .checked_add(self.cipher_id.len())
            .and_then(|n| n.checked_add(self.kdf_id.len()))
            .and_then(|n| n.checked_add(SALT_SIZE))
            .and_then(|n| n.checked_add(NONCE_SIZE))
            .and_then(|n| n.checked_add(self.payload.len()))
            .and_then(|n| n.checked_add(TAG_SIZE))
            .ok_or(FormatError::InvalidLength)?;

        let mut output = Vec::with_capacity(capacity);

        output.extend_from_slice(MAGIC);
        output.push(FORMAT_VERSION);
        output.push(cipher_len);
        output.push(kdf_len);
        output.push(SALT_SIZE as u8);
        output.extend_from_slice(&payload_len.to_be_bytes());

        output.extend_from_slice(self.cipher_id.as_bytes());
        output.extend_from_slice(self.kdf_id.as_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.payload);
        output.extend_from_slice(&self.tag);

        Ok(output)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < FIXED_HEADER_SIZE {
            return Err(FormatError::TruncatedData);
        }

        if &data[..8] != MAGIC {
            return Err(FormatError::InvalidMagic);
        }

        let version = data[8];

        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let cipher_len = data[9] as usize;
        let kdf_len = data[10] as usize;
        let salt_len = data[11] as usize;

        if cipher_len == 0 || cipher_len > MAX_ID_LENGTH || kdf_len == 0 || kdf_len > MAX_ID_LENGTH
        {
            return Err(FormatError::InvalidIdentifier);
        }

        if salt_len != SALT_SIZE {
            return Err(FormatError::InvalidSaltLength);
        }

        let payload_len = u64::from_be_bytes(
            data[12..20]
                .try_into()
                .map_err(|_| FormatError::TruncatedData)?,
        );

        let payload_len = usize::try_from(payload_len).map_err(|_| FormatError::InvalidLength)?;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(FormatError::PayloadTooLarge);
        }

        let expected_len = FIXED_HEADER_SIZE
            .checked_add(cipher_len)
            .and_then(|n| n.checked_add(kdf_len))
            .and_then(|n| n.checked_add(SALT_SIZE))
            .and_then(|n| n.checked_add(NONCE_SIZE))
            .and_then(|n| n.checked_add(payload_len))
            .and_then(|n| n.checked_add(TAG_SIZE))
            .ok_or(FormatError::InvalidLength)?;

        if data.len() < expected_len {
            return Err(FormatError::TruncatedData);
        }

        if data.len() > expected_len {
            return Err(FormatError::TrailingData);
        }

        let mut position = FIXED_HEADER_SIZE;

        let cipher_id = read_id(data, &mut position, cipher_len)?;
        let kdf_id = read_id(data, &mut position, kdf_len)?;

        let salt = data[position..position + SALT_SIZE].to_vec();
        position += SALT_SIZE;

        let nonce = data[position..position + NONCE_SIZE].to_vec();
        position += NONCE_SIZE;

        let payload_end = position
            .checked_add(payload_len)
            .ok_or(FormatError::InvalidLength)?;

        let payload = data[position..payload_end].to_vec();
        position = payload_end;

        let tag = data[position..position + TAG_SIZE].to_vec();

        Self::new(cipher_id, kdf_id, salt, nonce, payload, tag)
    }
}

pub(crate) fn validate_id(value: &str) -> Result<(), FormatError> {
    if value.is_empty()
        || value.len() > MAX_ID_LENGTH
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(FormatError::InvalidIdentifier);
    }

    Ok(())
}

fn read_id(data: &[u8], position: &mut usize, length: usize) -> Result<String, FormatError> {
    let end = position
        .checked_add(length)
        .ok_or(FormatError::InvalidLength)?;

    let bytes = data.get(*position..end).ok_or(FormatError::TruncatedData)?;

    let value = std::str::from_utf8(bytes)
        .map_err(|_| FormatError::InvalidIdentifier)?
        .to_owned();

    validate_id(&value)?;
    *position = end;

    Ok(value)
}
