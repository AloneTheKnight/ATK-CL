use super::constants::{MAX_PAYLOAD_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use super::container::FormatError;

/// SALT (16) || NONCE (16) || PAYLOAD (variable) || TAG (32)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenContainer {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    pub tag: Vec<u8>,
}

impl HiddenContainer {
    pub fn new(
        salt: Vec<u8>,
        nonce: Vec<u8>,
        payload: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Self, FormatError> {
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
            salt,
            nonce,
            payload,
            tag,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
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

        let capacity = SALT_SIZE
            .checked_add(NONCE_SIZE)
            .and_then(|n| n.checked_add(self.payload.len()))
            .and_then(|n| n.checked_add(TAG_SIZE))
            .ok_or(FormatError::InvalidLength)?;

        let mut output = Vec::with_capacity(capacity);

        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.payload);
        output.extend_from_slice(&self.tag);

        Ok(output)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let minimum_size = SALT_SIZE + NONCE_SIZE + TAG_SIZE;
        let maximum_size = minimum_size
            .checked_add(MAX_PAYLOAD_SIZE)
            .ok_or(FormatError::InvalidLength)?;

        if data.len() < minimum_size {
            return Err(FormatError::TruncatedData);
        }

        if data.len() > maximum_size {
            return Err(FormatError::PayloadTooLarge);
        }

        let payload_end = data.len() - TAG_SIZE;

        let salt = data[..SALT_SIZE].to_vec();
        let nonce = data[SALT_SIZE..SALT_SIZE + NONCE_SIZE].to_vec();
        let payload = data[SALT_SIZE + NONCE_SIZE..payload_end].to_vec();
        let tag = data[payload_end..].to_vec();

        Self::new(salt, nonce, payload, tag)
    }
}
