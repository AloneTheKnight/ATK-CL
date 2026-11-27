use super::{
    constants::{KDF_ID, KEY_SIZE},
    kdf::{
        key_expansion::expand_key, password_processing::process_password,
        salt_processing::process_salt,
    },
    password::Password,
    salt::Salt,
};

use std::fmt;
use zeroize::Zeroizing;

pub struct KeyMaterial {
    bytes: [u8; KEY_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    PermutationFailure,
    InputTooLarge,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermutationFailure => {
                write!(f, "ATK-KDF-1 permutation failed")
            }
            Self::InputTooLarge => {
                write!(f, "ATK-KDF-1 input is too large")
            }
        }
    }
}

impl std::error::Error for KdfError {}

impl KeyMaterial {
    pub(crate) fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

pub fn derive_key(password: &Password, salt: &Salt) -> Result<KeyMaterial, KdfError> {
    let password_bytes = process_password(password.as_bytes());
    let salt_bytes = process_salt(salt);

    let password_length =
        u64::try_from(password_bytes.len()).map_err(|_| KdfError::InputTooLarge)?;

    let input_capacity = KDF_ID
        .len()
        .checked_add(std::mem::size_of::<u64>())
        .and_then(|size| size.checked_add(password_bytes.len()))
        .and_then(|size| size.checked_add(salt_bytes.len()))
        .ok_or(KdfError::InputTooLarge)?;

    let mut input = Zeroizing::new(Vec::with_capacity(input_capacity));

    input.extend_from_slice(KDF_ID.as_bytes());
    input.extend_from_slice(&password_length.to_le_bytes());
    input.extend_from_slice(&password_bytes);
    input.extend_from_slice(&salt_bytes[..]);

    expand_key(&input)
}
