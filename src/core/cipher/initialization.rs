use super::constants::{KEY_SIZE, NONCE_SIZE};
use super::state::{CipherState, STATE_SIZE, STATE_WORDS};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitializationError {
    InvalidKeyLength,
    InvalidNonceLength,
}

pub fn initialize_state(key: &[u8], nonce: &[u8]) -> Result<CipherState, InitializationError> {
    if key.len() != KEY_SIZE {
        return Err(InitializationError::InvalidKeyLength);
    }

    if nonce.len() != NONCE_SIZE {
        return Err(InitializationError::InvalidNonceLength);
    }

    let mut bytes = Zeroizing::new([0u8; STATE_SIZE]);

    bytes[..KEY_SIZE].copy_from_slice(key);

    bytes[KEY_SIZE..KEY_SIZE + NONCE_SIZE].copy_from_slice(nonce);

    let mut words = Zeroizing::new([0u32; STATE_WORDS]);

    for (index, word) in words.iter_mut().enumerate() {
        let offset = index * 4;

        *word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
    }

    Ok(CipherState::new(*words))
}
