use super::constants::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use super::permutation::apply_permutation;
use super::state::{IntegrityState, STATE_WORDS};

use zeroize::Zeroizing;

const INITIAL_STATE: [u32; STATE_WORDS] = [
    0x41544B49, 0x4E543031, 0x9E3779B9, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F,
    0x1F83D9AB, 0x5BE0CD19, 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xC0DEC0DE, 0xA5A5A5A5,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    InvalidKeyLength,
    InvalidNonceLength,
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid integrity key length"),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length"),
        }
    }
}

impl std::error::Error for IntegrityError {}

fn xor_word(state: &mut IntegrityState, index: usize, value: u32) {
    let current = state.get(index).unwrap_or(0);
    state.set(index, current ^ value);
}

fn absorb_block(state: &mut IntegrityState, block: &[u8; 32], counter: u64) {
    for index in 0..8 {
        let offset = index * 4;

        let word = u32::from_le_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);

        xor_word(state, index, word);
    }

    xor_word(state, 14, counter as u32);
    xor_word(state, 15, (counter >> 32) as u32);

    apply_permutation(state);
}

fn initialize_state(key: &[u8], nonce: &[u8]) -> Result<IntegrityState, IntegrityError> {
    if key.len() != KEY_SIZE {
        return Err(IntegrityError::InvalidKeyLength);
    }

    if nonce.len() != NONCE_SIZE {
        return Err(IntegrityError::InvalidNonceLength);
    }

    let mut state = IntegrityState::new(INITIAL_STATE);

    for index in 0..8 {
        let offset = index * 4;

        let word = Zeroizing::new(u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]));

        xor_word(&mut state, index, *word);
    }

    for index in 0..4 {
        let offset = index * 4;

        let word = u32::from_le_bytes([
            nonce[offset],
            nonce[offset + 1],
            nonce[offset + 2],
            nonce[offset + 3],
        ]);

        xor_word(&mut state, index + 8, word);
    }

    xor_word(&mut state, 15, 0x41544B31);

    apply_permutation(&mut state);

    Ok(state)
}

pub fn compute_tag(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> Result<[u8; TAG_SIZE], IntegrityError> {
    let mut state = initialize_state(key, nonce)?;

    let mut counter = 0u64;

    for chunk in data.chunks(32) {
        let mut block = Zeroizing::new([0u8; 32]);
        block[..chunk.len()].copy_from_slice(chunk);

        if chunk.len() < 32 {
            block[chunk.len()] = 0x80;
        }

        absorb_block(&mut state, &block, counter);
        counter = counter.wrapping_add(1);
    }

    if data.is_empty() || data.len().is_multiple_of(32) {
        let mut block = Zeroizing::new([0u8; 32]);
        block[0] = 0x80;
        absorb_block(&mut state, &block, counter);
    }

    let data_len = data.len() as u64;
    xor_word(&mut state, 12, data_len as u32);
    xor_word(&mut state, 13, (data_len >> 32) as u32);
    xor_word(&mut state, 14, 0x494E5431);

    apply_permutation(&mut state);
    apply_permutation(&mut state);

    let serialized = Zeroizing::new(state.to_bytes_le());

    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&serialized[..TAG_SIZE]);

    Ok(tag)
}

pub fn verify_tag(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    expected_tag: &[u8],
) -> Result<bool, IntegrityError> {
    if expected_tag.len() != TAG_SIZE {
        return Ok(false);
    }

    let actual_tag = compute_tag(key, nonce, data)?;

    let mut difference = 0u8;

    for index in 0..TAG_SIZE {
        difference |= actual_tag[index] ^ expected_tag[index];
    }

    Ok(difference == 0)
}
