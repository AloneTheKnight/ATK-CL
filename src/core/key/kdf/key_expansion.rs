use crate::core::cipher::{round::apply_rounds, state::CipherState};

use super::super::constants::KEY_SIZE;
use super::super::derive::{KdfError, KeyMaterial};
use super::constants::{BLOCK_SIZE, KDF_ITERATIONS, ROUND_COUNT};
use zeroize::Zeroizing;

const INITIAL_STATE: [u32; 16] = [
    0x41544B31, 0x4B444631, 0x9E3779B9, 0x243F6A88, 0xB7E15162, 0x8AED2A6B, 0xC6EF3720, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
];

pub fn expand_key(input: &[u8]) -> Result<KeyMaterial, KdfError> {
    let mut state = CipherState::new(INITIAL_STATE);

    for (block_index, block) in input.chunks(BLOCK_SIZE).enumerate() {
        let block_counter = u32::try_from(block_index).map_err(|_| KdfError::InputTooLarge)?;

        let mut words = Zeroizing::new(*state.words());

        for (word_index, bytes) in block.chunks(4).enumerate() {
            let mut buffer = Zeroizing::new([0u8; 4]);
            buffer[..bytes.len()].copy_from_slice(bytes);

            words[word_index] ^= u32::from_le_bytes(*buffer);
        }

        words[15] ^= block_counter;
        state = CipherState::new(*words);

        apply_rounds(&mut state, ROUND_COUNT).map_err(|_| KdfError::PermutationFailure)?;
    }

    for iteration in 0..KDF_ITERATIONS {
        let mut words = Zeroizing::new(*state.words());

        words[0] ^= iteration as u32;
        words[15] ^= (iteration as u32).rotate_left(16);

        state = CipherState::new(*words);

        apply_rounds(&mut state, ROUND_COUNT).map_err(|_| KdfError::PermutationFailure)?;
    }

    let output = Zeroizing::new(state.to_bytes_le());

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&output[..KEY_SIZE]);

    Ok(KeyMaterial::from_bytes(*key))
}
