use zeroize::Zeroizing;

use crate::core::cipher::{round::apply_rounds, state::CipherState};

use super::constants::KEY_SIZE;
use super::derive::{KdfError, KeyMaterial};

const STATE_WORDS: usize = 16;
const ROUND_COUNT: usize = 10;

const SEPARATION_ID: &[u8] = b"ATK-KS-1";

const CIPHER_DOMAIN: &[u8] = b"ATK-SC-1-KEY";
const INTEGRITY_DOMAIN: &[u8] = b"ATK-INT-1-KEY";

const INITIAL_STATE: [u32; STATE_WORDS] = [
    0x41544B4B, 0x532D3031, 0x9E3779B9, 0x243F6A88, 0xB7E15162, 0x8AED2A6B, 0xC6EF3720, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
];

pub(crate) struct DerivedSubkeys {
    pub(crate) cipher_key: Zeroizing<[u8; KEY_SIZE]>,
    pub(crate) integrity_key: Zeroizing<[u8; KEY_SIZE]>,
}

pub(crate) fn derive_subkeys(master_key: &KeyMaterial) -> Result<DerivedSubkeys, KdfError> {
    let cipher_key = expand_domain(master_key, CIPHER_DOMAIN)?;
    let integrity_key = expand_domain(master_key, INTEGRITY_DOMAIN)?;

    Ok(DerivedSubkeys {
        cipher_key,
        integrity_key,
    })
}

fn expand_domain(
    master_key: &KeyMaterial,
    domain: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, KdfError> {
    let mut state = CipherState::new(INITIAL_STATE);

    let mut input = Zeroizing::new(Vec::new());

    input.extend_from_slice(SEPARATION_ID);
    input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    input.extend_from_slice(domain);
    input.extend_from_slice(master_key.as_bytes());

    for (index, chunk) in input.chunks(64).enumerate() {
        let mut words = Zeroizing::new(*state.words());

        for (word_index, bytes) in chunk.chunks(4).enumerate() {
            let mut buffer = Zeroizing::new([0u8; 4]);
            buffer[..bytes.len()].copy_from_slice(bytes);

            words[word_index] ^= u32::from_le_bytes(*buffer);
        }

        words[15] ^= index as u32;

        state = CipherState::new(*words);

        apply_rounds(&mut state, ROUND_COUNT).map_err(|_| KdfError::PermutationFailure)?;
    }

    for round in 0..1000u32 {
        let mut words = Zeroizing::new(*state.words());

        words[0] ^= round;
        words[15] ^= round.rotate_left(16);

        state = CipherState::new(*words);

        apply_rounds(&mut state, ROUND_COUNT).map_err(|_| KdfError::PermutationFailure)?;
    }

    let serialized = Zeroizing::new(state.to_bytes_le());

    let mut output = Zeroizing::new([0u8; KEY_SIZE]);
    output.copy_from_slice(&serialized[..KEY_SIZE]);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_KEY: [u8; 32] = [0x42; 32];

    const EXPECTED_CIPHER_KEY: [u8; 32] = [
        0x78, 0x78, 0xe9, 0x7d, 0xed, 0x26, 0x00, 0xdc, 0x88, 0x96, 0x88, 0xf5, 0x3f, 0x96, 0xaa,
        0x6d, 0xbd, 0x8d, 0x59, 0x40, 0x92, 0xae, 0x01, 0x38, 0x70, 0x94, 0xcd, 0xf5, 0xa2, 0x37,
        0x9b, 0xb9,
    ];

    const EXPECTED_INTEGRITY_KEY: [u8; 32] = [
        0x4d, 0x57, 0xd7, 0x43, 0x37, 0x19, 0xb9, 0xb6, 0x60, 0xbe, 0x86, 0x49, 0x56, 0xe1, 0x94,
        0x65, 0x59, 0x93, 0x22, 0x14, 0x04, 0x2c, 0x3e, 0x59, 0x94, 0x67, 0xe5, 0x5a, 0x23, 0x5b,
        0xcc, 0x2e,
    ];

    #[test]
    fn atk_ks1_known_answer_001() {
        let master = KeyMaterial::from_bytes(MASTER_KEY);
        let subkeys = derive_subkeys(&master).unwrap();

        assert_eq!(*subkeys.cipher_key, EXPECTED_CIPHER_KEY);
        assert_eq!(*subkeys.integrity_key, EXPECTED_INTEGRITY_KEY);
    }

    #[test]
    fn atk_ks1_subkeys_are_different() {
        let master = KeyMaterial::from_bytes(MASTER_KEY);
        let subkeys = derive_subkeys(&master).unwrap();

        assert_ne!(*subkeys.cipher_key, *subkeys.integrity_key);
    }
}
