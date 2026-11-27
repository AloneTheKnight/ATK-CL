use crate::core::cipher::stream::{StreamCipher, StreamCipherError};
use zeroize::Zeroizing;

pub fn count_changed_bits(left: &[u8], right: &[u8]) -> Option<usize> {
    if left.len() != right.len() {
        return None;
    }

    Some(
        left.iter()
            .zip(right.iter())
            .fold(0usize, |total, (&a, &b)| {
                total.saturating_add((a ^ b).count_ones() as usize)
            }),
    )
}

pub fn total_bits(data: &[u8]) -> usize {
    data.len().saturating_mul(8)
}

pub fn difference_ratio(left: &[u8], right: &[u8]) -> Option<f64> {
    let changed = count_changed_bits(left, right)?;
    let total = total_bits(left);

    if total == 0 {
        return Some(0.0);
    }

    Some(changed as f64 / total as f64)
}

pub fn key_bit_flip_difference(
    key: &[u8],
    nonce: &[u8],
    input: &[u8],
    byte_index: usize,
    bit_index: u8,
) -> Result<Option<usize>, StreamCipherError> {
    if bit_index > 7 || byte_index >= key.len() {
        return Ok(None);
    }

    let mut changed_key = Zeroizing::new(key.to_vec());
    changed_key[byte_index] ^= 1u8 << bit_index;

    let mut original_cipher = StreamCipher::from_key_nonce(key, nonce)?;
    let original_output = original_cipher.process_zeroizing(input)?;

    let mut changed_cipher = StreamCipher::from_key_nonce(&changed_key, nonce)?;
    let changed_output = changed_cipher.process_zeroizing(input)?;

    Ok(count_changed_bits(&original_output, &changed_output))
}
