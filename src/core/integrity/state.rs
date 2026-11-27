use std::fmt;
use zeroize::Zeroize;

pub const STATE_WORDS: usize = 16;
pub const WORD_SIZE: usize = 4;
pub const STATE_SIZE: usize = STATE_WORDS * WORD_SIZE;

#[derive(PartialEq, Eq)]
pub struct IntegrityState {
    words: [u32; STATE_WORDS],
}

impl fmt::Debug for IntegrityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrityState")
            .field("words", &"[REDACTED]")
            .finish()
    }
}

impl IntegrityState {
    pub fn new(words: [u32; STATE_WORDS]) -> Self {
        Self { words }
    }

    pub fn zeroed() -> Self {
        Self {
            words: [0; STATE_WORDS],
        }
    }

    pub fn words(&self) -> &[u32; STATE_WORDS] {
        &self.words
    }

    pub fn get(&self, index: usize) -> Option<u32> {
        self.words.get(index).copied()
    }

    pub fn set(&mut self, index: usize, value: u32) -> bool {
        if let Some(word) = self.words.get_mut(index) {
            *word = value;
            true
        } else {
            false
        }
    }

    pub fn to_bytes_le(&self) -> [u8; STATE_SIZE] {
        let mut bytes = [0u8; STATE_SIZE];

        for (index, word) in self.words.iter().enumerate() {
            let offset = index * WORD_SIZE;
            bytes[offset..offset + WORD_SIZE].copy_from_slice(&word.to_le_bytes());
        }

        bytes
    }

    pub fn from_bytes_le(bytes: &[u8; STATE_SIZE]) -> Self {
        let mut words = [0u32; STATE_WORDS];

        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * WORD_SIZE;

            *word = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }

        Self { words }
    }
}

impl Drop for IntegrityState {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}
