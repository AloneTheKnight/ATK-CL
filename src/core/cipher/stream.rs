use super::keystream::{KeystreamError, KeystreamGenerator};
use super::state::{CipherState, STATE_SIZE};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamCipherError {
    KeystreamFailure(KeystreamError),
    PositionOverflow,
    InvalidInitialization,
}

impl From<KeystreamError> for StreamCipherError {
    fn from(error: KeystreamError) -> Self {
        Self::KeystreamFailure(error)
    }
}

pub struct StreamCipher {
    generator: KeystreamGenerator,
    current_block: [u8; STATE_SIZE],
    block_position: usize,
    position: usize,
}

impl StreamCipher {
    pub fn new(state: CipherState) -> Self {
        Self {
            generator: KeystreamGenerator::new(state),
            current_block: [0; STATE_SIZE],
            block_position: STATE_SIZE,
            position: 0,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn process(&mut self, input: &[u8]) -> Result<Vec<u8>, StreamCipherError> {
        let mut output = self.process_zeroizing(input)?;
        Ok(std::mem::take(&mut *output))
    }

    pub(crate) fn process_zeroizing(
        &mut self,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StreamCipherError> {
        let new_position = self
            .position
            .checked_add(input.len())
            .ok_or(StreamCipherError::PositionOverflow)?;

        let mut output = Zeroizing::new(Vec::with_capacity(input.len()));

        for &byte in input {
            if self.block_position == STATE_SIZE {
                let next_block = self.generator.next_block_zeroizing()?;

                self.current_block.zeroize();
                self.current_block.copy_from_slice(&next_block[..]);

                self.block_position = 0;
            }

            output.push(byte ^ self.current_block[self.block_position]);
            self.block_position += 1;
        }

        self.position = new_position;

        Ok(output)
    }

    pub fn from_key_nonce(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        let state = super::initialization::initialize_state(key, nonce)
            .map_err(|_| StreamCipherError::InvalidInitialization)?;

        Ok(Self::new(state))
    }
}

impl Drop for StreamCipher {
    fn drop(&mut self) {
        self.current_block.zeroize();
    }
}
