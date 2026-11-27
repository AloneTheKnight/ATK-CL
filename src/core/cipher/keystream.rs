use super::round::{DEFAULT_ROUNDS, RoundError, apply_rounds};
use super::state::{CipherState, STATE_SIZE};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystreamError {
    CounterExhausted,
    RoundFailure,
}

impl From<RoundError> for KeystreamError {
    fn from(_: RoundError) -> Self {
        Self::RoundFailure
    }
}

pub struct KeystreamGenerator {
    initial_state: CipherState,
    counter: u64,
    exhausted: bool,
}

impl KeystreamGenerator {
    pub fn new(initial_state: CipherState) -> Self {
        Self {
            initial_state,
            counter: 0,
            exhausted: false,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn next_block(&mut self) -> Result<[u8; STATE_SIZE], KeystreamError> {
        let output = self.next_block_zeroizing()?;
        Ok(*output)
    }

    pub(crate) fn next_block_zeroizing(
        &mut self,
    ) -> Result<Zeroizing<[u8; STATE_SIZE]>, KeystreamError> {
        if self.exhausted {
            return Err(KeystreamError::CounterExhausted);
        }

        let mut words = Zeroizing::new(*self.initial_state.words());

        words[14] ^= self.counter as u32;
        words[15] ^= (self.counter >> 32) as u32;

        let mut state = CipherState::new(*words);

        apply_rounds(&mut state, DEFAULT_ROUNDS)?;

        let output = Zeroizing::new(state.to_bytes_le());

        match self.counter.checked_add(1) {
            Some(next) => self.counter = next,
            None => self.exhausted = true,
        }

        Ok(output)
    }
}
