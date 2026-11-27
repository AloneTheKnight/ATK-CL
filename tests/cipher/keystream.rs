use atk_cl::core::cipher::keystream::KeystreamGenerator;
use atk_cl::core::cipher::state::{CipherState, STATE_SIZE, STATE_WORDS};

#[test]
fn generated_block_has_expected_size() {
    let state = CipherState::new([1; STATE_WORDS]);
    let mut generator = KeystreamGenerator::new(state);

    assert_eq!(generator.next_block().unwrap().len(), STATE_SIZE);
}

#[test]
fn generator_starts_at_counter_zero() {
    let generator = KeystreamGenerator::new(CipherState::zeroed());
    assert_eq!(generator.counter(), 0);
}

#[test]
fn counter_increments_after_generation() {
    let state = CipherState::new([1; STATE_WORDS]);
    let mut generator = KeystreamGenerator::new(state);

    generator.next_block().unwrap();

    assert_eq!(generator.counter(), 1);
}

#[test]
fn consecutive_blocks_are_different() {
    let state = CipherState::new([1; STATE_WORDS]);
    let mut generator = KeystreamGenerator::new(state);

    let first = generator.next_block().unwrap();
    let second = generator.next_block().unwrap();

    assert_ne!(first, second);
}

#[test]
fn generators_are_deterministic() {
    let mut first = KeystreamGenerator::new(CipherState::new([0x12345678; STATE_WORDS]));

    let mut second = KeystreamGenerator::new(CipherState::new([0x12345678; STATE_WORDS]));

    assert_eq!(first.next_block().unwrap(), second.next_block().unwrap());
}
