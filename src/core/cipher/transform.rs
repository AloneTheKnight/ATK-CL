use super::state::{CipherState, STATE_WORDS};
use zeroize::Zeroizing;

pub fn apply_arx(state: &mut CipherState, a: usize, b: usize, c: usize, d: usize) -> bool {
    if [a, b, c, d].iter().any(|&i| i >= STATE_WORDS) {
        return false;
    }

    let mut words = Zeroizing::new(*state.words());

    words[a] = words[a].wrapping_add(words[b]);
    words[d] ^= words[a];
    words[d] = words[d].rotate_left(16);

    words[c] = words[c].wrapping_add(words[d]);
    words[b] ^= words[c];
    words[b] = words[b].rotate_left(12);

    words[a] = words[a].wrapping_add(words[b]);
    words[d] ^= words[a];
    words[d] = words[d].rotate_left(8);

    words[c] = words[c].wrapping_add(words[d]);
    words[b] ^= words[c];
    words[b] = words[b].rotate_left(7);

    *state = CipherState::new(*words);

    true
}
