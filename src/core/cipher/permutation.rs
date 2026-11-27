use super::state::{CipherState, STATE_WORDS};
use super::transform::apply_arx;

const COLUMN_GROUPS: [[usize; 4]; 4] =
    [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];

const DIAGONAL_GROUPS: [[usize; 4]; 4] =
    [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

fn apply_column_phase(state: &mut CipherState) -> bool {
    for group in COLUMN_GROUPS {
        if !apply_arx(state, group[0], group[1], group[2], group[3]) {
            return false;
        }
    }

    true
}

fn apply_diagonal_phase(state: &mut CipherState) -> bool {
    for group in DIAGONAL_GROUPS {
        if !apply_arx(state, group[0], group[1], group[2], group[3]) {
            return false;
        }
    }

    true
}

pub fn apply_permutation(state: &mut CipherState) -> bool {
    if STATE_WORDS != 16 {
        return false;
    }

    if !apply_column_phase(state) {
        return false;
    }

    if !apply_diagonal_phase(state) {
        return false;
    }

    true
}
