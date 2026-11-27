use super::state::IntegrityState;
use super::transform::apply_arx;

pub const ROUNDS: usize = 10;

pub fn apply_permutation(state: &mut IntegrityState) {
    for _ in 0..ROUNDS {
        assert!(apply_arx(state, 0, 4, 8, 12));
        assert!(apply_arx(state, 1, 5, 9, 13));
        assert!(apply_arx(state, 2, 6, 10, 14));
        assert!(apply_arx(state, 3, 7, 11, 15));

        assert!(apply_arx(state, 0, 5, 10, 15));
        assert!(apply_arx(state, 1, 6, 11, 12));
        assert!(apply_arx(state, 2, 7, 8, 13));
        assert!(apply_arx(state, 3, 4, 9, 14));
    }
}
