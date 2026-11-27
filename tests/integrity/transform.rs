use atk_cl::core::integrity::state::IntegrityState;
use atk_cl::core::integrity::transform::apply_arx;

fn sample_state() -> IntegrityState {
    IntegrityState::new(std::array::from_fn(|i| (i as u32 + 1) * 0x0102_0304))
}

#[test]
fn apply_arx_accepts_valid_indices() {
    let mut state = sample_state();

    let result = apply_arx(&mut state, 0, 4, 8, 12);

    assert!(result);
    assert_ne!(state, sample_state());
}

#[test]
fn apply_arx_rejects_out_of_bounds_index() {
    let mut state = sample_state();
    let original = state.to_bytes_le();

    let result = apply_arx(&mut state, 0, 4, 8, 16);

    assert!(!result);
    assert_eq!(state.to_bytes_le(), original);
}

#[test]
fn apply_arx_rejects_invalid_index_in_every_position() {
    let invalid_calls = [
        (16, 4, 8, 12),
        (0, 16, 8, 12),
        (0, 4, 16, 12),
        (0, 4, 8, 16),
    ];

    for (a, b, c, d) in invalid_calls {
        let mut state = sample_state();
        let original = state.to_bytes_le();

        let result = apply_arx(&mut state, a, b, c, d);

        assert!(
            !result,
            "Expected rejection for indices ({a}, {b}, {c}, {d})"
        );
        assert_eq!(state.to_bytes_le(), original);
    }
}

#[test]
fn apply_arx_rejects_multiple_invalid_indices() {
    let mut state = sample_state();
    let original = state.to_bytes_le();

    let result = apply_arx(&mut state, 16, 17, 18, 19);

    assert!(!result);
    assert_eq!(state.to_bytes_le(), original);
}
