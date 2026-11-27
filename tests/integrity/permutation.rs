use atk_cl::core::integrity::permutation::apply_permutation;
use atk_cl::core::integrity::state::IntegrityState;

#[test]
fn permutation_changes_state() {
    let mut state = IntegrityState::zeroed();
    state.set(0, 0x12345678);

    let mut original = IntegrityState::zeroed();
    original.set(0, 0x12345678);

    apply_permutation(&mut state);

    assert_ne!(state, original);
}

#[test]
fn permutation_is_deterministic() {
    let mut first = IntegrityState::zeroed();
    let mut second = IntegrityState::zeroed();

    first.set(0, 123);
    second.set(0, 123);

    apply_permutation(&mut first);
    apply_permutation(&mut second);

    assert_eq!(first, second);
}
