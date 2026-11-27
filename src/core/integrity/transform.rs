use super::state::IntegrityState;
use zeroize::Zeroizing;

pub fn apply_arx(state: &mut IntegrityState, a: usize, b: usize, c: usize, d: usize) -> bool {
    if state.get(a).is_none()
        || state.get(b).is_none()
        || state.get(c).is_none()
        || state.get(d).is_none()
    {
        return false;
    }

    let mut a_value = Zeroizing::new(state.get(a).unwrap_or(0));
    let mut b_value = Zeroizing::new(state.get(b).unwrap_or(0));
    let mut c_value = Zeroizing::new(state.get(c).unwrap_or(0));
    let mut d_value = Zeroizing::new(state.get(d).unwrap_or(0));

    *a_value = a_value.wrapping_add(*b_value);
    *d_value ^= *a_value;
    *d_value = d_value.rotate_left(16);

    *c_value = c_value.wrapping_add(*d_value);
    *b_value ^= *c_value;
    *b_value = b_value.rotate_left(12);

    *a_value = a_value.wrapping_add(*b_value);
    *d_value ^= *a_value;
    *d_value = d_value.rotate_left(8);

    *c_value = c_value.wrapping_add(*d_value);
    *b_value ^= *c_value;
    *b_value = b_value.rotate_left(7);

    state.set(a, *a_value);
    state.set(b, *b_value);
    state.set(c, *c_value);
    state.set(d, *d_value);

    true
}
