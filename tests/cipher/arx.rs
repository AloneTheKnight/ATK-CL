use atk_cl::core::cipher::arx::{add, rotate_left, xor};

#[test]
fn addition_wraps_around() {
    assert_eq!(add(u32::MAX, 1), 0);
}

#[test]
fn addition_works() {
    assert_eq!(add(10, 20), 30);
}

#[test]
fn rotation_works() {
    assert_eq!(rotate_left(0x00000001, 1), 0x00000002);
}

#[test]
fn rotation_wraps_bits() {
    assert_eq!(rotate_left(0x80000000, 1), 0x00000001);
}

#[test]
fn xor_works() {
    assert_eq!(xor(0b1100, 0b1010), 0b0110);
}

#[test]
fn xor_with_zero_preserves_value() {
    assert_eq!(xor(0x12345678, 0), 0x12345678);
}
