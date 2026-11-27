pub fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

pub fn rotate_left(value: u32, bits: u32) -> u32 {
    value.rotate_left(bits)
}

pub fn xor(a: u32, b: u32) -> u32 {
    a ^ b
}
