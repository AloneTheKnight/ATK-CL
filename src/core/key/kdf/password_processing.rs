use zeroize::Zeroizing;

pub fn process_password(password: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.to_vec())
}
