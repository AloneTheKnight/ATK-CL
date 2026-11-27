use crate::core::key::salt::{SALT_SIZE, Salt};
use zeroize::Zeroizing;

pub fn process_salt(salt: &Salt) -> Zeroizing<[u8; SALT_SIZE]> {
    Zeroizing::new(*salt.as_bytes())
}
