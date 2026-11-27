pub const MAGIC: &[u8; 8] = b"ATKCL\r\n\x1A";
pub const FORMAT_VERSION: u8 = 1;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 16;
pub const TAG_SIZE: usize = 32;

pub const MAX_ID_LENGTH: usize = 32;
pub const FIXED_HEADER_SIZE: usize = 8 + 1 + 1 + 1 + 1 + 8;

pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024;
