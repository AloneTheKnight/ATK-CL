use getrandom::fill;

pub const SALT_SIZE: usize = 16;

pub struct Salt {
    bytes: [u8; SALT_SIZE],
}

impl Salt {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; SALT_SIZE];
        fill(&mut bytes)?;

        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: [u8; SALT_SIZE]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; SALT_SIZE] {
        &self.bytes
    }
}
