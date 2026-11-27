use std::io;
use zeroize::Zeroize;

pub struct Password {
    value: Vec<u8>,
}

impl Password {
    pub fn read() -> io::Result<Self> {
        let value = rpassword::prompt_password("Enter password: ")?;
        Self::new(value.into_bytes())
    }

    pub fn new(mut value: Vec<u8>) -> io::Result<Self> {
        if value.is_empty() {
            value.zeroize();

            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Password cannot be empty.",
            ));
        }

        Ok(Self { value })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
