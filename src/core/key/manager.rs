use std::io;

use super::{password::Password, salt::Salt};

pub struct KeyManager {
    password: Password,
    salt: Salt,
}

impl KeyManager {
    pub fn create() -> io::Result<Self> {
        let password = Password::read()
            .map_err(|error| io::Error::new(error.kind(), format!("Password error: {error}")))?;

        let salt = Salt::generate()
            .map_err(|error| io::Error::other(format!("Salt generation failed: {error}")))?;

        Ok(Self { password, salt })
    }

    pub fn password(&self) -> &Password {
        &self.password
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }
}
