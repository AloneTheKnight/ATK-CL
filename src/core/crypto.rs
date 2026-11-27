use crate::core::cipher::StreamCipher;
use crate::core::cipher::constants::CIPHER_ID;
use crate::core::integrity::{compute_tag, verify_tag};
use crate::core::key::constants::KDF_ID;
use crate::core::key::derive::derive_key;
use crate::core::key::key_separation::derive_subkeys;
use crate::core::key::password::Password;
use crate::core::key::salt::Salt;
use crate::format::constants::{MAX_PAYLOAD_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use crate::format::container::Container;
use zeroize::Zeroizing;

use std::fmt;

#[derive(Debug)]
pub struct CryptoError(String);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CryptoError {}

fn error(message: impl Into<String>) -> CryptoError {
    CryptoError(message.into())
}

pub fn encrypt(data: &[u8], password: &Password) -> Result<Container, CryptoError> {
    if data.len() > MAX_PAYLOAD_SIZE {
        return Err(error("Input data exceeds the maximum allowed size."));
    }

    let salt = Salt::generate().map_err(|e| error(format!("Salt generation failed: {e:?}")))?;

    let mut nonce = [0u8; NONCE_SIZE];

    getrandom::fill(&mut nonce).map_err(|e| error(format!("Nonce generation failed: {e:?}")))?;

    let master_key =
        derive_key(password, &salt).map_err(|e| error(format!("Key derivation failed: {e:?}")))?;

    let subkeys =
        derive_subkeys(&master_key).map_err(|e| error(format!("Key separation failed: {e:?}")))?;

    let mut cipher = StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &nonce)
        .map_err(|e| error(format!("Cipher initialization failed: {e:?}")))?;

    let ciphertext = cipher
        .process_zeroizing(data)
        .map_err(|e| error(format!("Encryption failed: {e:?}")))?;

    let tag = compute_tag(subkeys.integrity_key.as_ref(), &nonce, &ciphertext)
        .map_err(|e| error(format!("Integrity tag generation failed: {e:?}")))?;

    Container::new(
        CIPHER_ID.to_string(),
        KDF_ID.to_string(),
        salt.as_bytes().to_vec(),
        nonce.to_vec(),
        ciphertext.to_vec(),
        tag.to_vec(),
    )
    .map_err(|e| error(format!("Container creation failed: {e:?}")))
}

pub fn encrypt_hidden(
    data: &[u8],
    password: &Password,
) -> Result<crate::format::HiddenContainer, CryptoError> {
    if data.len() > MAX_PAYLOAD_SIZE {
        return Err(error("Input data exceeds the maximum allowed size."));
    }

    let salt = Salt::generate().map_err(|e| error(format!("Salt generation failed: {e:?}")))?;

    let mut nonce = [0u8; NONCE_SIZE];

    getrandom::fill(&mut nonce).map_err(|e| error(format!("Nonce generation failed: {e:?}")))?;

    let master_key =
        derive_key(password, &salt).map_err(|e| error(format!("Key derivation failed: {e:?}")))?;

    let subkeys =
        derive_subkeys(&master_key).map_err(|e| error(format!("Key separation failed: {e:?}")))?;

    let mut cipher = StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &nonce)
        .map_err(|e| error(format!("Cipher initialization failed: {e:?}")))?;

    let ciphertext = cipher
        .process_zeroizing(data)
        .map_err(|e| error(format!("Encryption failed: {e:?}")))?;

    let tag = compute_tag(subkeys.integrity_key.as_ref(), &nonce, &ciphertext)
        .map_err(|e| error(format!("Integrity tag generation failed: {e:?}")))?;

    crate::format::HiddenContainer::new(
        salt.as_bytes().to_vec(),
        nonce.to_vec(),
        ciphertext.to_vec(),
        tag.to_vec(),
    )
    .map_err(|e| error(format!("Hidden container creation failed: {e:?}")))
}

pub fn decrypt(container: &Container, password: &Password) -> Result<Vec<u8>, CryptoError> {
    let mut plaintext = decrypt_zeroizing(container, password)?;
    Ok(std::mem::take(&mut *plaintext))
}

pub fn decrypt_hidden_zeroizing(
    container: &crate::format::HiddenContainer,
    password: &Password,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if container.payload.len() > MAX_PAYLOAD_SIZE
        || container.salt.len() != SALT_SIZE
        || container.nonce.len() != NONCE_SIZE
        || container.tag.len() != TAG_SIZE
    {
        return Err(error("Decryption failed."));
    }

    let salt_bytes: [u8; SALT_SIZE] = container
        .salt
        .as_slice()
        .try_into()
        .map_err(|_| error("Decryption failed."))?;

    let salt = Salt::from_bytes(salt_bytes);

    let master_key = derive_key(password, &salt).map_err(|_| error("Decryption failed."))?;

    let subkeys = derive_subkeys(&master_key).map_err(|_| error("Decryption failed."))?;

    let valid = verify_tag(
        subkeys.integrity_key.as_ref(),
        &container.nonce,
        &container.payload,
        &container.tag,
    )
    .map_err(|_| error("Decryption failed."))?;

    if !valid {
        return Err(error("Decryption failed."));
    }

    let mut cipher = StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &container.nonce)
        .map_err(|_| error("Decryption failed."))?;

    cipher
        .process_zeroizing(&container.payload)
        .map_err(|_| error("Decryption failed."))
}

pub fn decrypt_zeroizing(
    container: &Container,
    password: &Password,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if container.cipher_id != CIPHER_ID {
        return Err(error("Unsupported cipher identifier."));
    }

    if container.kdf_id != KDF_ID {
        return Err(error("Unsupported KDF identifier."));
    }

    if container.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(error("Container payload exceeds the maximum allowed size."));
    }

    if container.salt.len() != SALT_SIZE {
        return Err(error("Invalid salt length."));
    }

    if container.nonce.len() != NONCE_SIZE {
        return Err(error("Invalid nonce length."));
    }

    if container.tag.len() != TAG_SIZE {
        return Err(error("Invalid integrity tag length."));
    }

    let salt_bytes: [u8; SALT_SIZE] = container
        .salt
        .as_slice()
        .try_into()
        .map_err(|_| error("Invalid salt length."))?;

    let salt = Salt::from_bytes(salt_bytes);

    let master_key =
        derive_key(password, &salt).map_err(|e| error(format!("Key derivation failed: {e:?}")))?;

    let subkeys =
        derive_subkeys(&master_key).map_err(|e| error(format!("Key separation failed: {e:?}")))?;

    let valid = verify_tag(
        subkeys.integrity_key.as_ref(),
        &container.nonce,
        &container.payload,
        &container.tag,
    )
    .map_err(|e| error(format!("Integrity verification failed: {e:?}")))?;

    if !valid {
        return Err(error(
            "Integrity verification failed. The password may be incorrect or the container may have been modified.",
        ));
    }

    let mut cipher = StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &container.nonce)
        .map_err(|e| error(format!("Cipher initialization failed: {e:?}")))?;

    cipher
        .process_zeroizing(&container.payload)
        .map_err(|e| error(format!("Decryption failed: {e:?}")))
}

#[cfg(test)]
mod full_pipeline_kat {
    use super::*;

    const PASSWORD: &[u8] = b"ATK-CL full pipeline KAT";
    const SALT_BYTES: [u8; 16] = [0x33; 16];
    const NONCE: [u8; 16] = [0x11; 16];
    const PLAINTEXT: &[u8] = b"ATK-CL full pipeline known answer";

    const EXPECTED_MASTER_KEY: [u8; 32] = [
        0x26, 0x55, 0x0e, 0xd9, 0x5b, 0x50, 0x73, 0xaf, 0xba, 0x68, 0x81, 0x83, 0x63, 0x95, 0x5d,
        0x06, 0x8f, 0xaf, 0x0f, 0x1d, 0xcd, 0x0b, 0xaf, 0xc7, 0x54, 0xe6, 0x8c, 0xf5, 0x55, 0xc5,
        0x72, 0xcc,
    ];

    const EXPECTED_CIPHER_KEY: [u8; 32] = [
        0xbf, 0xf8, 0x1b, 0x9b, 0xeb, 0x39, 0x65, 0xec, 0xeb, 0x4c, 0x35, 0x2b, 0x7b, 0x81, 0x61,
        0x33, 0xc8, 0xbb, 0x6a, 0x7f, 0x6a, 0xd9, 0xbb, 0xdc, 0xec, 0xa2, 0x95, 0x79, 0xc2, 0x61,
        0x57, 0xd3,
    ];

    const EXPECTED_INTEGRITY_KEY: [u8; 32] = [
        0xf5, 0x98, 0xdb, 0x27, 0x5f, 0x5f, 0x4f, 0xee, 0x99, 0xdd, 0x75, 0xe1, 0x5d, 0xa7, 0x82,
        0xb4, 0xbb, 0xf4, 0x7b, 0x3e, 0xf8, 0xa4, 0xdb, 0xb7, 0x65, 0x85, 0xe5, 0x23, 0xf1, 0x92,
        0x42, 0x54,
    ];

    const EXPECTED_CIPHERTEXT: [u8; 33] = [
        0x30, 0x99, 0x9a, 0x56, 0xd8, 0xdb, 0x1d, 0x61, 0xfb, 0x80, 0xe4, 0x14, 0x55, 0xac, 0xba,
        0x73, 0x95, 0x99, 0x45, 0x2d, 0xda, 0x84, 0xf5, 0xc2, 0xe7, 0x49, 0x89, 0x6f, 0x9a, 0x3b,
        0xcd, 0x47, 0x8f,
    ];

    const EXPECTED_TAG: [u8; 32] = [
        0x8f, 0x31, 0xfd, 0xc6, 0xfc, 0x92, 0xe3, 0x9d, 0x8b, 0x8e, 0x4f, 0x33, 0xd0, 0xec, 0x7d,
        0x93, 0x08, 0xf3, 0x93, 0x70, 0x0a, 0x22, 0x3b, 0x95, 0x5b, 0x27, 0x57, 0xc3, 0xa0, 0xb5,
        0xb7, 0x4a,
    ];

    #[test]
    fn atk_full_pipeline_known_answer_001() {
        // ATK-KDF-1
        let password = Password::new(PASSWORD.to_vec()).unwrap();
        let salt = Salt::from_bytes(SALT_BYTES);

        let master_key = derive_key(&password, &salt).unwrap();

        assert_eq!(master_key.as_bytes(), &EXPECTED_MASTER_KEY);

        // ATK-KS-1
        let subkeys = derive_subkeys(&master_key).unwrap();

        assert_eq!(*subkeys.cipher_key, EXPECTED_CIPHER_KEY);
        assert_eq!(*subkeys.integrity_key, EXPECTED_INTEGRITY_KEY);
        assert_ne!(*subkeys.cipher_key, *subkeys.integrity_key);

        // ATK-SC-1
        let mut cipher = StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &NONCE).unwrap();

        let ciphertext = cipher.process(PLAINTEXT).unwrap();

        assert_eq!(ciphertext.as_slice(), EXPECTED_CIPHERTEXT);

        // ATK-INT-1
        let tag = compute_tag(subkeys.integrity_key.as_ref(), &NONCE, &ciphertext).unwrap();

        assert_eq!(tag, EXPECTED_TAG);

        assert!(
            verify_tag(
                subkeys.integrity_key.as_ref(),
                &NONCE,
                &ciphertext,
                &EXPECTED_TAG,
            )
            .unwrap()
        );

        let mut modified = ciphertext.clone();
        modified[0] ^= 0x01;

        assert!(
            !verify_tag(
                subkeys.integrity_key.as_ref(),
                &NONCE,
                &modified,
                &EXPECTED_TAG,
            )
            .unwrap()
        );

        let mut decryptor =
            StreamCipher::from_key_nonce(subkeys.cipher_key.as_ref(), &NONCE).unwrap();

        let decrypted = decryptor.process(&ciphertext).unwrap();

        assert_eq!(decrypted, PLAINTEXT);
    }
}
