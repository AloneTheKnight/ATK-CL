# Public API

This document lists the main public entry points in version 0.1.0. The source code and generated rustdoc remain the definitive API contract.

## Encryption

Module: `atk_cl::core::crypto`

```rust
pub fn encrypt(
    data: &[u8],
    password: &Password,
) -> Result<Container, CryptoError>;

pub fn decrypt(
    container: &Container,
    password: &Password,
) -> Result<Vec<u8>, CryptoError>;

pub fn decrypt_zeroizing(
    container: &Container,
    password: &Password,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;

pub fn encrypt_hidden(
    data: &[u8],
    password: &Password,
) -> Result<HiddenContainer, CryptoError>;

pub fn decrypt_hidden_zeroizing(
    container: &HiddenContainer,
    password: &Password,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;
```

`decrypt` is retained as an API that returns a regular `Vec<u8>`. Prefer `decrypt_zeroizing` when the plaintext buffer should be zeroized when dropped. In this version, the public hidden-container decryption function returns `Zeroizing<Vec<u8>>`.

## Password and salt

Module `atk_cl::core::key::password`:

```rust
pub struct Password { /* private fields */ }

impl Password {
    pub fn read() -> std::io::Result<Self>;
    pub fn new(value: Vec<u8>) -> std::io::Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
```

An empty password is rejected. `Password::read` prompts for a password using `rpassword`. When dropped, the internal password vector is zeroized.

Module `atk_cl::core::key::salt`:

```rust
pub const SALT_SIZE: usize = 16;

pub struct Salt { /* private fields */ }

impl Salt {
    pub fn generate() -> Result<Self, getrandom::Error>;
    pub fn from_bytes(bytes: [u8; SALT_SIZE]) -> Self;
    pub fn as_bytes(&self) -> &[u8; SALT_SIZE];
}
```

## KDF

Module `atk_cl::core::key::derive`:

```rust
pub struct KeyMaterial { /* private fields */ }

impl KeyMaterial {
    pub fn as_bytes(&self) -> &[u8; 32];
}

pub fn derive_key(
    password: &Password,
    salt: &Salt,
) -> Result<KeyMaterial, KdfError>;
```

`KeyMaterial::from_bytes` is not public to external crates. `derive_subkeys` is also crate-private and is not exported for external consumers.

## Stream cipher

The `atk_cl::core::cipher` module re-exports `StreamCipher`.

```rust
pub struct StreamCipher { /* private fields */ }

impl StreamCipher {
    pub fn new(state: CipherState) -> Self;
    pub fn from_key_nonce(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError>;
    pub fn process(&mut self, input: &[u8]) -> Result<Vec<u8>, StreamCipherError>;
    pub fn position(&self) -> usize;
}
```

`process` mutates the object state and continues the current stream across calls. To decrypt, create a new `StreamCipher` with the same key and nonce. `process` returns a regular `Vec<u8>`; the lower-level zeroizing variant is `pub(crate)`.

## Containers

The `atk_cl::format` module re-exports `Container`, `FormatError`, and `HiddenContainer`.

Standard container:

```rust
pub struct Container {
    pub cipher_id: String,
    pub kdf_id: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    pub tag: Vec<u8>,
}

impl Container {
    pub fn new(
        cipher_id: String,
        kdf_id: String,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        payload: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Self, FormatError>;

    pub fn encode(&self) -> Result<Vec<u8>, FormatError>;
    pub fn decode(data: &[u8]) -> Result<Self, FormatError>;
}
```

The hidden container has public `salt`, `nonce`, `payload`, and `tag` fields, with `new`, `encode`, and `decode` methods that perform corresponding size validation.

Container fields are public and can be modified after construction. `encode` revalidates structural constraints. The cryptographic layer checks whether the algorithm identifiers are supported during decryption.

## Encoding

Module `atk_cl::utils::encoding`:

```rust
pub fn to_hex(data: &[u8]) -> String;
pub fn from_hex(input: &str) -> Result<Vec<u8>, EncodingError>;
pub fn from_hex_zeroizing(input: &str)
    -> Result<zeroize::Zeroizing<Vec<u8>>, EncodingError>;

pub fn to_base64(data: &[u8]) -> String;
pub fn from_base64(input: &str) -> Result<Vec<u8>, EncodingError>;
pub fn from_base64_zeroizing(input: &str)
    -> Result<zeroize::Zeroizing<Vec<u8>>, EncodingError>;

pub fn format_both(data: &[u8]) -> zeroize::Zeroizing<String>;
```

HEX output uses uppercase letters. The HEX decoder ignores whitespace. Base64 uses the standard Base64 alphabet and also removes whitespace before decoding.

## File IO

Module `atk_cl::io::file` contains:
- `read_file(path: &str) -> io::Result<Vec<u8>>`;
- `read_file_limited(path: &str, max_size: usize) -> io::Result<Zeroizing<Vec<u8>>>`;
- `paths_refer_to_same_file(input: &str, output: &str) -> io::Result<bool>`;
- `write_file_new(path: &str, data: &[u8]) -> io::Result<()>`;
- `write_file_replace(path: &str, data: &[u8]) -> io::Result<()>`;
- `write_file(path: &str, data: &[u8]) -> io::Result<()>`.

`write_file_new` does not overwrite an existing file. `write_file_replace` performs replacement through a temporary file. `write_file` directly calls `fs::write` and has different write semantics.

## Version

`atk_cl::core::LIBRARY_VERSION` contains the Cargo package version (`0.1.0`).
