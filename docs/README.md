# ATK-CL

**Alone The Knight's Crypto Lib** is an experimental cryptographic library written in Rust.

- Package version: `0.1.0`
- Rust edition: 2024
- Algorithm identifiers: `ATK-SC-1`, `ATK-KDF-1`, `ATK-INT-1`, `ATK-KS-1`
- Status: **Experimental — Not cryptographically validated**

> **Security warning:** ATK-CL implements custom cryptographic constructions. They have not undergone independent cryptanalysis and must not be used to protect real secrets, critical data, or production systems. Tests and known-answer vectors demonstrate reproducibility of the implementation; they do not establish cryptographic security.

## Features

- Stream encryption using the custom `ATK-SC-1` keystream generator.
- Password-based master-key derivation using `ATK-KDF-1`.
- Master-key separation into encryption and integrity keys using `ATK-KS-1`.
- 32-byte integrity tag generation and verification using `ATK-INT-1`.
- A standard container with a signature, version, and algorithm identifiers.
- A hidden container without a signature or algorithm identifiers.
- CLI workflows for encryption, decryption, key management, and research.
- HEX and Base64 encoding utilities.

## Build and run

A Rust toolchain supporting Edition 2024 is required.

```bash
cargo build --release
cargo run --release
```

The application starts an interactive CLI menu.

## Using ATK-CL as a library

Add the local crate as a dependency:

```toml
[dependencies]
atk-cl = { path = "../atk-cl" }
```

Minimal encryption/decryption example:

```rust
use atk_cl::core::crypto::{decrypt_zeroizing, encrypt};
use atk_cl::core::key::password::Password;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = Password::new(b"example password".to_vec())?;

    let plaintext = b"Example data";
    let container = encrypt(plaintext, &password)?;

    let encoded = container.encode()?;
    let decoded = atk_cl::format::Container::decode(&encoded)?;

    let recovered = decrypt_zeroizing(&decoded, &password)?;
    assert_eq!(&recovered[..], plaintext);

    Ok(())
}
```

`decrypt_zeroizing` returns `zeroize::Zeroizing<Vec<u8>>`, so the plaintext buffer is zeroized when the value is dropped. A compatibility function named `decrypt` is also available and returns a regular `Vec<u8>`; its contents are not automatically zeroized on drop.

The hard-coded password above is for demonstration only. Do not store real passwords in source code, command-line arguments, or logs.

## Main modules

| Module | Purpose |
|---|---|
| `core::cipher` | Cipher state, rounds, keystream generation, and `StreamCipher` |
| `core::integrity` | Integrity state and tag generation/verification |
| `core::key` | Password, salt, KDF, key material, and research tools |
| `core::crypto` | Complete encryption and decryption workflows |
| `format` | Standard and hidden containers |
| `io` | File and console input/output |
| `utils::encoding` | HEX and Base64 utilities |

See [ARCHITECTURE.md](ARCHITECTURE.md), [ALGORITHMS.md](ALGORITHMS.md), [FORMAT.md](FORMAT.md), [API.md](API.md), and [SECURITY.md](SECURITY.md) for details.

## Format limits

- Maximum payload size: 64 MiB (`67,108,864` bytes).
- Salt size: 16 bytes.
- Nonce size: 16 bytes.
- Tag size: 32 bytes.
- Standard container format version: `1`.

## Project checks

```bash
cargo fmt --all -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo check --release
```

The test suite includes primitive tests, known-answer vectors, encryption round trips, container validation, KDF, integrity, and research-tool tests. These tests are not a substitute for independent cryptanalysis.

---

> **Disclaimer:** This project was developed as a homework assignment and is not an official or production-ready cryptographic library.
>
> The **Research Lab** was an experimental feature developed for testing purposes. It was initially implemented manually and later completed with the assistance of a neural network.
>
> The **DOCS** files were generated using AI.
>
> AI assistance was used only for non-essential components that do not participate in cryptographic operations. This was primarily due to time constraints, as the entire project had to be completed within a one-week deadline. AI-generated parts have not been thoroughly reviewed, so their correctness is not guaranteed.