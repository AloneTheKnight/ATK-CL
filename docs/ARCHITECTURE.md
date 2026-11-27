# ATK-CL Architecture

## Overview

ATK-CL is organized into an application layer, a cryptographic core, a container-format layer, and supporting input/output utilities.

```text
src/
├── main.rs
├── lib.rs
├── cli/
├── core/
│   ├── cipher/
│   ├── integrity/
│   ├── key/
│   │   ├── kdf/
│   │   └── research/
│   └── crypto.rs
├── format/
├── io/
└── utils/
```

## Entry points

`src/main.rs` calls `atk_cl::cli::menu::run()`. The library entry point, `src/lib.rs`, publicly exports `cli`, `core`, `format`, `io`, and `utils`.

## Layers

### CLI

The `cli` module contains interactive workflows:
- `menu.rs` — main menu and version/status information;
- `encrypt.rs`, `decrypt.rs` — encryption and decryption workflows;
- `key_management.rs` — password and salt management;
- `research.rs` — research menu;
- `save.rs` — saving results.

The CLI uses lower-level modules; it is not itself the cryptographic algorithm.

### Core

`core::crypto` connects the components into complete workflows.

Standard-container encryption performs the following operations:
1. Rejects input larger than the maximum payload size.
2. Generates a 16-byte salt and a 16-byte nonce using `getrandom`.
3. Derives a master key using `derive_key`.
4. Separates the master key into encryption and integrity keys using the internal `derive_subkeys` function.
5. Encrypts the data using `StreamCipher`.
6. Computes an integrity tag over the nonce and ciphertext.
7. Creates a `Container` with the `ATK-SC-1` and `ATK-KDF-1` identifiers.

Decryption:
1. Validates the container identifiers and field sizes.
2. Derives the master key and subkeys again.
3. Verifies the integrity tag before decryption.
4. Only after successful verification, processes the ciphertext through the stream cipher.

The hidden-container workflow uses the same cryptographic processing, but a different serialization layout without public algorithm identifiers.

### Cipher

`core::cipher` contains:
- `state.rs` — a state of 16 `u32` words (64 bytes);
- `initialization.rs` — converts a key and nonce into the initial state;
- `arx.rs`, `transform.rs` — ARX operations;
- `permutation.rs`, `round.rs` — permutation and repeated rounds;
- `keystream.rs` — generates 64-byte keystream blocks;
- `stream.rs` — XORs input data with the keystream.

### Integrity

`core::integrity` implements a separate state, ARX transformations, a permutation, and the `compute_tag` / `verify_tag` functions. The tag is 32 bytes long.

### Key

`core::key` contains:
- `Password` — a non-empty password represented as bytes;
- `Salt` — a 16-byte salt;
- `derive` and `kdf` — derivation of a 32-byte master key;
- `key_separation.rs` — internal separation of the master key into two subkeys;
- `research` — measurement and statistical tools.

`derive_subkeys` is `pub(crate)`, so it is not part of the public API for external crates.

### Format

`format::Container` serializes the standard container with a signature and version. `format::HiddenContainer` serializes a compact container without a signature, version, or algorithm identifiers. Both formats limit the payload to 64 MiB.

### IO and Utils

`io::file` provides file reading and writing, including bounded reads and temporary-file-based writes for selected operations. `utils::encoding` implements HEX and standard Base64 encoding/decoding.

## Dependency direction

At a high level, the CLI uses Core, Format, and IO. `core::crypto` uses Cipher, Integrity, Key, and Format. Format does not perform cryptographic operations; it validates structure and serializes fields.

## Sensitive-data handling

The implementation uses `zeroize` and `Zeroizing` for a number of secret buffers and states. `Password`, `KeyMaterial`, `CipherState`, `IntegrityState`, and the stream cipher's current block have cleanup behavior on drop. This is best-effort memory hygiene, not a guarantee that every copy is removed from memory, CPU registers, swap, crash dumps, or backups.
