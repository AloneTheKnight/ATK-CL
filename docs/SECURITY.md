# Security and Limitations

## Status

**ATK-CL 0.1.0 is experimental. Its custom cryptographic algorithms have not undergone independent cryptanalysis.**

Do not use this version for:
- storing passwords, keys, or valuable secrets;
- protecting personal, financial, medical, or corporate data;
- production systems;
- situations where data compromise could cause harm.

For real data protection, use established cryptographic libraries and widely analyzed standard AEAD and KDF constructions.

## What the tests demonstrate

The project tests cover:
- deterministic behavior of specific implementations;
- matching the embedded known-answer vectors;
- handling of boundary lengths and malformed inputs;
- encryption/decryption round trips;
- detection of modified data by the implemented tag;
- structural validation of containers.

They do **not** prove:
- resistance to known or unknown cryptographic attacks;
- absence of cryptographic weaknesses;
- security of the chosen parameters;
- correctness on every compiler and architecture;
- constant-time behavior;
- system-wide key-generation security.

## Passwords and KDF

`Password` rejects empty values and zeroizes its internal buffer when dropped. `ATK-KDF-1` uses a 16-byte salt and 1000 iterations of a custom transformation.

The current code does not provide a configurable KDF cost, memory cost, or parallelism setting. This algorithm must not be considered equivalent to or a replacement for Argon2id, scrypt, or PBKDF2. Do not use weak or reused passwords.

## Salt and nonce

The salt and nonce are generated through `getrandom`:
- salt: 16 bytes;
- nonce: 16 bytes.

They are stored in the container and are not secret. Security depends on the quality of the system random source and correct algorithm usage; the fact that `getrandom` is called does not prove the security of the overall construction.

## Integrity and operation order

The standard and hidden decryption workflows verify the tag before decryption. The tag is computed using the integrity key, nonce, and ciphertext. This must not be interpreted as proof of a correct AEAD construction: the scheme is custom and has not been independently reviewed.

`verify_tag` accumulates XOR differences across the tag bytes. Strict constant-time execution cannot be inferred from this source code alone.

## Memory zeroization

The project uses `zeroize` and `Zeroizing` for a number of secret buffers. This reduces the likelihood that some secrets remain in managed buffers after those buffers are released. It does not guarantee:
- removal of every temporary copy;
- removal of copies created by calling code;
- clearing of CPU registers, swap, crash dumps, or paging files;
- protection against a malicious process reading memory;
- secure erasure of input or output files.

Public methods returning ordinary `Vec<u8>` or `String` values do not automatically zeroize their contents.

## Standard and hidden containers

The standard container exposes algorithm identifiers, format version, salt, nonce, and payload length.

The hidden container has no magic signature or version. It is not steganography and does not guarantee plausible deniability. Data may still be recognized or tested against format hypotheses, and format selection may be ambiguous.

## Error handling

For standard containers, error messages may distinguish unsupported identifiers, invalid sizes, and integrity-verification failure. Hidden-container decryption collapses errors into the generic message `Decryption failed.`. This should not be interpreted as eliminating all side channels.

## Reporting issues

Because the project is experimental, do not include real secrets, keys, or sensitive files when reporting an issue. Use synthetic data and test vectors for reproduction.
