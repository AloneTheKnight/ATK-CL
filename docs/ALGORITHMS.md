# ATK-CL Algorithms

This document describes the behavior implemented in the version 0.1.0 source code. It is an implementation description, not an independently reviewed cryptographic specification or a claim of security.

## Identifiers

| Identifier | Purpose |
|---|---|
| `ATK-SC-1` | Stream encryption |
| `ATK-KDF-1` | Password-and-salt-based master-key derivation |
| `ATK-INT-1` | Integrity-tag generation and verification |
| `ATK-KS-1` | Separation of the master key into subkeys |

## ATK-SC-1 — Stream transformation

Parameters:
- key: 32 bytes;
- nonce: 16 bytes;
- state: 16 `u32` words, 64 bytes total;
- keystream block: 64 bytes;
- number of rounds: 10.

### Initialization

`initialize_state` validates the key and nonce lengths, concatenates them into a 48-byte buffer, and interprets consecutive 4-byte chunks as little-endian `u32` words. The 12 resulting words occupy the first 48 bytes of the 64-byte state; the remaining 16 bytes of the state are zero-initialized.

### ARX transformation

Operations on 32-bit words:
- addition modulo \(2^{32}\);
- XOR;
- left rotation.

For a four-word tuple `a, b, c, d`, the rotation amounts are 16, 12, 8, and 7 bits, respectively.

### Permutation and keystream

One permutation applies four column tuples followed by four diagonal tuples. `apply_rounds` repeats the permutation 10 times.

The generator copies the initial state, XORs the low and high 32-bit halves of a 64-bit counter into state words 14 and 15, performs 10 rounds, and serializes the state into a 64-byte little-endian block. The counter advances after each block.

`StreamCipher` XORs input bytes with the bytes of these blocks. A single `StreamCipher` instance preserves its position across successive `process` calls. To independently encrypt or decrypt a stream, create a new instance with the same key and nonce.

The stream transformation is symmetric: applying the same keystream to ciphertext recovers the original bytes.

## ATK-KDF-1 — Key derivation

Parameters defined in the source:
- salt: 16 bytes;
- output master key: 32 bytes;
- input block size: 64 bytes;
- rounds per block processing: 10;
- additional iterations: 1000.

`process_password` copies the password bytes, and `process_salt` copies the salt. The KDF input is constructed as:

```text
"ATK-KDF-1"
|| password_length_u64_le
|| password_bytes
|| salt_bytes
```

A fixed 16-word initial state is then used. Each 64-byte input block is XORed into the state words (the final partial fragment is copied into a local 4-byte buffer padded with zeroes), the block index is XORed into word 15, and 10 rounds are performed. After input processing, 1000 additional iterations are executed: the iteration number is XORed into word 0, its 16-bit left rotation into word 15, and then 10 rounds are performed. The first 32 bytes of the little-endian serialized state become the master key.

**Important:** `process_password` does not perform separate password hashing, Unicode normalization, or password stretching before the KDF. This construction must not be considered equivalent to Argon2, scrypt, PBKDF2, or another standard password KDF.

## ATK-KS-1 — Key separation

Key separation is an internal implementation component (`pub(crate)`). It derives two 32-byte keys from one master key using different domain strings:
- `ATK-SC-1-KEY`;
- `ATK-INT-1-KEY`.

Each domain input contains:

```text
"ATK-KS-1"
|| domain_length_u64_le
|| domain
|| master_key
```

A fixed 16-word initial state is used, with 10 rounds for each input block and 1000 additional iterations that modify state words 0 and 15. The first 32 bytes of the serialized state become the corresponding subkey.

## ATK-INT-1 — Integrity tag

Parameters:
- key: 32 bytes;
- nonce: 16 bytes;
- absorption block size: 32 bytes;
- tag: 32 bytes;
- permutation: 10 rounds, each using column and diagonal ARX phases.

The initial state XORs the key into words 0–7 and the nonce into words 8–11, then XORs the domain marker `0x41544B31` into word 15 and performs a permutation.

Data is processed in 32-byte blocks. A partial block is padded with `0x80`; empty input and input whose length is an exact multiple of 32 bytes receive a separate final block with `0x80` in its first byte. During absorption, each block is interpreted as eight little-endian words and XORed into state words 0–7; the block counter is XORed into words 14 and 15. After data absorption, the data length is XORed into words 12 and 13, and marker `0x494E5431` into word 14. Two final permutations are performed; the first 32 bytes of the serialized state form the tag.

`verify_tag` rejects tags of an incorrect length and compares the 32 bytes by accumulating XOR differences. This source code alone does not prove constant-time execution on all compilers and processors.

## Complete pipeline

For a standard container:
1. Generate a random salt and nonce.
2. `ATK-KDF-1` derives the master key.
3. `ATK-KS-1` derives the encryption and integrity keys.
4. `ATK-SC-1` produces the ciphertext.
5. `ATK-INT-1` computes a tag using the integrity key, nonce, and ciphertext.
6. Serialize the container.

During decryption, the tag is verified before the ciphertext is decrypted.

## Test vectors

The project contains known-answer tests for components and the complete pipeline, as well as block-boundary and round-trip tests. These tests pin the output of the current implementation. They are not independent confirmation of cryptographic correctness.
