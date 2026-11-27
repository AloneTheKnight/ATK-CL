# Container Formats

## Common parameters

| Field | Size |
|---|---:|
| Salt | 16 bytes |
| Nonce | 16 bytes |
| Tag | 32 bytes |
| Maximum payload | 67,108,864 bytes (64 MiB) |

## Standard container — version 1

Binary layout:

| Field | Size | Representation |
|---|---:|---|
| Magic | 8 | `ATKCL` + CR LF + `0x1A` |
| Version | 1 | `0x01` |
| Cipher ID length | 1 | unsigned byte |
| KDF ID length | 1 | unsigned byte |
| Salt length | 1 | unsigned byte; must be 16 in version 1 |
| Payload length | 8 | unsigned 64-bit big-endian |
| Cipher ID | variable | ASCII, 1–32 bytes |
| KDF ID | variable | ASCII, 1–32 bytes |
| Salt | 16 | bytes |
| Nonce | 16 | bytes |
| Payload | variable | ciphertext |
| Tag | 32 | bytes |

Magic bytes:

```text
41 54 4B 43 4C 0D 0A 1A
```

Allowed identifier characters are ASCII `A`–`Z`, `0`–`9`, and `-`. Empty identifiers and identifiers longer than 32 bytes are rejected.

The current implementation uses:
- cipher ID: `ATK-SC-1`;
- KDF ID: `ATK-KDF-1`.

`Container::decode` validates the magic, version, identifier lengths, salt size, maximum payload size, truncated data, and unexpected trailing bytes. The decoded fields are then validated by `Container::new`.

`FORMAT_VERSION` remains `1`.

## Hidden container

Layout:

```text
SALT (16) || NONCE (16) || PAYLOAD (variable) || TAG (32)
```

The hidden container does not contain:
- a magic signature;
- a format version;
- cipher or KDF identifiers;
- a payload-length field.

The payload size is determined from the total input length after subtracting the fixed-size fields. The minimum hidden-container size is 64 bytes (an empty payload). The maximum size is 64 MiB + 64 bytes.

The hidden format has no built-in identification marker. Therefore, arbitrary data may be interpreted as a candidate hidden container if its length is within the accepted range. Format selection and ambiguity handling depend on the calling code.

**The hidden format does not provide stronger cryptographic protection than the standard container and does not guarantee that the existence of data is concealed.** The absence of a header is a serialization property, not a steganographic mechanism.

## Format errors

`FormatError` includes:
- `InvalidMagic`;
- `UnsupportedVersion(u8)`;
- `InvalidIdentifier`;
- `InvalidSaltLength`;
- `InvalidNonceLength`;
- `InvalidTagLength`;
- `InvalidLength`;
- `TruncatedData`;
- `TrailingData`;
- `PayloadTooLarge`.

## Compatibility notes

Changing the container structure, field order, byte order, or algorithm identifiers may prevent previously created files from being read. Do not change the version 1 format without an explicit compatibility decision and corresponding test vectors.
