# Iteration 6 Remote Crypto Codec Dispatch

Status: M2 CODEC CONTRACT

## Scope

M2 proves cross-language encryption/decryption only. It does not persist private
keys, expose a browser route, publish to Relay, or authorize an Agent command.

## Keys and identities

- Each Host and Device has a separate P-256 ECDSA signing keypair and P-256 ECDH
  agreement keypair. A key is never reused between signing and agreement.
- Public keys use uncompressed SEC1 points: exactly 65 bytes, prefix `0x04`.
- Private keys exist only in the owning endpoint. Test vectors may use fixed
  private scalars and must be clearly labelled non-production.
- Device registry v2 will persist SHA-256 commitments for both device public
  keys. A remote envelope supplies the public keys; Host recomputes and compares
  commitments before signature verification or ECDH.

## Key derivation

ECDH yields the 32-byte P-256 shared secret.

```text
salt = SHA-256(
  "nomad.remote-envelope.salt.v2\n" ||
  mailbox_id || "\n" ||
  host_signing_key_commitment || "\n" ||
  host_agreement_key_commitment || "\n" ||
  device_signing_key_commitment || "\n" ||
  device_agreement_key_commitment || "\n" ||
  decimal_epoch
)
info = "nomad.remote-envelope.key.v2\n" || direction
key = HKDF-SHA-256(shared_secret, salt, info, 32)
```

Host and Device derive separate `host_to_device` and `device_to_host` keys.
Epoch change always changes keys.

## Nonce, plaintext and encryption

- AES-256-GCM nonce is deterministic and validated:
  - bytes `0..4`: `SHA-256("nomad.remote-envelope.nonce.v2\n" || direction)[0..4]`
  - bytes `4..12`: unsigned 64-bit big-endian sequence
- A nonce from the wire must equal the derived nonce. Sequence allocation is
  durable and strictly increasing before encryption; retry reuses the exact
  canonical frame bytes rather than encrypting again.
- Application plaintext is canonical UTF-8 JSON, max 32 KiB. Encrypted plaintext
  is binary: 4-byte big-endian JSON length, JSON bytes, then random padding.
- Total padded plaintext length is the smallest bucket in
  `[512, 2048, 8192, 32768, 65536]` that fits. Decryption rejects unknown bucket
  lengths, invalid length prefix, non-UTF-8,
  non-canonical JSON, duplicate/unknown application fields, and invalid GCM tag.
- AAD is the exact frozen v2 frame metadata from the Relay contract. Ciphertext
  is AES-GCM ciphertext plus 16-byte tag, encoded base64url without padding.
- Sender signs `SHA-256(AAD || aes_gcm_ciphertext_and_tag)` with its P-256 ECDSA
  signing key using IEEE-P1363 fixed 64-byte `r || s`. The Relay `ciphertext`
  bytes are one opaque binary sealed packet: version byte `0x01`, sender signing
  public key (65 bytes), sender agreement public key (65 bytes), signature (64
  bytes), then AES-GCM ciphertext and tag. Relay validates only total size and
  base64url syntax; it never parses this packet. The receiver parses it, compares
  both public-key commitments with paired state, derives the direction key,
  verifies the signature, and only then releases decrypted canonical JSON.

## Owned implementation packages

M2-Rust owns new `connector/src/remote_crypto.rs`, crate-private module
registration, minimal dependencies, and Rust vectors/tests.

M2-Web owns new `mobile-reference/src/remote/crypto.ts` and tests. It uses native
WebCrypto only and keeps private `CryptoKey` values non-extractable in runtime.

Both implementations consume one checked-in content-safe vector JSON under
`contracts/vectors/remote-envelope-v2.json`. The vector contains only fixed test
keys and the literal marker `TEST_ONLY_VECTOR`, never a runtime credential.

## Required tests

- Rust encrypt -> Web decrypt, Web encrypt -> Rust decrypt; exact shared secret,
  salt, direction keys, nonce, AAD, ciphertext and P1363 signature vectors.
- Direction, epoch, mailbox, identity commitment, sequence, nonce, ciphertext,
  tag and signature mutation each fails closed.
- Same tuple produces identical output only when the exact vector randomness and
  padding are reused; production APIs require caller-owned durable sequence.
- Oversize, invalid padding bucket, length prefix, UTF-8 and non-canonical JSON
  fail closed.
- Key and plaintext canaries do not appear in frame metadata, errors, debug, or
  Relay persistence fixtures.

Only after Rust and Web vectors agree may M3 connect these codecs to Relay v2.
