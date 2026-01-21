# CryptoEng_W2526_RustCode
Example code for [Cryptography Engineering](https://runzhizeng.github.io/CE-w2526/)

- Lecture 1: SHA3-256, HMAC, HKDF, AEAD demo.
- Lecture 2: Parse information from a certificate, Diffie-Hellman key exchange + HKDF + AEAD.
- Lecture 3: HKDF-Extract-Expand demo, signature demo, and ECDSA demo (for implementing the nonce-reuse attack).
- Lecture 4: DHIES demo (based on x25519-dalek).
- Lecture 10:
  - Offline dictionary attacks, including the provided dictionary and Rust/Python code to compute the hashed password.
  - Rust/Python programs for hash-to-curve operations (for implementing the DH-based OPRF in OPAQUE). If you are using Python, please use P-256 to implement your OPAQUE program.
  - Important note: The Python hash2curve program is **not** a secure implementation. **DO NOT** use it in any real-world system. The Rust version is a thin wrapper around the standard [hash2curve crate](https://docs.rs/hash2curve/latest/hash2curve/) and should be safe to use.

## Notes
- First, run `cargo test` to ensure everything compiles and all tests pass.
- Then, run `cargo run` to see the demo.
- If any dependency is missing, refer to the comments in the code, which may indicate how to install it.