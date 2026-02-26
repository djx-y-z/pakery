## [0.1.0] - 2026-02-26

### Added

- `pakery-core`: shared cryptographic trait abstractions (`Hash`, `Kdf`, `Mac`, `CpaceGroup`, `DhGroup`, `Oprf`, `Ksf`)
- `pakery-cpace`: CPace balanced PAKE protocol (draft-irtf-cfrg-cpace)
- `pakery-opaque`: OPAQUE augmented PAKE protocol (RFC 9807)
- `pakery-spake2`: SPAKE2 balanced PAKE protocol (RFC 9382)
- `pakery-spake2plus`: SPAKE2+ augmented PAKE protocol (RFC 9383)
- `pakery-crypto`: concrete implementations for Ristretto255 and P-256 cipher suites
- Ristretto255 / SHA-512 cipher suite support
- P-256 / SHA-256 cipher suite support
- Argon2id key-stretching function support for OPAQUE
- Custom RFC 9497 OPRF implementation (Ristretto255 and P-256)
- `no_std` support across all crates (no heap allocation required)
- WASM (`wasm32-unknown-unknown`) support
- RFC test vector validation for all protocols
- Constant-time operations via `subtle`
- Secret zeroization via `zeroize`
