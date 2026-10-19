//! The verifiable modes of RFC 9497: VOPRF (`modeID = 0x01`) and POPRF
//! (`modeID = 0x02`).
//!
//! [RFC 9497] specifies three variants of an oblivious pseudorandom function
//! over a prime-order group. The base mode (`0x00`) is `Ristretto255Oprf` /
//! `P256Oprf`, behind the `Oprf` trait OPAQUE builds on. This module adds the
//! two verifiable variants:
//!
//! - **VOPRF** (§3.3.2): the server attaches a discrete-log-equivalence (DLEQ)
//!   proof that it evaluated with the key behind its public key `pkS`.
//! - **POPRF** (§3.3.3): a VOPRF with a public input `info` that both parties
//!   know. The output is `F(skS, input, info)`, and the proof is checked
//!   against a key tweaked by `info`.
//!
//! | Suite (feature) | VOPRF types | POPRF types | `Ne` | `Nh` |
//! |---|---|---|---|---|
//! | ristretto255-SHA512 (`ristretto255`) | `Ristretto255Voprf{Server,Client,ClientState}` | `Ristretto255Poprf{Server,Client,ClientState}` | 32 | 64 |
//! | P256-SHA256 (`p256`) | `P256Voprf{Server,Client,ClientState}` | `P256Poprf{Server,Client,ClientState}` | 33 | 32 |
//!
//! The server and client types are the contexts RFC 9497 §3.2 sets up: the
//! server holds `skS`, the client holds `pkS`. Everything crosses the API as
//! bytes: elements are `[u8; Ne]`, scalars and secret keys `[u8; 32]`, proofs
//! `[u8; 64]` (`c || s`, §3.3), and outputs `Zeroizing<[u8; Nh]>`. No curve
//! type appears in a signature, so the curve crates' major versions are not
//! part of this module's API.
//!
//! # Example
//!
#![cfg_attr(feature = "ristretto255", doc = "```")]
#![cfg_attr(not(feature = "ristretto255"), doc = "```ignore")]
//! use pakery_crypto::{Ristretto255PoprfClient, Ristretto255PoprfServer};
//!
//! # fn main() -> Result<(), pakery_crypto::VoprfError> {
//! let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
//!
//! let server = Ristretto255PoprfServer::generate(&mut rng);
//! let client = Ristretto255PoprfClient::new(&server.public_key())?;
//!
//! let info = b"example-app/v1 epoch=42";
//! let (state, blinded) = client.blind(b"private input", info, &mut rng)?;
//! let (evaluated, proof) = server.blind_evaluate(&blinded, info, &mut rng)?;
//! let output = client.finalize(&state, b"private input", info, &evaluated, &proof)?;
//!
//! // The server, knowing the input, computes the same value without the
//! // round trip.
//! assert_eq!(*output, *server.evaluate(b"private input", info)?);
//! # Ok(())
//! # }
//! ```
//!
//! # Protocol notes
//!
//! - **`info` (POPRF).** RFC 9497 §5.4: the public input "is known to both
//!   parties at the start of the protocol", and it is RECOMMENDED to give it
//!   higher-level domain separation, such as a unique, prefix-free encoding.
//!   The client's state keeps the tweaked key that `blind` derived from it,
//!   as §3.3.3 has the client do, and `finalize` must be given the same `info`.
//!   A server that evaluated under another `info` fails as `Verify`.
//! - **The input.** `finalize` takes the input again, as RFC 9497 does, and
//!   checks it against the one the state was blinded with: the proof covers
//!   neither the input nor the client's tweaked key, so without these checks
//!   a caller's mistake would yield a wrong output or a misleading `Verify`.
//!   It surfaces as `InputMismatch` instead, which leaves `Verify` meaning one
//!   thing: the server's response does not verify.
//! - **Batches.** A server can evaluate several blinded elements with one
//!   proof (§3.3.2, §3.3.3); a POPRF batch shares one `info`. The client
//!   finalizes the batch with the states, inputs and evaluated elements in
//!   the order the blinded elements were sent. At most 65535 elements.
//! - **Lengths.** Inputs and `info` are at most 65535 bytes, the most their
//!   two-byte length prefix encodes. §1.2 says "no larger than 2^16 - 1
//!   bytes" and §5.1 "MUST be smaller than 2^16 - 1 bytes"; the bound taken is
//!   the encodable one.
//! - **Errors.** [`VoprfError`] names RFC 9497's errors and the two limits
//!   above.
//!
//! # Deterministic blinding (hazmat)
//!
//! With the `hazmat` feature, each client also offers `deterministic_blind`,
//! which takes the blind as 64 bytes instead of drawing it from a generator.
//! The bytes are reduced modulo the group order — as a little-endian integer
//! for ristretto255, big-endian for P-256 — and rejected if that gives zero.
//! RFC 9497 draws the blind at random; a caller that chooses it takes on this
//! contract:
//!
//! - **Derive the bytes with a PRF under a key only the client holds.** For
//!   example HMAC-SHA-512 under a secret of at least 128 bits, over a context
//!   that names the suite, the mode, the server's public key and (for the
//!   POPRF) the `info`, followed by the input. Never derive the blind from the
//!   input or other public or server-known data alone: anyone holding the
//!   transcript could then test guesses for the input offline.
//! - **Never use the same bytes for two different inputs**, and supply 64
//!   uniform bytes, not 32 zero-padded ones.
//! - **Repeated requests are linkable, by design.** The same `(input, blind)`
//!   always yields the same blinded element, and in the POPRF the blinded
//!   element does not depend on `info`: put `info` in the PRF context if
//!   requests under different `info` must stay unlinkable.
//! - **Input secrecy becomes computational.** RFC 9497 §7.1 promises that "the
//!   server does not learn anything about the client input x, even with
//!   unbounded computation". With a derived blind that rests instead on the
//!   PRF and its key. An adversary who can compute discrete logs still cannot
//!   link or open requests without that key; anyone who later learns the key
//!   can recompute every past blind and test input guesses against every
//!   recorded blinded element, with no group assumption broken. Protect the
//!   key like a long-term secret.
//! - **Repetition helps physical side channels.** The same `(input, blind)`
//!   repeats the same secret scalar multiplication, which an attacker
//!   measuring power or electromagnetic emanations can average; random blinds
//!   avoid this.
//!
//! # Security considerations
//!
//! - **One key per mode, suite and application.** A blinded element carries no
//!   mode, so a server that evaluates with the same scalar in two modes —
//!   or with the scalar of an OPAQUE OPRF key — gives each an evaluation
//!   oracle for the other, bypassing whatever rate limit guards it.
//!   `derive` yields different keys per mode from the same seed;
//!   `from_secret_key` cannot enforce this, so do not import one key into two
//!   contexts.
//! - **Key consistency.** Verifiability means the output is correct with
//!   respect to the key the server committed to (§7.1). A server that gives
//!   different clients different public keys can tell them apart, so clients
//!   should obtain `pkS` through a channel where they can compare it.
//! - **What the security analysis covers.** The VOPRF's pseudorandomness,
//!   input secrecy and verifiability are proven in [JKK14] "for one instance
//!   (i.e., one key) of the VOPRF protocol and without batching"; RFC 9497
//!   §7.2.1 states that no analysis covers multiple server keys or batching.
//!   The POPRF rests on the One-More Gap Strong Diffie-Hellman Inversion
//!   assumption (§7.2.2).
//! - **Static Diffie-Hellman oracle.** Each evaluation a client obtains is a
//!   static Diffie-Hellman sample; Q of them reduce the group's security by
//!   about log2(Q)/2 bits (§7.2.3). Rate-limit evaluations or rotate keys.
//!   RFC 9497 §4 asks applications to take caution with the 128-bit-security
//!   suites, which both of these are.
//! - **Quantum adversaries.** Verifiability and pseudorandomness rest on
//!   discrete-logarithm-type assumptions (§7.2.2 reduces both POPRF
//!   assumptions to q-DL in the algebraic group model). An adversary able to
//!   compute discrete logs can recover `skS` from `pkS` and then compute or
//!   forge any evaluation. It cannot recover inputs blinded with random
//!   blinds: that secrecy is unconditional (§7.1).
//! - **Hedged proof nonce.** RFC 9497 §2.2.1 draws the DLEQ proof's nonce `r`
//!   with `RandomScalar`. Two proofs that share `r` reveal the key — in the
//!   POPRF even under different `info` — and a plain random draw repeats
//!   whenever the generator does: after a fork, a VM snapshot restore, or with
//!   a seeded or cloned generator. Following RFC 9591 §4.1, this crate derives
//!   `r` by hashing 32 fresh random bytes together with the secret key and the
//!   whole statement under the tag `"pakery-DLEQNonce-" || contextString`.
//!   Distinct statements then get distinct nonces even if the generator
//!   repeats. The proofs are ordinary RFC 9497 proofs; a verifier cannot tell
//!   how `r` was chosen.
//! - **Constant time.** Every operation on secret data — the key, the tweaked
//!   key and its inverse, the blind and its inverse, the proof nonce, the
//!   input and the unblinded element — uses constant-time group and scalar
//!   arithmetic, as §7.4 requires; P-256 elements are encoded with a
//!   constant-time encoder rather than through the SEC1 crate, whose
//!   compression branches on the point. Proof verification handles only
//!   public data and uses the same constant-time operations.
//! - **Zeroization.** Secret keys and client states are wiped on drop, and
//!   intermediate secrets (tweaked keys, inverses, nonces, unblinded elements,
//!   hashed inputs) live in `Zeroizing` buffers. Scalars and points of the
//!   underlying curve crates are `Copy`, so wiping is best-effort.
//!
//! [RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497
//! [JKK14]: https://doi.org/10.1007/978-3-662-45608-8_13

mod api;
mod error;
mod protocol;
#[cfg(feature = "p256")]
mod suite_p256;
#[cfg(feature = "ristretto255")]
mod suite_ristretto255;
#[cfg(test)]
mod test_macros;
#[cfg(test)]
mod test_vectors;

pub use error::VoprfError;
#[cfg(feature = "p256")]
pub use suite_p256::{
    P256PoprfClient, P256PoprfClientState, P256PoprfServer, P256VoprfClient, P256VoprfClientState,
    P256VoprfServer,
};
#[cfg(feature = "ristretto255")]
pub use suite_ristretto255::{
    Ristretto255PoprfClient, Ristretto255PoprfClientState, Ristretto255PoprfServer,
    Ristretto255VoprfClient, Ristretto255VoprfClientState, Ristretto255VoprfServer,
};
