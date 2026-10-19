//! Generators for the public per-suite types.
//!
//! Each macro emits a server, a client and a client-state type for one
//! ciphersuite. Every method delegates to `protocol` and carries no logic of
//! its own: cargo-mutants does not mutate macro bodies, so a branch placed
//! here would be untested by construction. The array sizes are spelled as
//! literals so rustdoc shows `[u8; 32]` rather than a projection through a
//! private trait; they are checked against the suite's `VoprfGroup` constants
//! by the type checker, because each method returns the core's type.

/// The VOPRF (mode `0x01`) types of one ciphersuite.
macro_rules! voprf_types {
    (
        suite: $suite:literal,
        group: $group:ty,
        ne: $ne:literal,
        nh: $nh:literal,
        server: $server:ident,
        client: $client:ident,
        state: $state:ident $(,)?
    ) => {
        #[doc = concat!("The server of the RFC 9497 VOPRF (mode `0x01`) for ", $suite, ": the context `SetupVOPRFServer` creates, holding `skS`.")]
        ///
        /// The secret key is zeroized on drop. A zeroized server refuses to
        /// evaluate ([`VoprfError::Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize))
        /// rather than act as the zero key.
        ///
        /// See the [module documentation](crate::verifiable_oprf) for the
        /// protocol and its security considerations.
        pub struct $server($crate::verifiable_oprf::protocol::ServerCore<$group>);

        impl $server {
            /// `GenerateKeyPair` (RFC 9497 §3.2): a fresh random key.
            pub fn generate(rng: &mut impl ::rand_core::CryptoRng) -> Self {
                Self($crate::verifiable_oprf::protocol::ServerCore::generate(rng))
            }

            /// `DeriveKeyPair(seed, info)` (RFC 9497 §3.2.1) under the VOPRF
            /// context string.
            ///
            /// The key is a secret only as long as `seed` is: it must come
            /// from a CSPRNG. `info` is public. The same seed derives
            /// different keys in the VOPRF and the POPRF.
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// if `info` is longer than 65535 bytes;
            /// [`DeriveKeyPair`](crate::verifiable_oprf::VoprfError::DeriveKeyPair)
            /// if 256 derivation attempts yield zero.
            pub fn derive(
                seed: &[u8; 32],
                info: &[u8],
            ) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ServerCore::derive(
                    $crate::verifiable_oprf::protocol::Mode::Voprf,
                    seed,
                    info,
                )
                .map(Self)
            }

            /// Load a secret key serialized by [`secret_key`](Self::secret_key).
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// unless `secret_key` is the 32-byte canonical encoding of a
            /// nonzero scalar.
            pub fn from_secret_key(
                secret_key: &[u8],
            ) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ServerCore::from_secret_key(secret_key)
                    .map(Self)
            }

            /// `SerializeScalar(skS)`.
            pub fn secret_key(&self) -> ::zeroize::Zeroizing<[u8; 32]> {
                self.0.secret_key()
            }

            /// `SerializeElement(pkS)`: the public key clients verify against.
            pub fn public_key(&self) -> [u8; $ne] {
                self.0.public_key()
            }

            /// `BlindEvaluate(skS, pkS, blindedElement)` (RFC 9497 §3.3.2):
            /// the evaluated element and the proof `c || s`.
            ///
            /// # Security
            ///
            /// `rng` must be a cryptographically secure generator. It feeds
            /// the proof nonce, which this crate hedges with the secret key and
            /// the statement (see the module documentation), so a generator
            /// that repeats does not reveal the key — but a predictable one
            /// still weakens the nonce to the secrecy of the key alone.
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// if `blinded` is not a valid non-identity element.
            pub fn blind_evaluate(
                &self,
                blinded: &[u8],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<([u8; $ne], [u8; 64]), $crate::verifiable_oprf::VoprfError> {
                let (mut evaluated, proof) = self.blind_evaluate_batch(&[blinded], rng)?;
                Ok((evaluated.remove(0), proof))
            }

            /// `BlindEvaluate` over a batch, with one proof for all of it
            /// (RFC 9497 §3.3.2: "Using larger lists allows servers to batch
            /// the evaluation of multiple elements while producing a single
            /// batched DLEQ proof").
            ///
            /// The evaluated elements come back in the order of `blinded`.
            /// RFC 9497 §7.2.1 notes that no security analysis covers
            /// batching; each element costs about two scalar multiplications,
            /// so a server should cap the batch size it accepts.
            ///
            /// # Errors
            ///
            /// [`Batch`](crate::verifiable_oprf::VoprfError::Batch) for an
            /// empty batch or one of more than 65535 elements;
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// if any element is invalid.
            pub fn blind_evaluate_batch<B: AsRef<[u8]>>(
                &self,
                blinded: &[B],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<(::alloc::vec::Vec<[u8; $ne]>, [u8; 64]), $crate::verifiable_oprf::VoprfError>
            {
                self.0.blind_evaluate(
                    $crate::verifiable_oprf::protocol::Mode::Voprf,
                    blinded,
                    |dsts, k, bm, a0, a1| {
                        $crate::verifiable_oprf::protocol::hedged_nonce::<$group>(
                            dsts, rng, k, bm, a0, a1,
                        )
                    },
                )
            }

            /// `Evaluate(skS, input)` (RFC 9497 §3.3.1): the PRF output for an
            #[doc = concat!("input the server knows, equal to what [`", stringify!($client), "::finalize`] returns for the same input.")]
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// for an input longer than 65535 bytes;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if it hashes to the identity.
            pub fn evaluate(
                &self,
                input: &[u8],
            ) -> Result<::zeroize::Zeroizing<[u8; $nh]>, $crate::verifiable_oprf::VoprfError> {
                self.0.evaluate($crate::verifiable_oprf::protocol::Mode::Voprf, input)
            }
        }

        impl ::zeroize::Zeroize for $server {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ::zeroize::ZeroizeOnDrop for $server {}

        impl ::core::fmt::Debug for $server {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($server), " { .. }"))
            }
        }

        #[doc = concat!("The client of the RFC 9497 VOPRF (mode `0x01`) for ", $suite, ": the context `SetupVOPRFClient` creates, holding the server's `pkS`.")]
        ///
        /// See the [module documentation](crate::verifiable_oprf) for the
        /// protocol and its security considerations.
        pub struct $client($crate::verifiable_oprf::protocol::ClientCore<$group>);

        impl $client {
            /// Deserialize the server's public key.
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// unless `public_key` is a valid non-identity element.
            pub fn new(public_key: &[u8]) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ClientCore::new(public_key).map(Self)
            }

            /// `Blind(input)` (RFC 9497 §3.3.1) with a random blind: the
            /// state to keep and the blinded element to send.
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// for an input longer than 65535 bytes;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if it hashes to the identity.
            pub fn blind(
                &self,
                input: &[u8],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<($state, [u8; $ne]), $crate::verifiable_oprf::VoprfError> {
                self.0
                    .blind($crate::verifiable_oprf::protocol::Mode::Voprf, input, rng)
                    .map(|(state, blinded)| ($state(state), blinded))
            }

            /// `Blind(input)` with a blind derived from 64 caller-supplied
            /// bytes instead of a random one.
            ///
            #[doc = concat!("The bytes are reduced modulo the group order (", $suite, ": see the module documentation for the byte order).")]
            ///
            /// # Security
            ///
            /// Read the deterministic-blinding contract in the
            /// [module documentation](crate::verifiable_oprf#deterministic-blinding-hazmat)
            /// before using this. In short: the bytes must be the output of a
            /// PRF under a key only the client holds, never derived from the
            /// input or other public data alone, and never reused for a
            /// different input. Equal `(input, blind)` pairs produce equal
            /// blinded elements, so the server can link them by design, and
            /// RFC 9497 §7.1's unconditional input secrecy becomes
            /// computational.
            ///
            /// # Errors
            ///
            /// As [`blind`](Self::blind), and
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if the bytes reduce to zero — the same bytes always will, so
            /// derive other bytes.
            #[cfg(feature = "hazmat")]
            pub fn deterministic_blind(
                &self,
                input: &[u8],
                blind: &[u8; 64],
            ) -> Result<($state, [u8; $ne]), $crate::verifiable_oprf::VoprfError> {
                self.0
                    .deterministic_blind($crate::verifiable_oprf::protocol::Mode::Voprf, input, blind)
                    .map(|(state, blinded)| ($state(state), blinded))
            }

            /// `Finalize(input, blind, evaluatedElement, blindedElement, pkS,
            /// proof)` (RFC 9497 §3.3.2): verify the proof, unblind and hash.
            ///
            /// `input` must be the input `state` was blinded with; it is
            /// checked, because the proof does not cover it.
            ///
            /// # Errors
            ///
            /// [`InputMismatch`](crate::verifiable_oprf::VoprfError::InputMismatch)
            /// if `input` differs from the blinded one;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if `state` was zeroized;
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// for a malformed evaluated element or proof;
            /// [`Verify`](crate::verifiable_oprf::VoprfError::Verify) if the
            /// proof does not verify against the server's public key.
            pub fn finalize(
                &self,
                state: &$state,
                input: &[u8],
                evaluated: &[u8],
                proof: &[u8],
            ) -> Result<::zeroize::Zeroizing<[u8; $nh]>, $crate::verifiable_oprf::VoprfError> {
                let mut outputs = self.0.finalize(
                    $crate::verifiable_oprf::protocol::Mode::Voprf,
                    &[&state.0],
                    &[input],
                    &[evaluated],
                    proof,
                )?;
                // Moved out with `replace`, not `remove`: `remove` would leave
                // the output's bytes in the slot of a buffer freed unwiped.
                Ok(::core::mem::replace(
                    &mut outputs[0],
                    ::zeroize::Zeroizing::new([0u8; $nh]),
                ))
            }

            /// `Finalize` over a batch evaluated with one proof.
            ///
            /// `states[i]`, `inputs[i]` and `evaluated[i]` belong together, in
            /// the order the blinded elements were sent.
            ///
            /// # Errors
            ///
            /// As [`finalize`](Self::finalize), and
            /// [`Batch`](crate::verifiable_oprf::VoprfError::Batch) if the
            /// three lists differ in length, are empty, or exceed 65535.
            pub fn finalize_batch<I: AsRef<[u8]>, E: AsRef<[u8]>>(
                &self,
                states: &[$state],
                inputs: &[I],
                evaluated: &[E],
                proof: &[u8],
            ) -> Result<
                ::alloc::vec::Vec<::zeroize::Zeroizing<[u8; $nh]>>,
                $crate::verifiable_oprf::VoprfError,
            > {
                let states: ::alloc::vec::Vec<_> = states.iter().map(|s| &s.0).collect();
                self.0.finalize(
                    $crate::verifiable_oprf::protocol::Mode::Voprf,
                    &states,
                    inputs,
                    evaluated,
                    proof,
                )
            }
        }

        impl ::core::fmt::Debug for $client {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($client), " { .. }"))
            }
        }

        #[doc = concat!("What a [`", stringify!($client), "`] keeps between `blind` and `finalize`.")]
        ///
        /// It holds the secret blind and the hashed input, both zeroized on
        /// drop. It is deliberately neither `Clone` nor `Copy`.
        pub struct $state($crate::verifiable_oprf::protocol::ClientStateCore<$group>);

        impl ::zeroize::Zeroize for $state {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ::zeroize::ZeroizeOnDrop for $state {}

        impl ::core::fmt::Debug for $state {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($state), " { .. }"))
            }
        }
    };
}

/// The POPRF (mode `0x02`) types of one ciphersuite.
macro_rules! poprf_types {
    (
        suite: $suite:literal,
        group: $group:ty,
        ne: $ne:literal,
        nh: $nh:literal,
        server: $server:ident,
        client: $client:ident,
        state: $state:ident $(,)?
    ) => {
        #[doc = concat!("The server of the RFC 9497 POPRF (mode `0x02`) for ", $suite, ": the context `SetupPOPRFServer` creates, holding `skS`.")]
        ///
        /// The secret key is zeroized on drop. A zeroized server refuses to
        /// evaluate ([`VoprfError::Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize))
        /// rather than act as the zero key.
        ///
        /// See the [module documentation](crate::verifiable_oprf) for the
        /// protocol and its security considerations.
        pub struct $server($crate::verifiable_oprf::protocol::ServerCore<$group>);

        impl $server {
            /// `GenerateKeyPair` (RFC 9497 §3.2): a fresh random key.
            pub fn generate(rng: &mut impl ::rand_core::CryptoRng) -> Self {
                Self($crate::verifiable_oprf::protocol::ServerCore::generate(rng))
            }

            /// `DeriveKeyPair(seed, info)` (RFC 9497 §3.2.1) under the POPRF
            /// context string.
            ///
            /// The key is a secret only as long as `seed` is: it must come
            /// from a CSPRNG. This `info` is the key-derivation label, not the
            /// POPRF public input. The same seed derives different keys in the
            /// VOPRF and the POPRF.
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// if `info` is longer than 65535 bytes;
            /// [`DeriveKeyPair`](crate::verifiable_oprf::VoprfError::DeriveKeyPair)
            /// if 256 derivation attempts yield zero.
            pub fn derive(
                seed: &[u8; 32],
                info: &[u8],
            ) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ServerCore::derive(
                    $crate::verifiable_oprf::protocol::Mode::Poprf(&[]),
                    seed,
                    info,
                )
                .map(Self)
            }

            /// Load a secret key serialized by [`secret_key`](Self::secret_key).
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// unless `secret_key` is the 32-byte canonical encoding of a
            /// nonzero scalar.
            pub fn from_secret_key(
                secret_key: &[u8],
            ) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ServerCore::from_secret_key(secret_key)
                    .map(Self)
            }

            /// `SerializeScalar(skS)`.
            pub fn secret_key(&self) -> ::zeroize::Zeroizing<[u8; 32]> {
                self.0.secret_key()
            }

            /// `SerializeElement(pkS)`: the public key clients verify against.
            pub fn public_key(&self) -> [u8; $ne] {
                self.0.public_key()
            }

            /// `BlindEvaluate(skS, blindedElement, info)` (RFC 9497 §3.3.3):
            /// the evaluated element and the proof `c || s`.
            ///
            /// # Security
            ///
            /// `rng` must be a cryptographically secure generator. It feeds
            /// the proof nonce, which this crate hedges with the secret key and
            /// the statement (see the module documentation), so a generator
            /// that repeats does not reveal the key — but a predictable one
            /// still weakens the nonce to the secrecy of the key alone.
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// if `blinded` is not a valid non-identity element;
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// if `info` is longer than 65535 bytes;
            /// [`Inverse`](crate::verifiable_oprf::VoprfError::Inverse) if
            /// `skS + HashToScalar(framedInfo)` is zero — which only a party
            /// that knows `skS` can arrange, so RFC 9497 §3.3.3 treats it as a
            /// reason to rotate the key.
            pub fn blind_evaluate(
                &self,
                blinded: &[u8],
                info: &[u8],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<([u8; $ne], [u8; 64]), $crate::verifiable_oprf::VoprfError> {
                let (mut evaluated, proof) = self.blind_evaluate_batch(&[blinded], info, rng)?;
                Ok((evaluated.remove(0), proof))
            }

            /// `BlindEvaluate` over a batch sharing one `info`, with one proof
            /// for all of it (RFC 9497 §3.3.3).
            ///
            /// The evaluated elements come back in the order of `blinded`.
            /// RFC 9497 §7.2.1 notes that no security analysis covers
            /// batching; each element costs about two scalar multiplications,
            /// so a server should cap the batch size it accepts.
            ///
            /// # Errors
            ///
            /// As [`blind_evaluate`](Self::blind_evaluate), and
            /// [`Batch`](crate::verifiable_oprf::VoprfError::Batch) for an
            /// empty batch or one of more than 65535 elements.
            pub fn blind_evaluate_batch<B: AsRef<[u8]>>(
                &self,
                blinded: &[B],
                info: &[u8],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<(::alloc::vec::Vec<[u8; $ne]>, [u8; 64]), $crate::verifiable_oprf::VoprfError>
            {
                self.0.blind_evaluate(
                    $crate::verifiable_oprf::protocol::Mode::Poprf(info),
                    blinded,
                    |dsts, k, bm, a0, a1| {
                        $crate::verifiable_oprf::protocol::hedged_nonce::<$group>(
                            dsts, rng, k, bm, a0, a1,
                        )
                    },
                )
            }

            /// `Evaluate(skS, input, info)` (RFC 9497 §3.3.3): the PRF output
            #[doc = concat!("for an input the server knows, equal to what [`", stringify!($client), "::finalize`] returns for the same input and `info`.")]
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// for an input or `info` longer than 65535 bytes;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if the input hashes to the identity;
            /// [`Inverse`](crate::verifiable_oprf::VoprfError::Inverse) as for
            /// [`blind_evaluate`](Self::blind_evaluate).
            pub fn evaluate(
                &self,
                input: &[u8],
                info: &[u8],
            ) -> Result<::zeroize::Zeroizing<[u8; $nh]>, $crate::verifiable_oprf::VoprfError> {
                self.0.evaluate($crate::verifiable_oprf::protocol::Mode::Poprf(info), input)
            }
        }

        impl ::zeroize::Zeroize for $server {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ::zeroize::ZeroizeOnDrop for $server {}

        impl ::core::fmt::Debug for $server {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($server), " { .. }"))
            }
        }

        #[doc = concat!("The client of the RFC 9497 POPRF (mode `0x02`) for ", $suite, ": the context `SetupPOPRFClient` creates, holding the server's `pkS`.")]
        ///
        /// See the [module documentation](crate::verifiable_oprf) for the
        /// protocol and its security considerations.
        pub struct $client($crate::verifiable_oprf::protocol::ClientCore<$group>);

        impl $client {
            /// Deserialize the server's public key.
            ///
            /// # Errors
            ///
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// unless `public_key` is a valid non-identity element.
            pub fn new(public_key: &[u8]) -> Result<Self, $crate::verifiable_oprf::VoprfError> {
                $crate::verifiable_oprf::protocol::ClientCore::new(public_key).map(Self)
            }

            /// `Blind(input, info, pkS)` (RFC 9497 §3.3.3) with a random blind:
            /// the state to keep and the blinded element to send.
            ///
            /// The state keeps the tweaked key this `info` gives, as RFC 9497
            /// §3.3.3 has the client do, and `finalize` requires the same
            /// `info`. The blinded element itself does not depend on `info`;
            /// a value the server could not evaluate fails here, before a
            /// request is sent.
            ///
            /// # Errors
            ///
            /// [`InputTooLong`](crate::verifiable_oprf::VoprfError::InputTooLong)
            /// for an input or `info` longer than 65535 bytes;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if the input hashes to the identity or the tweaked key
            /// `pkS + HashToScalar(framedInfo) * G` is the identity.
            pub fn blind(
                &self,
                input: &[u8],
                info: &[u8],
                rng: &mut impl ::rand_core::CryptoRng,
            ) -> Result<($state, [u8; $ne]), $crate::verifiable_oprf::VoprfError> {
                self.0
                    .blind($crate::verifiable_oprf::protocol::Mode::Poprf(info), input, rng)
                    .map(|(state, blinded)| ($state(state), blinded))
            }

            /// `Blind(input, info, pkS)` with a blind derived from 64
            /// caller-supplied bytes instead of a random one.
            ///
            #[doc = concat!("The bytes are reduced modulo the group order (", $suite, ": see the module documentation for the byte order).")]
            ///
            /// # Security
            ///
            /// Read the deterministic-blinding contract in the
            /// [module documentation](crate::verifiable_oprf#deterministic-blinding-hazmat)
            /// before using this. In short: the bytes must be the output of a
            /// PRF under a key only the client holds, never derived from the
            /// input or other public data alone, and never reused for a
            /// different input. Equal `(input, blind)` pairs produce equal
            /// blinded elements — whatever the `info` — so the server can link
            /// them by design, and RFC 9497 §7.1's unconditional input secrecy
            /// becomes computational.
            ///
            /// # Errors
            ///
            /// As [`blind`](Self::blind), and
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if the bytes reduce to zero — the same bytes always will, so
            /// derive other bytes.
            #[cfg(feature = "hazmat")]
            pub fn deterministic_blind(
                &self,
                input: &[u8],
                info: &[u8],
                blind: &[u8; 64],
            ) -> Result<($state, [u8; $ne]), $crate::verifiable_oprf::VoprfError> {
                self.0
                    .deterministic_blind(
                        $crate::verifiable_oprf::protocol::Mode::Poprf(info),
                        input,
                        blind,
                    )
                    .map(|(state, blinded)| ($state(state), blinded))
            }

            /// `Finalize(input, blind, evaluatedElement, blindedElement, proof,
            /// info, tweakedKey)` (RFC 9497 §3.3.3): verify the proof, unblind
            /// and hash.
            ///
            /// `input` and `info` must be the ones `state` was blinded with,
            /// and this client the one that blinded it. All three are checked:
            /// the tweaked key is recomputed from this client's public key and
            /// this `info` and compared with the one `blind` stored, and the
            /// input is compared with the blinded one, because the proof covers
            /// neither. So a caller's mistake surfaces as
            /// [`InputMismatch`](crate::verifiable_oprf::VoprfError::InputMismatch),
            /// and [`Verify`](crate::verifiable_oprf::VoprfError::Verify) means
            /// only that the server's response does not verify — including a
            /// server that evaluated under another `info`.
            ///
            /// # Errors
            ///
            /// [`InputMismatch`](crate::verifiable_oprf::VoprfError::InputMismatch)
            /// as above;
            /// [`InvalidInput`](crate::verifiable_oprf::VoprfError::InvalidInput)
            /// if `state` was zeroized or the tweaked key is the identity;
            /// [`Deserialize`](crate::verifiable_oprf::VoprfError::Deserialize)
            /// for a malformed evaluated element or proof;
            /// [`Verify`](crate::verifiable_oprf::VoprfError::Verify) if the
            /// proof does not verify.
            pub fn finalize(
                &self,
                state: &$state,
                input: &[u8],
                info: &[u8],
                evaluated: &[u8],
                proof: &[u8],
            ) -> Result<::zeroize::Zeroizing<[u8; $nh]>, $crate::verifiable_oprf::VoprfError> {
                let mut outputs = self.0.finalize(
                    $crate::verifiable_oprf::protocol::Mode::Poprf(info),
                    &[&state.0],
                    &[input],
                    &[evaluated],
                    proof,
                )?;
                // Moved out with `replace`, not `remove`: `remove` would leave
                // the output's bytes in the slot of a buffer freed unwiped.
                Ok(::core::mem::replace(
                    &mut outputs[0],
                    ::zeroize::Zeroizing::new([0u8; $nh]),
                ))
            }

            /// `Finalize` over a batch evaluated under one `info` with one
            /// proof.
            ///
            /// `states[i]`, `inputs[i]` and `evaluated[i]` belong together, in
            /// the order the blinded elements were sent.
            ///
            /// # Errors
            ///
            /// As [`finalize`](Self::finalize), and
            /// [`Batch`](crate::verifiable_oprf::VoprfError::Batch) if the
            /// three lists differ in length, are empty, or exceed 65535.
            pub fn finalize_batch<I: AsRef<[u8]>, E: AsRef<[u8]>>(
                &self,
                states: &[$state],
                inputs: &[I],
                info: &[u8],
                evaluated: &[E],
                proof: &[u8],
            ) -> Result<
                ::alloc::vec::Vec<::zeroize::Zeroizing<[u8; $nh]>>,
                $crate::verifiable_oprf::VoprfError,
            > {
                let states: ::alloc::vec::Vec<_> = states.iter().map(|s| &s.0).collect();
                self.0.finalize(
                    $crate::verifiable_oprf::protocol::Mode::Poprf(info),
                    &states,
                    inputs,
                    evaluated,
                    proof,
                )
            }
        }

        impl ::core::fmt::Debug for $client {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($client), " { .. }"))
            }
        }

        #[doc = concat!("What a [`", stringify!($client), "`] keeps between `blind` and `finalize`.")]
        ///
        /// It holds the secret blind and the hashed input, both zeroized on
        /// drop. It is deliberately neither `Clone` nor `Copy`.
        pub struct $state($crate::verifiable_oprf::protocol::ClientStateCore<$group>);

        impl ::zeroize::Zeroize for $state {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ::zeroize::ZeroizeOnDrop for $state {}

        impl ::core::fmt::Debug for $state {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($state), " { .. }"))
            }
        }
    };
}

pub(crate) use poprf_types;
pub(crate) use voprf_types;
