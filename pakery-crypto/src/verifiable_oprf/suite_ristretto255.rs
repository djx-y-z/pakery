//! ristretto255-SHA512 (RFC 9497 §4.1).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use pakery_core::ct;
use rand_core::CryptoRng;
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use super::api::{poprf_types, voprf_types};
use super::protocol::{ModeDsts, VoprfGroup};
use super::VoprfError;
use crate::oprf_common::expand_message_xmd;

/// The ristretto255-SHA512 group (private suite marker).
pub(crate) struct Ristretto255;

/// `expand_message_xmd(SHA-512, msg, dst, 64)` into a buffer wiped on drop.
fn xmd64(msg: &[&[u8]], dst: &[u8]) -> Zeroizing<[u8; 64]> {
    let uniform = Zeroizing::new(
        expand_message_xmd::<Sha512>(msg, dst, 64)
            .expect("every DST here is at most 255 bytes and 64 is a valid length"),
    );
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&uniform);
    out
}

impl VoprfGroup for Ristretto255 {
    type Scalar = Scalar;
    type Point = RistrettoPoint;
    type Hash = Sha512;
    type Element = [u8; 32];
    type Output = [u8; 64];

    const ELEMENT_LEN: usize = 32;
    const OUTPUT_ZERO: [u8; 64] = [0u8; 64];

    const VOPRF: ModeDsts = ModeDsts {
        hash_to_group: b"HashToGroup-OPRFV1-\x01-ristretto255-SHA512",
        hash_to_scalar: b"HashToScalar-OPRFV1-\x01-ristretto255-SHA512",
        derive_key_pair: b"DeriveKeyPairOPRFV1-\x01-ristretto255-SHA512",
        seed: b"Seed-OPRFV1-\x01-ristretto255-SHA512",
        nonce: b"pakery-DLEQNonce-OPRFV1-\x01-ristretto255-SHA512",
    };

    const POPRF: ModeDsts = ModeDsts {
        hash_to_group: b"HashToGroup-OPRFV1-\x02-ristretto255-SHA512",
        hash_to_scalar: b"HashToScalar-OPRFV1-\x02-ristretto255-SHA512",
        derive_key_pair: b"DeriveKeyPairOPRFV1-\x02-ristretto255-SHA512",
        seed: b"Seed-OPRFV1-\x02-ristretto255-SHA512",
        nonce: b"pakery-DLEQNonce-OPRFV1-\x02-ristretto255-SHA512",
    };

    fn identity() -> RistrettoPoint {
        RistrettoPoint::identity()
    }

    fn mul_base(k: &Scalar) -> RistrettoPoint {
        RistrettoPoint::mul_base(k)
    }

    fn mul(p: &RistrettoPoint, k: &Scalar) -> RistrettoPoint {
        p * k
    }

    fn add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
        a + b
    }

    fn scalar_zero() -> Scalar {
        Scalar::ZERO
    }

    fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
        a + b
    }

    fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
        a - b
    }

    fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
        a * b
    }

    fn scalar_invert(a: &Scalar) -> Scalar {
        // dalek's addition-chain inversion returns 0 for 0 rather than failing;
        // every caller has rejected zero first.
        a.invert()
    }

    /// 64 RNG bytes reduced modulo `l`, redrawn on zero: the consumption
    /// pattern of this crate's base-mode OPRF and of the reference
    /// implementation, which the vector tests and the differential test replay.
    fn random_scalar(rng: &mut impl CryptoRng) -> Scalar {
        loop {
            let mut wide = Zeroizing::new([0u8; 64]);
            rng.fill_bytes(&mut *wide);
            // ctgrind: fresh randomness is secret; the reduction is
            // branch-free, so the taint carries into the scalar.
            ct::mark_secret(&*wide);
            let s = Scalar::from_bytes_mod_order_wide(&wide);
            // ctgrind: a zero candidate only triggers a redraw — public.
            if ct::declassify_choice(s.ct_eq(&Scalar::ZERO)) {
                continue;
            }
            return s;
        }
    }

    /// The 64 bytes are read as a little-endian integer and reduced mod `l`.
    #[cfg(any(test, feature = "hazmat"))]
    fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
        Scalar::from_bytes_mod_order_wide(bytes)
    }

    /// `hash_to_ristretto255` (RFC 9380 Appendix B): `expand_message_xmd`
    /// with SHA-512 to 64 bytes, then the RFC 9496 one-way map.
    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<RistrettoPoint, VoprfError> {
        Ok(RistrettoPoint::from_uniform_bytes(&xmd64(&[input], dst)))
    }

    /// RFC 9497 §4.1: 64 bytes of `expand_message_xmd`, little-endian, mod `l`.
    fn hash_to_scalar(msg: &[&[u8]], dst: &[u8]) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&xmd64(msg, dst))
    }

    fn encode_element_unchecked(p: &RistrettoPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }

    /// RFC 9496 §4.3.1 `Decode`, which accepts only canonical encodings, then
    /// the identity check RFC 9497 §4.1 adds. The data is public.
    fn decode_element(bytes: &[u8]) -> Option<RistrettoPoint> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        let point = CompressedRistretto(bytes).decompress()?;
        if bool::from(point.ct_eq(&RistrettoPoint::identity())) {
            return None;
        }
        Some(point)
    }

    fn encode_scalar(s: &Scalar) -> [u8; 32] {
        s.to_bytes()
    }

    /// Canonical little-endian scalars only (the top three bits clear and the
    /// value below `l`), decided without a branch.
    fn decode_scalar(bytes: &[u8; 32]) -> (Scalar, Choice) {
        let scalar = Scalar::from_canonical_bytes(*bytes);
        (scalar.unwrap_or(Scalar::ZERO), scalar.is_some())
    }
}

voprf_types! {
    suite: "ristretto255-SHA512",
    group: Ristretto255,
    ne: 32,
    nh: 64,
    server: Ristretto255VoprfServer,
    client: Ristretto255VoprfClient,
    state: Ristretto255VoprfClientState,
}

poprf_types! {
    suite: "ristretto255-SHA512",
    group: Ristretto255,
    ne: 32,
    nh: 64,
    server: Ristretto255PoprfServer,
    client: Ristretto255PoprfClient,
    state: Ristretto255PoprfClientState,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    /// Encodings RFC 9496 `Decode` plus the identity check must reject.
    const INVALID_ELEMENTS: &[&[u8]] = &[
        &[0u8; 32],  // the identity
        &[0xff; 32], // not a field element
        // s = p = 2^255 - 19, a non-canonical encoding of zero.
        &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        &[1u8; 31],
        &[1u8; 33],
        &[],
    ];

    /// The group order l, little-endian: the smallest non-canonical scalar.
    const SCALAR_ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// l as 64 little-endian bytes: reduces to zero.
    #[cfg(feature = "hazmat")]
    const WIDE_ORDER: [u8; 64] = {
        let mut wide = [0u8; 64];
        let mut i = 0;
        while i < 32 {
            wide[i] = SCALAR_ORDER[i];
            i += 1;
        }
        wide
    };

    /// ristretto255 `RandomScalar` draws 64 bytes and reduces them, so the
    /// RFC's 32-byte little-endian blind followed by 32 zero bytes reduces to
    /// exactly that blind.
    fn blind_rng(blind: &[u8]) -> Vec<u8> {
        let mut bytes = blind.to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes
    }

    /// The same 64 bytes, as `deterministic_blind` reads them (little-endian).
    #[cfg(feature = "hazmat")]
    fn wide_blind(blind: &[u8]) -> [u8; 64] {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(blind);
        wide
    }

    /// 64 little-endian bytes with a nonzero high half that reduce to zero:
    /// `(l - 2^256 mod l) + 2^256` (low half `16c` for `l = 2^252 + c`).
    #[cfg(feature = "hazmat")]
    const WIDE_ZERO_HIGH: [u8; 64] = [
        0xd0, 0x3e, 0x5d, 0xcf, 0xa5, 0x31, 0x26, 0x81, 0x65, 0xcd, 0x79, 0x2f, 0xea, 0x9d, 0xef,
        0x4d, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// `RandomScalar` redraws on a zero candidate: 64 zero bytes first, then
    /// the RFC blind, must give the RFC blinded element and consume both.
    #[test]
    fn random_scalar_redraws_on_zero() {
        use crate::verifiable_oprf::protocol::test_support::{hex, ScriptedRng};
        use crate::verifiable_oprf::test_vectors::{
            RISTRETTO255_VOPRF_KEY, RISTRETTO255_VOPRF_VECTORS,
        };
        let tv = &RISTRETTO255_VOPRF_VECTORS[0];
        let client = super::Ristretto255VoprfClient::new(&hex(RISTRETTO255_VOPRF_KEY.pk)).unwrap();
        let script = [[0u8; 64].as_slice(), &blind_rng(&hex(tv.blinds[0]))].concat();
        let mut rng = ScriptedRng::new(&script);
        let (_, blinded) = client.blind(&hex(tv.inputs[0]), &mut rng).unwrap();
        assert!(rng.is_exhausted());
        assert_eq!(blinded.as_slice(), hex(tv.blinded[0]).as_slice());
    }

    /// `.cargo/mutants.toml` excludes replacing `identity` and `scalar_zero`
    /// with `Default::default()` as equivalent mutants. That holds only while
    /// curve25519-dalek's `Default` is the identity and zero, so this asserts
    /// it against the crate's own values: a dependency bump that changed
    /// either fails here instead of leaving the exclusion to hide a real
    /// mutant.
    #[test]
    fn curve_defaults_are_the_identity_and_zero() {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::traits::Identity;
        use curve25519_dalek::Scalar;
        assert_eq!(RistrettoPoint::default(), RistrettoPoint::identity());
        assert_eq!(Scalar::default(), Scalar::ZERO);
    }

    /// The 64-byte reduction against values computed with Python big
    /// integers (`int.from_bytes(b, "little") % l`), not with this code.
    #[test]
    fn wide_reduction_matches_big_integer_arithmetic() {
        use crate::verifiable_oprf::protocol::test_support::hex;
        use crate::verifiable_oprf::protocol::VoprfGroup;
        let cases = [
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903",
            ),
            (
                "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
                "c91e0907d114fd83c1edc396490bb2dafa43c19815b0354e70dc80c317c3cb0a",
            ),
        ];
        for (wide, expected) in cases {
            let wide: [u8; 64] = hex(wide).try_into().unwrap();
            let scalar = <super::Ristretto255 as VoprfGroup>::scalar_from_wide(&wide);
            assert_eq!(
                <super::Ristretto255 as VoprfGroup>::encode_scalar(&scalar).as_slice(),
                hex(expected).as_slice()
            );
        }
    }

    mod voprf_vectors {
        use super::super::{Ristretto255, Ristretto255VoprfClient, Ristretto255VoprfServer};
        use super::blind_rng;
        #[cfg(feature = "hazmat")]
        use super::wide_blind;
        #[cfg(feature = "hazmat")]
        use crate::verifiable_oprf::test_vectors::RISTRETTO255_VOPRF_DETERMINISTIC;
        use crate::verifiable_oprf::test_vectors::{
            RISTRETTO255_VOPRF_HEDGED, RISTRETTO255_VOPRF_KEY, RISTRETTO255_VOPRF_VECTORS,
        };

        crate::verifiable_oprf::test_macros::rfc_vector_tests! {
            voprf,
            server: Ristretto255VoprfServer,
            client: Ristretto255VoprfClient,
            group: Ristretto255,
            key: RISTRETTO255_VOPRF_KEY,
            vectors: RISTRETTO255_VOPRF_VECTORS,
            blind_rng: blind_rng,
            wide_blind: wide_blind,
            hedged: RISTRETTO255_VOPRF_HEDGED,
            deterministic: RISTRETTO255_VOPRF_DETERMINISTIC,
        }
    }

    mod poprf_vectors {
        use super::super::{Ristretto255, Ristretto255PoprfClient, Ristretto255PoprfServer};
        use super::blind_rng;
        #[cfg(feature = "hazmat")]
        use super::wide_blind;
        #[cfg(feature = "hazmat")]
        use crate::verifiable_oprf::test_vectors::RISTRETTO255_POPRF_DETERMINISTIC;
        use crate::verifiable_oprf::test_vectors::{
            RISTRETTO255_POPRF_HEDGED, RISTRETTO255_POPRF_KEY, RISTRETTO255_POPRF_VECTORS,
        };

        crate::verifiable_oprf::test_macros::rfc_vector_tests! {
            poprf,
            server: Ristretto255PoprfServer,
            client: Ristretto255PoprfClient,
            group: Ristretto255,
            key: RISTRETTO255_POPRF_KEY,
            vectors: RISTRETTO255_POPRF_VECTORS,
            blind_rng: blind_rng,
            wide_blind: wide_blind,
            hedged: RISTRETTO255_POPRF_HEDGED,
            deterministic: RISTRETTO255_POPRF_DETERMINISTIC,
        }
    }

    mod voprf_behaviour {
        use super::super::{Ristretto255, Ristretto255VoprfClient, Ristretto255VoprfServer};
        use super::{INVALID_ELEMENTS, SCALAR_ORDER};
        #[cfg(feature = "hazmat")]
        use super::{WIDE_ORDER, WIDE_ZERO_HIGH};

        crate::verifiable_oprf::test_macros::behaviour_tests! {
            common,
            server: Ristretto255VoprfServer,
            client: Ristretto255VoprfClient,
            group: Ristretto255,
            ne: 32,
            invalid_elements: INVALID_ELEMENTS,
            scalar_order: SCALAR_ORDER,
            wide_order: WIDE_ORDER,
            wide_zero_high: WIDE_ZERO_HIGH,
            mode: crate::verifiable_oprf::protocol::Mode::Voprf,
            info: [],
        }
    }

    mod poprf_behaviour {
        use super::super::{Ristretto255, Ristretto255PoprfClient, Ristretto255PoprfServer};
        use super::{INVALID_ELEMENTS, SCALAR_ORDER};
        #[cfg(feature = "hazmat")]
        use super::{WIDE_ORDER, WIDE_ZERO_HIGH};

        crate::verifiable_oprf::test_macros::behaviour_tests! {
            common,
            server: Ristretto255PoprfServer,
            client: Ristretto255PoprfClient,
            group: Ristretto255,
            ne: 32,
            invalid_elements: INVALID_ELEMENTS,
            scalar_order: SCALAR_ORDER,
            wide_order: WIDE_ORDER,
            wide_zero_high: WIDE_ZERO_HIGH,
            mode: crate::verifiable_oprf::protocol::Mode::Poprf(b"test info"),
            info: [b"test info"],
        }

        crate::verifiable_oprf::test_macros::poprf_info_tests! {
            server: Ristretto255PoprfServer,
            client: Ristretto255PoprfClient,
            group: Ristretto255,
        }
    }
}
