//! P256-SHA256 (RFC 9497 §4.3).

use p256::elliptic_curve::ff::PrimeField;
#[cfg(any(test, feature = "hazmat"))]
use p256::elliptic_curve::ops::Reduce;
use p256::hash2curve::GroupDigest;
use p256::{FieldBytes, NistP256, ProjectivePoint, Scalar};
use pakery_core::ct;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use super::api::{poprf_types, voprf_types};
use super::protocol::{ModeDsts, VoprfGroup};
use super::VoprfError;
use crate::oprf_common::expand_message_xmd;
#[cfg(any(test, feature = "hazmat"))]
use crate::oprf_p256::r_constant;
use crate::oprf_p256::{encode_point_ct, point_from_bytes, reduce_48_to_scalar};

/// The P256-SHA256 group (private suite marker).
pub(crate) struct P256;

impl VoprfGroup for P256 {
    type Scalar = Scalar;
    type Point = ProjectivePoint;
    type Hash = Sha256;
    type Element = [u8; 33];
    type Output = [u8; 32];

    const ELEMENT_LEN: usize = 33;
    const OUTPUT_ZERO: [u8; 32] = [0u8; 32];

    const VOPRF: ModeDsts = ModeDsts {
        hash_to_group: b"HashToGroup-OPRFV1-\x01-P256-SHA256",
        hash_to_scalar: b"HashToScalar-OPRFV1-\x01-P256-SHA256",
        derive_key_pair: b"DeriveKeyPairOPRFV1-\x01-P256-SHA256",
        seed: b"Seed-OPRFV1-\x01-P256-SHA256",
        nonce: b"pakery-DLEQNonce-OPRFV1-\x01-P256-SHA256",
    };

    const POPRF: ModeDsts = ModeDsts {
        hash_to_group: b"HashToGroup-OPRFV1-\x02-P256-SHA256",
        hash_to_scalar: b"HashToScalar-OPRFV1-\x02-P256-SHA256",
        derive_key_pair: b"DeriveKeyPairOPRFV1-\x02-P256-SHA256",
        seed: b"Seed-OPRFV1-\x02-P256-SHA256",
        nonce: b"pakery-DLEQNonce-OPRFV1-\x02-P256-SHA256",
    };

    fn identity() -> ProjectivePoint {
        ProjectivePoint::IDENTITY
    }

    fn mul_base(k: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * k
    }

    fn mul(p: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
        *p * k
    }

    fn add(a: &ProjectivePoint, b: &ProjectivePoint) -> ProjectivePoint {
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
        // `invert` is constant time and returns a none `CtOption` for zero;
        // `unwrap_or` selects without a branch. Every caller has rejected zero.
        a.invert().unwrap_or(Scalar::ZERO)
    }

    /// 32-byte big-endian rejection sampling, redrawn on an out-of-range or
    /// zero candidate: the consumption pattern of this crate's base-mode OPRF
    /// and of the reference implementation, which the vector tests and the
    /// differential test replay.
    fn random_scalar(rng: &mut impl CryptoRng) -> Scalar {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *bytes);
            // ctgrind: candidates are not marked — accepting or rejecting one
            // is a public retry decision taken before the value means anything.
            // Copied in place rather than through a by-value array, and the
            // candidate's value wiped once it is decided on, so the only
            // copies left unwiped are `from_repr`'s own argument and the
            // `CtOption` it returns.
            let mut repr = FieldBytes::default();
            repr.copy_from_slice(&*bytes);
            let candidate = Scalar::from_repr(repr);
            repr.zeroize();
            let mut value = candidate.unwrap_or(Scalar::ZERO);
            let accept = candidate.is_some() & !value.ct_eq(&Scalar::ZERO);
            value.zeroize();
            if bool::from(accept) {
                // ctgrind: the accepted value is the secret; mark it and
                // re-derive the scalar from the marked bytes so the taint
                // carries into every later operation.
                ct::mark_secret(&*bytes);
                let mut repr = FieldBytes::default();
                repr.copy_from_slice(&*bytes);
                let scalar = Scalar::from_repr(repr).unwrap_or(Scalar::ZERO);
                repr.zeroize();
                return scalar;
            }
        }
    }

    /// The 64 bytes are read as a big-endian integer and reduced mod `n`:
    /// `hi * 2^256 + lo`, each half reduced first. Both halves go through
    /// `Reduce<FieldBytes>`, which is big-endian; the crate does not use
    /// `FromUniformBytes<64>`, whose trait documents little-endian input while
    /// p256 implements it big-endian.
    #[cfg(any(test, feature = "hazmat"))]
    fn scalar_from_wide(bytes: &[u8; 64]) -> Scalar {
        let mut hi = FieldBytes::default();
        let mut lo = FieldBytes::default();
        hi.copy_from_slice(&bytes[..32]);
        lo.copy_from_slice(&bytes[32..]);
        let mut high = <Scalar as Reduce<FieldBytes>>::reduce(&hi);
        let mut low = <Scalar as Reduce<FieldBytes>>::reduce(&lo);
        hi.zeroize();
        lo.zeroize();
        let mut shifted = high * r_constant();
        let scalar = shifted + low;
        high.zeroize();
        low.zeroize();
        shifted.zeroize();
        scalar
    }

    /// `hash_to_curve` with suite `P256_XMD:SHA-256_SSWU_RO_` (RFC 9380).
    fn hash_to_group(input: &[u8], dst: &[u8]) -> Result<ProjectivePoint, VoprfError> {
        NistP256::hash_from_bytes(&[input], &[dst]).map_err(|_| VoprfError::InvalidInput)
    }

    /// RFC 9497 §4.3: `hash_to_field` with `L = 48`, big-endian, mod `n`.
    fn hash_to_scalar(msg: &[&[u8]], dst: &[u8]) -> Scalar {
        let uniform = expand_message_xmd::<Sha256>(msg, dst, 48)
            .expect("every DST here is at most 255 bytes and 48 is a valid length");
        let mut wide = Zeroizing::new([0u8; 48]);
        wide.copy_from_slice(&uniform);
        reduce_48_to_scalar(&wide)
    }

    fn encode_element_unchecked(p: &ProjectivePoint) -> [u8; 33] {
        encode_point_ct(p)
    }

    /// Compressed SEC1 only — every element has one valid encoding — with the
    /// partial public-key validation RFC 9497 §4.3 asks for (coordinates in
    /// range, on the curve), then the identity check. The data is public.
    fn decode_element(bytes: &[u8]) -> Option<ProjectivePoint> {
        let point = point_from_bytes(bytes).ok()?;
        if bool::from(point.ct_eq(&ProjectivePoint::IDENTITY)) {
            return None;
        }
        Some(point)
    }

    /// The secret key (`secret_key`) and the proof nonce's key bytes pass
    /// through here, so the encoding is copied out of a `FieldBytes` that is
    /// then wiped, rather than converted by value.
    fn encode_scalar(s: &Scalar) -> [u8; 32] {
        let mut repr = s.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(&repr);
        repr.zeroize();
        out
    }

    /// Canonical big-endian scalars below `n`, decided without a branch.
    fn decode_scalar(bytes: &[u8; 32]) -> (Scalar, Choice) {
        // A secret key passes through here (`from_secret_key`): `repr` is
        // wiped, and the only copies left unwiped are `from_repr`'s by-value
        // argument and the `CtOption` it returns.
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(bytes);
        let scalar = Scalar::from_repr(repr);
        repr.zeroize();
        (scalar.unwrap_or(Scalar::ZERO), scalar.is_some())
    }
}

voprf_types! {
    suite: "P256-SHA256",
    group: P256,
    ne: 33,
    nh: 32,
    server: P256VoprfServer,
    client: P256VoprfClient,
    state: P256VoprfClientState,
}

poprf_types! {
    suite: "P256-SHA256",
    group: P256,
    ne: 33,
    nh: 32,
    server: P256PoprfServer,
    client: P256PoprfClient,
    state: P256PoprfClientState,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    /// The generator's x-coordinate (SEC 2), for malformed encodings that
    /// carry a valid x.
    const GX: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];

    const fn tagged(tag: u8) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = tag;
        let mut i = 0;
        while i < 32 {
            out[i + 1] = GX[i];
            i += 1;
        }
        out
    }

    /// Encodings compressed-SEC1 decoding plus the identity check must reject.
    const INVALID_ELEMENTS: &[&[u8]] = &[
        &[0x00], // the SEC1 identity
        &[0u8; 33],
        &tagged(0x05), // SEC1 "compact" form of a valid x
        &tagged(0x04), // uncompressed tag at compressed length
        // x = 2^256 - 1, above the field modulus.
        &[
            0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        &[0x02; 32],
        &[0x02; 34],
        &[],
    ];

    /// The group order n, big-endian: the smallest non-canonical scalar.
    const SCALAR_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    /// n as 64 big-endian bytes: reduces to zero.
    #[cfg(feature = "hazmat")]
    const WIDE_ORDER: [u8; 64] = {
        let mut wide = [0u8; 64];
        let mut i = 0;
        while i < 32 {
            wide[32 + i] = SCALAR_ORDER[i];
            i += 1;
        }
        wide
    };

    /// P-256 `RandomScalar` accepts the first in-range nonzero 32-byte
    /// big-endian candidate, so the RFC's blind is consumed as it is.
    fn blind_rng(blind: &[u8]) -> Vec<u8> {
        blind.to_vec()
    }

    /// 64 bytes that `deterministic_blind` (big-endian) reduces to the blind:
    /// 32 zero bytes, then the blind.
    #[cfg(feature = "hazmat")]
    fn wide_blind(blind: &[u8]) -> [u8; 64] {
        let mut wide = [0u8; 64];
        wide[32..].copy_from_slice(blind);
        wide
    }

    /// 64 big-endian bytes with a nonzero high half that reduce to zero:
    /// `2^256 + (n - 2^256 mod n)`.
    #[cfg(feature = "hazmat")]
    const WIDE_ZERO_HIGH: [u8; 64] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0x01, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x79, 0xcd, 0xf5, 0x5b, 0x4e, 0x2f, 0x3d, 0x09, 0xe7, 0x73, 0x95, 0x85,
        0xf8, 0xc6, 0x4a, 0xa2,
    ];

    /// `RandomScalar` redraws on a zero candidate and on one at or above the
    /// order: zero, then `2^256 - 1`, then the RFC blind must give the RFC
    /// blinded element and consume all three.
    #[test]
    fn random_scalar_redraws_on_zero_and_out_of_range() {
        use crate::verifiable_oprf::protocol::test_support::{hex, ScriptedRng};
        use crate::verifiable_oprf::test_vectors::{P256_VOPRF_KEY, P256_VOPRF_VECTORS};
        let tv = &P256_VOPRF_VECTORS[0];
        let client = super::P256VoprfClient::new(&hex(P256_VOPRF_KEY.pk)).unwrap();
        let script = [[0u8; 32].as_slice(), &[0xff; 32], &hex(tv.blinds[0])].concat();
        let mut rng = ScriptedRng::new(&script);
        let (_, blinded) = client.blind(&hex(tv.inputs[0]), &mut rng).unwrap();
        assert!(rng.is_exhausted());
        assert_eq!(blinded.as_slice(), hex(tv.blinded[0]).as_slice());
    }

    /// `.cargo/mutants.toml` excludes replacing `identity` and `scalar_zero`
    /// with `Default::default()` as equivalent mutants. That holds only while
    /// p256's `Default` is the identity and zero, so this asserts it against
    /// the crate's own constants: a dependency bump that changed either fails
    /// here instead of leaving the exclusion to hide a real mutant.
    #[test]
    fn curve_defaults_are_the_identity_and_zero() {
        use p256::{ProjectivePoint, Scalar};
        assert_eq!(ProjectivePoint::default(), ProjectivePoint::IDENTITY);
        assert_eq!(Scalar::default(), Scalar::ZERO);
    }

    /// The 64-byte reduction against values computed with Python big
    /// integers (`int.from_bytes(b, "big") % n`), not with this code:
    /// both halves nonzero, `n` itself, and `n * 2^256 + 1`.
    #[test]
    fn wide_reduction_matches_big_integer_arithmetic() {
        use crate::verifiable_oprf::protocol::test_support::hex;
        use crate::verifiable_oprf::protocol::VoprfGroup;
        let cases = [
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea1",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
                "b87818e6929169989e6d824949750c903d5305ad0cb6ff4466effb526341d131",
            ),
        ];
        for (wide, expected) in cases {
            let wide: [u8; 64] = hex(wide).try_into().unwrap();
            let scalar = <super::P256 as VoprfGroup>::scalar_from_wide(&wide);
            assert_eq!(
                <super::P256 as VoprfGroup>::encode_scalar(&scalar).as_slice(),
                hex(expected).as_slice()
            );
        }
    }

    mod voprf_vectors {
        use super::super::{P256VoprfClient, P256VoprfServer, P256};
        use super::blind_rng;
        #[cfg(feature = "hazmat")]
        use super::wide_blind;
        #[cfg(feature = "hazmat")]
        use crate::verifiable_oprf::test_vectors::P256_VOPRF_DETERMINISTIC;
        use crate::verifiable_oprf::test_vectors::{
            P256_VOPRF_HEDGED, P256_VOPRF_KEY, P256_VOPRF_VECTORS,
        };

        crate::verifiable_oprf::test_macros::rfc_vector_tests! {
            voprf,
            server: P256VoprfServer,
            client: P256VoprfClient,
            group: P256,
            key: P256_VOPRF_KEY,
            vectors: P256_VOPRF_VECTORS,
            blind_rng: blind_rng,
            wide_blind: wide_blind,
            hedged: P256_VOPRF_HEDGED,
            deterministic: P256_VOPRF_DETERMINISTIC,
        }
    }

    mod poprf_vectors {
        use super::super::{P256PoprfClient, P256PoprfServer, P256};
        use super::blind_rng;
        #[cfg(feature = "hazmat")]
        use super::wide_blind;
        #[cfg(feature = "hazmat")]
        use crate::verifiable_oprf::test_vectors::P256_POPRF_DETERMINISTIC;
        use crate::verifiable_oprf::test_vectors::{
            P256_POPRF_HEDGED, P256_POPRF_KEY, P256_POPRF_VECTORS,
        };

        crate::verifiable_oprf::test_macros::rfc_vector_tests! {
            poprf,
            server: P256PoprfServer,
            client: P256PoprfClient,
            group: P256,
            key: P256_POPRF_KEY,
            vectors: P256_POPRF_VECTORS,
            blind_rng: blind_rng,
            wide_blind: wide_blind,
            hedged: P256_POPRF_HEDGED,
            deterministic: P256_POPRF_DETERMINISTIC,
        }
    }

    mod voprf_behaviour {
        use super::super::{P256VoprfClient, P256VoprfServer, P256};
        use super::{INVALID_ELEMENTS, SCALAR_ORDER};
        #[cfg(feature = "hazmat")]
        use super::{WIDE_ORDER, WIDE_ZERO_HIGH};

        crate::verifiable_oprf::test_macros::behaviour_tests! {
            common,
            server: P256VoprfServer,
            client: P256VoprfClient,
            group: P256,
            ne: 33,
            invalid_elements: INVALID_ELEMENTS,
            scalar_order: SCALAR_ORDER,
            wide_order: WIDE_ORDER,
            wide_zero_high: WIDE_ZERO_HIGH,
            mode: crate::verifiable_oprf::protocol::Mode::Voprf,
            info: [],
        }
    }

    mod poprf_behaviour {
        use super::super::{P256PoprfClient, P256PoprfServer, P256};
        use super::{INVALID_ELEMENTS, SCALAR_ORDER};
        #[cfg(feature = "hazmat")]
        use super::{WIDE_ORDER, WIDE_ZERO_HIGH};

        crate::verifiable_oprf::test_macros::behaviour_tests! {
            common,
            server: P256PoprfServer,
            client: P256PoprfClient,
            group: P256,
            ne: 33,
            invalid_elements: INVALID_ELEMENTS,
            scalar_order: SCALAR_ORDER,
            wide_order: WIDE_ORDER,
            wide_zero_high: WIDE_ZERO_HIGH,
            mode: crate::verifiable_oprf::protocol::Mode::Poprf(b"test info"),
            info: [b"test info"],
        }

        crate::verifiable_oprf::test_macros::poprf_info_tests! {
            server: P256PoprfServer,
            client: P256PoprfClient,
            group: P256,
        }
    }
}
