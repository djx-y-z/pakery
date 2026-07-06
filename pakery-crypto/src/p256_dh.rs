//! P-256 Diffie-Hellman group implementation.

use alloc::vec::Vec;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ProjectivePoint;
use pakery_core::crypto::dh::DhGroup;
use pakery_core::PakeError;
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::oprf_p256::{point_from_bytes, point_to_bytes, scalar_from_bytes, P256Oprf};

/// P-256 Diffie-Hellman group (byte-level operations).
///
/// **Note:** [`derive_keypair`](DhGroup::derive_keypair) uses the
/// `"OPAQUE-DeriveDiffieHellmanKeyPair"` info label, making this
/// implementation OPAQUE-specific. Using it outside OPAQUE will produce
/// keys scoped to the OPAQUE domain separator.
pub struct P256Dh;

impl DhGroup for P256Dh {
    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        use subtle::ConstantTimeEq;

        // ctgrind: launder the scalar validity check — `Scalar::from_repr`
        // branches on a CtOption discriminant inside p256, and canonicity of
        // an honestly generated secret key is public. The parse happens on a
        // local copy (the caller's slice stays marked); the DH result is
        // re-marked secret below so taint stays end-to-end.
        let sk_arr: [u8; 32] = sk
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid scalar length"))?;
        let sk_arr = Zeroizing::new(sk_arr);
        pakery_core::ct::declassify(&*sk_arr);
        let scalar = scalar_from_bytes(&*sk_arr)?;
        let pk_point = point_from_bytes(pk)?;
        let result = pk_point * scalar;

        // ctgrind: the identity-rejection outcome is a public protocol abort.
        if pakery_core::ct::declassify_choice(result.ct_eq(&ProjectivePoint::IDENTITY)) {
            return Err(PakeError::IdentityPoint);
        }
        let out = point_to_bytes(&result);
        // ctgrind: the DH output is secret key material (re-mark after the
        // laundered scalar parse above).
        pakery_core::ct::mark_secret(&out);
        Ok(Zeroizing::new(out))
    }

    fn derive_keypair(seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        use pakery_core::crypto::oprf::Oprf;

        let sk_bytes = P256Oprf::derive_key(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")?;
        // ctgrind: launder the scalar validity check (public for an honestly
        // derived key) on a local copy; `sk_bytes` itself stays marked. The
        // derived public key is public by definition, so no re-mark.
        let sk_copy = Zeroizing::new(sk_bytes.to_vec());
        pakery_core::ct::declassify(&sk_copy);
        let scalar = scalar_from_bytes(&sk_copy)?;
        let pk_point = ProjectivePoint::GENERATOR * scalar;
        let pk = pk_point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Ok((sk_bytes, pk))
    }

    fn generate_keypair(
        rng: &mut impl CryptoRng,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        // ctgrind: the keypair seed is fresh secret material.
        pakery_core::ct::mark_secret(&seed);
        let result = Self::derive_keypair(&seed);
        seed.zeroize();
        result
    }

    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, PakeError> {
        // ctgrind: launder the scalar validity check (public for an honestly
        // generated key) on a local copy; the resulting public key is public.
        let sk_copy = Zeroizing::new(sk.to_vec());
        pakery_core::ct::declassify(&sk_copy);
        let scalar = scalar_from_bytes(&sk_copy)?;
        let pk_point = ProjectivePoint::GENERATOR * scalar;
        let pk = pk_point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Ok(pk)
    }
}
