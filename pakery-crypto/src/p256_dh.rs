//! P-256 Diffie-Hellman group implementation.

use alloc::vec::Vec;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ProjectivePoint;
use pakery_core::crypto::dh::DhGroup;
use pakery_core::PakeError;
use rand_core::CryptoRngCore;
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

        let scalar = scalar_from_bytes(sk)?;
        let pk_point = point_from_bytes(pk)?;
        let result = pk_point * scalar;

        if bool::from(result.ct_eq(&ProjectivePoint::IDENTITY)) {
            return Err(PakeError::IdentityPoint);
        }
        Ok(Zeroizing::new(point_to_bytes(&result)))
    }

    fn derive_keypair(seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        use pakery_core::crypto::oprf::Oprf;

        let sk_bytes = P256Oprf::derive_key(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")?;
        let scalar = scalar_from_bytes(&sk_bytes)?;
        let pk_point = ProjectivePoint::GENERATOR * scalar;
        let pk = pk_point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Ok((sk_bytes, pk))
    }

    fn generate_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let result = Self::derive_keypair(&seed);
        seed.zeroize();
        result
    }

    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, PakeError> {
        let scalar = scalar_from_bytes(sk)?;
        let pk_point = ProjectivePoint::GENERATOR * scalar;
        let pk = pk_point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Ok(pk)
    }
}
