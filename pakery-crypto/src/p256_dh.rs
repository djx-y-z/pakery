//! P-256 Diffie-Hellman group implementation.

use alloc::vec::Vec;

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
    // P-256: 32-byte scalar, 33-byte compressed SEC1 point.
    const SK_LEN: usize = 32;
    const PK_LEN: usize = 33;

    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        use subtle::ConstantTimeEq;

        // ctgrind: the secret key stays secret through the parse (only the
        // accept/reject decision is declassified), so the DH result is
        // secret as well and its encoding below runs under taint.
        let scalar = scalar_from_bytes(sk)?;
        let pk_point = point_from_bytes(pk)?;
        let result = pk_point * scalar;

        // ctgrind: the identity-rejection outcome is a public protocol abort.
        if pakery_core::ct::declassify_choice(result.ct_eq(&ProjectivePoint::IDENTITY)) {
            return Err(PakeError::IdentityPoint);
        }
        // The shared point is secret: `point_to_bytes` encodes it in constant
        // time. sec1's compressed encoding branched on its y parity here
        // before 0.6.1.
        let out = point_to_bytes(&result);
        // ctgrind: the DH output is secret key material — already tainted
        // through the scalar; marked again to keep the policy explicit.
        pakery_core::ct::mark_secret(&out);
        Ok(Zeroizing::new(out))
    }

    fn derive_keypair(seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        use pakery_core::crypto::oprf::Oprf;

        // ctgrind: the seed is secret key material whoever drew it, and
        // OPAQUE passes its ephemeral key shares' RNG bytes straight in.
        // Marked here, the key and every product with it run tainted.
        pakery_core::ct::mark_secret(seed);
        let sk_bytes = P256Oprf::derive_key(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")?;
        let scalar = scalar_from_bytes(&sk_bytes)?;
        let pk = point_to_bytes(&(ProjectivePoint::GENERATOR * scalar));
        // ctgrind: the public key is public by definition.
        pakery_core::ct::declassify(&pk);
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
        let scalar = scalar_from_bytes(sk)?;
        let pk = point_to_bytes(&(ProjectivePoint::GENERATOR * scalar));
        // ctgrind: the public key is public by definition.
        pakery_core::ct::declassify(&pk);
        Ok(pk)
    }
}
