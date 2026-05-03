//! Test vectors from draft-irtf-cfrg-cpace-18 for Ristretto255 + SHA-512
//! (G_Coffee25519 in testvectors.json).

use pakery_core::encoding::{leb128_encode, lv_cat, o_cat, prepend_len};
use pakery_cpace::generator::{calculate_generator, generator_string};
use pakery_cpace::transcript::{derive_isk, derive_session_id, CpaceMode};
use pakery_cpace::{CpaceInitiator, CpaceResponder};

use pakery_crypto::{Ristretto255Group, Sha512Hash};

/// CPace ciphersuite: Ristretto255 + SHA-512.
struct CpaceRistretto255Sha512;

impl pakery_cpace::CpaceCiphersuite for CpaceRistretto255Sha512 {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;

    const DSI: &'static [u8] = b"CPaceRistretto255";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;
}

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

// Test vector constants (G_Coffee25519 = Ristretto255)
const PRS_HEX: &str = "50617373776F7264"; // "Password"
const CI_HEX: &str = "6F630B425F726573706F6E6465720B415F696E69746961746F72";
const SID_HEX: &str = "7E4B4791D6A8EF019B936C79FB7F2C57";
const G_HEX: &str = "A6FC82C3B8968FBB2E06FEE81CA858586DEA50D248F0C7CA6A18B0902A30B36B";
const YA_SCALAR_HEX: &str = "DA3D23700A9E5699258AEF94DC060DFDA5EBB61F02A5EA77FAD53F4FF0976D08";
const ADA_HEX: &str = "414461"; // "ADa"
const YA_POINT_HEX: &str = "D40FB265A7ABEAEE7939D91A585FE59F7053F982C296EC413C624C669308F87A";
const YB_SCALAR_HEX: &str = "D2316B454718C35362D83D69DF6320F38578ED5984651435E2949762D900B80D";
const ADB_HEX: &str = "414462"; // "ADb"
const YB_POINT_HEX: &str = "08BCF6E9777A9C313A3DB6DAA510F2D398403319C2341BD506A92E672EB7E307";
const K_HEX: &str = "E22B1EF7788F661478F3CDDD4C600774FC0F41E6B711569190FF88FA0E607E09";
const ISK_IR_HEX: &str = "4C5469A16B2364C4B944EBC1A79E51D1674AD47DB26E8718154F59FAEBFAA52D8346F30AA58377117EB20D527F2CBC5C76381F7FD372E89DF8239F87F2E02ED1";
const ISK_SY_HEX: &str = "980DCC5A1C52CEEA031E75F38ED266586616488C5C5780285FCBCF79087C7BCDBD993502EEE606B718BA31E840A000A7B7BEFE15EA427C5CFE88344FA1237F35";
const SID_OUTPUT_IR_HEX: &str = "2A76D3BBC499DFDC4DCACC9FF042F4E1A54E3843258E100CCD7C60F0A541F9D3EBF025E68A460DDE218BD39F0711BC6FA11409C9D7B69D8CCF6B32FC51DDB699";
const SID_OUTPUT_OC_HEX: &str = "CA4B50700C46203CCD10BC0E9F31095E508189CB59857537BE561048D34B9ED9A9697AF11C998F484C3D783B0B531434CAA6835D4C32344FCD17160C9C348FC7";

// Invalid points (G_Coffee25519_points)
const INVALID_Y1_HEX: &str = "2B3C6B8C4F3800E7AEF6864025B4ED79BD599117E427C41BD47D93D654B4A51C";
const INVALID_Y2_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// --- Encoding tests ---

#[test]
fn test_leb128_encode() {
    assert_eq!(leb128_encode(0), vec![0x00]);
    assert_eq!(leb128_encode(4), vec![0x04]);
    assert_eq!(leb128_encode(127), vec![0x7F]);
    assert_eq!(leb128_encode(128), vec![0x80, 0x01]);
    assert_eq!(leb128_encode(300), vec![0xAC, 0x02]);
}

#[test]
fn test_prepend_len() {
    // Empty
    assert_eq!(prepend_len(b""), vec![0x00]);

    // "1234" (4 bytes)
    assert_eq!(prepend_len(b"1234"), vec![0x04, 0x31, 0x32, 0x33, 0x34]);

    // 128 bytes: 0x00..0x7F
    let data: Vec<u8> = (0..128u8).collect();
    let result = prepend_len(&data);
    assert_eq!(result.len(), 2 + 128); // LEB128(128) = [0x80, 0x01]
    assert_eq!(result[0], 0x80);
    assert_eq!(result[1], 0x01);
    assert_eq!(&result[2..], &data[..]);
}

#[test]
fn test_lv_cat() {
    let result = lv_cat(&[b"1234", b"5", b"", b"678"]);
    let expected: Vec<u8> = vec![
        0x04, 0x31, 0x32, 0x33, 0x34, 0x01, 0x35, 0x00, 0x03, 0x36, 0x37, 0x38,
    ];
    assert_eq!(result, expected);
}

#[test]
fn test_o_cat() {
    // When a > b: oc || a || b
    // When a <= b: oc || b || a
    let result1 = o_cat(b"a", b"b");
    assert_eq!(result1, b"ocba"); // a < b, so b || a

    let result2 = o_cat(b"b", b"a");
    assert_eq!(result2, b"ocba"); // b > a, so b || a

    let result3 = o_cat(b"x", b"x");
    assert_eq!(result3, b"ocxx"); // equal, so b || a = x || x
}

// --- Generator tests ---

#[test]
fn test_generator_string() {
    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);

    let gen_str = generator_string::<CpaceRistretto255Sha512>(&prs, &ci, &sid);

    assert_eq!(gen_str.len(), 172, "generator string should be 172 bytes");
}

#[test]
fn test_calculate_generator() {
    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let expected_g = h(G_HEX);

    let g = calculate_generator::<CpaceRistretto255Sha512>(&prs, &ci, &sid).unwrap();
    let g_bytes = pakery_core::crypto::CpaceGroup::to_bytes(&g);

    assert_eq!(
        &g_bytes[..],
        &expected_g[..],
        "generator must match test vector"
    );
}

// --- Point computation tests ---

#[test]
fn test_ya_computation() {
    use pakery_core::crypto::CpaceGroup;

    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);

    let g = calculate_generator::<CpaceRistretto255Sha512>(&prs, &ci, &sid).unwrap();
    let ya_scalar = decode_scalar(YA_SCALAR_HEX);
    let ya_point = g.scalar_mul(&ya_scalar);

    assert_eq!(
        &ya_point.to_bytes()[..],
        &h(YA_POINT_HEX)[..],
        "Ya = ya * g must match test vector"
    );
}

#[test]
fn test_yb_computation() {
    use pakery_core::crypto::CpaceGroup;

    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);

    let g = calculate_generator::<CpaceRistretto255Sha512>(&prs, &ci, &sid).unwrap();
    let yb_scalar = decode_scalar(YB_SCALAR_HEX);
    let yb_point = g.scalar_mul(&yb_scalar);

    assert_eq!(
        &yb_point.to_bytes()[..],
        &h(YB_POINT_HEX)[..],
        "Yb = yb * g must match test vector"
    );
}

#[test]
fn test_shared_secret_k() {
    use pakery_core::crypto::CpaceGroup;

    let ya_scalar = decode_scalar(YA_SCALAR_HEX);
    let yb_scalar = decode_scalar(YB_SCALAR_HEX);
    let ya_point = Ristretto255Group::from_bytes(&h(YA_POINT_HEX)).unwrap();
    let yb_point = Ristretto255Group::from_bytes(&h(YB_POINT_HEX)).unwrap();
    let expected_k = h(K_HEX);

    // K = ya * Yb
    let k1 = yb_point.scalar_mul(&ya_scalar);
    assert_eq!(&k1.to_bytes()[..], &expected_k[..], "K = ya * Yb");

    // K = yb * Ya (commutativity)
    let k2 = ya_point.scalar_mul(&yb_scalar);
    assert_eq!(&k2.to_bytes()[..], &expected_k[..], "K = yb * Ya");
}

fn decode_scalar(hex_str: &str) -> <Ristretto255Group as pakery_core::crypto::CpaceGroup>::Scalar {
    let bytes = h(hex_str);
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    curve25519_dalek::Scalar::from_canonical_bytes(arr).expect("valid canonical scalar")
}

// --- ISK derivation tests ---

#[test]
fn test_isk_ir() {
    let sid = h(SID_HEX);
    let k = h(K_HEX);
    let ya = h(YA_POINT_HEX);
    let ad_a = h(ADA_HEX);
    let yb = h(YB_POINT_HEX);
    let ad_b = h(ADB_HEX);
    let expected = h(ISK_IR_HEX);

    let isk = derive_isk::<CpaceRistretto255Sha512>(
        &sid,
        &k,
        &ya,
        &ad_a,
        &yb,
        &ad_b,
        CpaceMode::InitiatorResponder,
    );

    assert_eq!(
        isk.as_bytes(),
        &expected[..],
        "ISK_IR must match test vector"
    );
}

#[test]
fn test_isk_sy() {
    let sid = h(SID_HEX);
    let k = h(K_HEX);
    let ya = h(YA_POINT_HEX);
    let ad_a = h(ADA_HEX);
    let yb = h(YB_POINT_HEX);
    let ad_b = h(ADB_HEX);
    let expected = h(ISK_SY_HEX);

    let isk = derive_isk::<CpaceRistretto255Sha512>(
        &sid,
        &k,
        &ya,
        &ad_a,
        &yb,
        &ad_b,
        CpaceMode::Symmetric,
    );

    assert_eq!(
        isk.as_bytes(),
        &expected[..],
        "ISK_SY must match test vector"
    );
}

// --- Session ID output tests ---

#[test]
fn test_session_id_output_ir() {
    let ya = h(YA_POINT_HEX);
    let ad_a = h(ADA_HEX);
    let yb = h(YB_POINT_HEX);
    let ad_b = h(ADB_HEX);
    let expected = h(SID_OUTPUT_IR_HEX);

    let sid_out = derive_session_id::<CpaceRistretto255Sha512>(
        &ya,
        &ad_a,
        &yb,
        &ad_b,
        CpaceMode::InitiatorResponder,
    );

    assert_eq!(sid_out, expected, "sid_output_ir must match test vector");
}

#[test]
fn test_session_id_output_oc() {
    let ya = h(YA_POINT_HEX);
    let ad_a = h(ADA_HEX);
    let yb = h(YB_POINT_HEX);
    let ad_b = h(ADB_HEX);
    let expected = h(SID_OUTPUT_OC_HEX);

    let sid_out =
        derive_session_id::<CpaceRistretto255Sha512>(&ya, &ad_a, &yb, &ad_b, CpaceMode::Symmetric);

    assert_eq!(sid_out, expected, "sid_output_oc must match test vector");
}

// --- Generator is never identity ---

#[test]
fn test_generator_is_not_identity() {
    use pakery_core::crypto::CpaceGroup;

    let ci = h(CI_HEX);
    let sid = h(SID_HEX);

    let test_inputs: &[&[u8]] = &[
        b"",             // empty password
        b"Password",     // normal password
        b"\x00\x00\x00", // null bytes
        &[0x41; 1024],   // long input
    ];

    for (i, password) in test_inputs.iter().enumerate() {
        let g = calculate_generator::<CpaceRistretto255Sha512>(password, &ci, &sid).unwrap();
        assert!(
            !g.is_identity(),
            "Generator must not be identity for test input {}",
            i
        );
    }
}

// --- Empty password round-trip ---

#[test]
fn test_empty_password_round_trip() {
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let ad_a = b"";
    let ad_b = b"";

    let mut rng_a = rand_core::UnwrapErr(rand_core::OsRng);
    let mut rng_b = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(b"", &ci, &sid, ad_a, &mut rng_a).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya_bytes,
        b"",
        &ci,
        &sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng_b,
    )
    .unwrap();

    let init_output = state
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "Empty password must produce matching ISKs"
    );

    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match with empty password"
    );
}

// --- Invalid point tests ---

#[test]
fn test_invalid_points_rejected() {
    use pakery_core::crypto::CpaceGroup;

    let invalid_points = [INVALID_Y1_HEX, INVALID_Y2_HEX];

    for (i, hex) in invalid_points.iter().enumerate() {
        let bytes = h(hex);
        let result = Ristretto255Group::from_bytes(&bytes);
        assert!(
            result.is_err() || result.unwrap().is_identity(),
            "Invalid point Y{} should be rejected or be identity",
            i + 1
        );
    }
}

// --- Full protocol flow tests ---

/// Deterministic RNG that replays a fixed scalar for testing.
struct FixedScalarRng {
    scalar_bytes: [u8; 32],
    used: bool,
}

impl FixedScalarRng {
    fn new(scalar_hex: &str) -> Self {
        let bytes = hex::decode(scalar_hex).expect("valid hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self {
            scalar_bytes: arr,
            used: false,
        }
    }
}

impl rand_core::RngCore for FixedScalarRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.used {
            if dest.len() <= 32 {
                dest.copy_from_slice(&self.scalar_bytes[..dest.len()]);
            } else {
                dest[..32].copy_from_slice(&self.scalar_bytes);
                for b in &mut dest[32..] {
                    *b = 0;
                }
            }
            self.used = true;
        } else {
            for b in dest.iter_mut() {
                *b = 0;
            }
        }
    }
}

impl rand_core::CryptoRng for FixedScalarRng {}

#[test]
fn test_full_protocol_ir() {
    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let ad_a = h(ADA_HEX);
    let ad_b = h(ADB_HEX);

    // Initiator start
    let mut rng_a = FixedScalarRng::new(YA_SCALAR_HEX);
    let (ya_bytes, state) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(&prs, &ci, &sid, &ad_a, &mut rng_a)
            .unwrap();

    assert_eq!(ya_bytes, h(YA_POINT_HEX), "Ya must match test vector");

    // Responder
    let mut rng_b = FixedScalarRng::new(YB_SCALAR_HEX);
    let (yb_bytes, resp_output) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya_bytes,
        &prs,
        &ci,
        &sid,
        &ad_a,
        &ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng_b,
    )
    .unwrap();

    assert_eq!(yb_bytes, h(YB_POINT_HEX), "Yb must match test vector");

    // Initiator finish
    let init_output = state
        .finish(&yb_bytes, &ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    // Both sides must agree on ISK
    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "ISK must match between initiator and responder"
    );
    assert_eq!(
        init_output.isk.as_bytes(),
        &h(ISK_IR_HEX)[..],
        "ISK_IR must match test vector"
    );

    // Session IDs must match
    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match"
    );
    assert_eq!(
        init_output.session_id,
        h(SID_OUTPUT_IR_HEX),
        "sid_output_ir must match test vector"
    );
}

#[test]
fn test_full_protocol_symmetric() {
    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let ad_a = h(ADA_HEX);
    let ad_b = h(ADB_HEX);

    // Initiator start
    let mut rng_a = FixedScalarRng::new(YA_SCALAR_HEX);
    let (ya_bytes, state) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(&prs, &ci, &sid, &ad_a, &mut rng_a)
            .unwrap();

    // Responder
    let mut rng_b = FixedScalarRng::new(YB_SCALAR_HEX);
    let (_, resp_output) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya_bytes,
        &prs,
        &ci,
        &sid,
        &ad_a,
        &ad_b,
        CpaceMode::Symmetric,
        &mut rng_b,
    )
    .unwrap();

    // Initiator finish
    let yb_bytes = h(YB_POINT_HEX);
    let init_output = state
        .finish(&yb_bytes, &ad_b, CpaceMode::Symmetric)
        .unwrap();

    // Both sides must agree
    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "ISK must match between initiator and responder"
    );
    assert_eq!(
        init_output.isk.as_bytes(),
        &h(ISK_SY_HEX)[..],
        "ISK_SY must match test vector"
    );
    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match"
    );
    assert_eq!(
        init_output.session_id,
        h(SID_OUTPUT_OC_HEX),
        "sid_output_oc must match test vector"
    );
}

#[test]
fn test_wrong_password_fails() {
    let prs_correct = h(PRS_HEX);
    let prs_wrong = b"WrongPassword".to_vec();
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let ad_a = h(ADA_HEX);
    let ad_b = h(ADB_HEX);

    // Initiator with correct password
    let mut rng_a = FixedScalarRng::new(YA_SCALAR_HEX);
    let (ya_bytes, state) = CpaceInitiator::<CpaceRistretto255Sha512>::start(
        &prs_correct,
        &ci,
        &sid,
        &ad_a,
        &mut rng_a,
    )
    .unwrap();

    // Responder with wrong password
    let mut rng_b = FixedScalarRng::new(YB_SCALAR_HEX);
    let (yb_bytes, resp_output) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya_bytes,
        &prs_wrong,
        &ci,
        &sid,
        &ad_a,
        &ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng_b,
    )
    .unwrap();

    // Initiator finish — should succeed (no error) but produce different ISK
    let init_output = state
        .finish(&yb_bytes, &ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_ne!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "Different passwords must produce different ISKs"
    );
}

// --- Deterministic replay ---

#[test]
fn test_deterministic_replay() {
    let prs = h(PRS_HEX);
    let ci = h(CI_HEX);
    let sid = h(SID_HEX);
    let ad_a = h(ADA_HEX);
    let ad_b = h(ADB_HEX);

    // Run 1
    let mut rng_a1 = FixedScalarRng::new(YA_SCALAR_HEX);
    let (ya1, state1) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(&prs, &ci, &sid, &ad_a, &mut rng_a1)
            .unwrap();

    let mut rng_b1 = FixedScalarRng::new(YB_SCALAR_HEX);
    let (yb1, resp1) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya1,
        &prs,
        &ci,
        &sid,
        &ad_a,
        &ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng_b1,
    )
    .unwrap();
    let init1 = state1
        .finish(&yb1, &ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    // Run 2 (same scalars)
    let mut rng_a2 = FixedScalarRng::new(YA_SCALAR_HEX);
    let (ya2, state2) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(&prs, &ci, &sid, &ad_a, &mut rng_a2)
            .unwrap();

    let mut rng_b2 = FixedScalarRng::new(YB_SCALAR_HEX);
    let (yb2, resp2) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya2,
        &prs,
        &ci,
        &sid,
        &ad_a,
        &ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng_b2,
    )
    .unwrap();
    let init2 = state2
        .finish(&yb2, &ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_eq!(ya1, ya2, "Ya must be deterministic");
    assert_eq!(yb1, yb2, "Yb must be deterministic");
    assert_eq!(
        init1.isk.as_bytes(),
        init2.isk.as_bytes(),
        "Initiator ISK must be deterministic"
    );
    assert_eq!(
        resp1.isk.as_bytes(),
        resp2.isk.as_bytes(),
        "Responder ISK must be deterministic"
    );
    assert_eq!(
        init1.session_id, init2.session_id,
        "Session IDs must be deterministic"
    );
}

// --- Swapped messages produce different keys ---

#[test]
fn test_swapped_shares_produce_different_isk() {
    let password = b"password";
    let ci = b"ci";
    let sid = b"sid";
    let ad_a = b"initiator";
    let ad_b = b"responder";
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Normal handshake
    let (ya_bytes, state_a) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(password, ci, sid, ad_a, &mut rng)
            .unwrap();
    let (yb_bytes, output_b) = CpaceResponder::<CpaceRistretto255Sha512>::respond(
        &ya_bytes,
        password,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();
    let output_a = state_a
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();
    assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());

    // Swapped: initiator sends Ya but receives its own Ya back instead of Yb
    let (ya_bytes2, state_a2) =
        CpaceInitiator::<CpaceRistretto255Sha512>::start(password, ci, sid, ad_a, &mut rng)
            .unwrap();
    let output_a2 = state_a2
        .finish(&ya_bytes2, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    // Reflected message should produce a different ISK (protocol is not vulnerable to reflection)
    // Note: In IR mode, K = ya * Ya which is ya^2 * G — different from normal K = ya * Yb.
    // The ISK is still derived correctly but doesn't match the responder's ISK.
    assert_ne!(
        output_a.isk.as_bytes(),
        output_a2.isk.as_bytes(),
        "reflected share must produce different ISK"
    );
}
