//! RFC 9497 Appendix A test vectors for the verifiable modes.
//!
//! Generated mechanically from the RFC text (sections A.1.2, A.1.3, A.3.2 and
//! A.3.3), so every value can be compared with the RFC verbatim. Field names
//! follow the RFC, with "EvaluationElement" spelled `evaluated` as erratum 8720
//! corrects it. Batch values are listed per element.

/// The server key of one (suite, mode) section.
pub(crate) struct KeyVector {
    pub(crate) seed: &'static str,
    pub(crate) key_info: &'static str,
    pub(crate) sk: &'static str,
    pub(crate) pk: &'static str,
}

/// One test vector; `info` is empty for the VOPRF, which has none.
pub(crate) struct TestVector {
    pub(crate) inputs: &'static [&'static str],
    pub(crate) info: &'static str,
    pub(crate) blinds: &'static [&'static str],
    pub(crate) blinded: &'static [&'static str],
    pub(crate) evaluated: &'static [&'static str],
    pub(crate) proof: &'static str,
    pub(crate) proof_random_scalar: &'static str,
    pub(crate) outputs: &'static [&'static str],
}

// RFC 9497 A.1.2.
#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_VOPRF_KEY: KeyVector = KeyVector {
    seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
    key_info: "74657374206b6579",
    sk: "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",
    pk: "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e",
};

#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_VOPRF_VECTORS: &[TestVector] = &[
    // A.1.2.1, batch size 1.
    TestVector {
        inputs: &["00"],
        info: "",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"],
        blinded: &["863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"],
        evaluated: &["aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"],
        proof: "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        outputs: &["b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c"],
    },
    // A.1.2.2, batch size 1.
    TestVector {
        inputs: &["5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"],
        blinded: &["cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"],
        evaluated: &["60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"],
        proof: "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        outputs: &["8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"],
    },
    // A.1.2.3, batch size 2.
    TestVector {
        inputs: &["00", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706", "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"],
        blinded: &["863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945", "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654"],
        evaluated: &["aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e", "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a"],
        proof: "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08",
        proof_random_scalar: "419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c",
        outputs: &["b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c", "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"],
    },
];

// RFC 9497 A.1.3.
#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_POPRF_KEY: KeyVector = KeyVector {
    seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
    key_info: "74657374206b6579",
    sk: "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07",
    pk: "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631",
};

#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_POPRF_VECTORS: &[TestVector] = &[
    // A.1.3.1, batch size 1.
    TestVector {
        inputs: &["00"],
        info: "7465737420696e666f",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"],
        blinded: &["c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"],
        evaluated: &["1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"],
        proof: "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        outputs: &["ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221"],
    },
    // A.1.3.2, batch size 1.
    TestVector {
        inputs: &["5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "7465737420696e666f",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"],
        blinded: &["f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"],
        evaluated: &["8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540"],
        proof: "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908",
        proof_random_scalar: "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",
        outputs: &["7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507"],
    },
    // A.1.3.3, batch size 2.
    TestVector {
        inputs: &["00", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "7465737420696e666f",
        blinds: &["64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706", "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"],
        blinded: &["c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715", "423a01c072e06eb1cce96d23acce06e1ea64a609d7ec9e9023f3049f2d64e50c"],
        evaluated: &["1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874", "aa1f16e903841036e38075da8a46655c94fc92341887eb5819f46312adfc0504"],
        proof: "43fdb53be399cbd3561186ae480320caa2b9f36cca0e5b160c4a677b8bbf4301b28f12c36aa8e11e5a7ef551da0781e863a6dc8c0b2bf5a149c9e00621f02006",
        proof_random_scalar: "419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c",
        outputs: &["ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221", "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507"],
    },
];

// RFC 9497 A.3.2.
#[cfg(feature = "p256")]
pub(crate) const P256_VOPRF_KEY: KeyVector = KeyVector {
    seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
    key_info: "74657374206b6579",
    sk: "ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6",
    pk: "03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462",
};

#[cfg(feature = "p256")]
pub(crate) const P256_VOPRF_VECTORS: &[TestVector] = &[
    // A.3.2.1, batch size 1.
    TestVector {
        inputs: &["00"],
        info: "",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"],
        blinded: &["02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da"],
        evaluated: &["0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2"],
        proof: "e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c2664f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa",
        proof_random_scalar: "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
        outputs: &["0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1"],
    },
    // A.3.2.2, batch size 1.
    TestVector {
        inputs: &["5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"],
        blinded: &["03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd"],
        evaluated: &["030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1"],
        proof: "2787d729c57e3d9512d3aa9e8708ad226bc48e0f1750b0767aaff73482c44b8d2873d74ec88aebd3504961acea16790a05c542d9fbff4fe269a77510db00abab",
        proof_random_scalar: "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
        outputs: &["771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18"],
    },
    // A.3.2.3, batch size 2.
    TestVector {
        inputs: &["00", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364", "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"],
        blinded: &["02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da", "03462e9ae64cae5b83ba98a6b360d942266389ac369b923eb3d557213b1922f8ab"],
        evaluated: &["0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2", "02bb24f4d838414aef052a8f044a6771230ca69c0a5677540fff738dd31bb69771"],
        proof: "bdcc351707d02a72ce49511c7db990566d29d6153ad6f8982fad2b435d6ce4d60da1e6b3fa740811bde34dd4fe0aa1b5fe6600d0440c9ddee95ea7fad7a60cf2",
        proof_random_scalar: "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963",
        outputs: &["0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1", "771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18"],
    },
];

// RFC 9497 A.3.3.
#[cfg(feature = "p256")]
pub(crate) const P256_POPRF_KEY: KeyVector = KeyVector {
    seed: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
    key_info: "74657374206b6579",
    sk: "6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2",
    pk: "030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3",
};

#[cfg(feature = "p256")]
pub(crate) const P256_POPRF_VECTORS: &[TestVector] = &[
    // A.3.3.1, batch size 1.
    TestVector {
        inputs: &["00"],
        info: "7465737420696e666f",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"],
        blinded: &["031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0"],
        evaluated: &["02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2"],
        proof: "f8a33690b87736c854eadfcaab58a59b8d9c03b569110b6f31f8bf7577f3fbb85a8a0c38468ccde1ba942be501654adb106167c8eb178703ccb42bccffb9231a",
        proof_random_scalar: "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
        outputs: &["193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592"],
    },
    // A.3.3.2, batch size 1.
    TestVector {
        inputs: &["5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "7465737420696e666f",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"],
        blinded: &["021a440ace8ca667f261c10ac7686adc66a12be31e3520fca317643a1eee9dcd4d"],
        evaluated: &["0208ca109cbae44f4774fc0bdd2783efdcb868cb4523d52196f700210e777c5de3"],
        proof: "043a8fb7fc7fd31e35770cabda4753c5bf0ecc1e88c68d7d35a62bf2631e875af4613641be2d1875c31d1319d191c4bbc0d04875f4fd03c31d3d17dd8e069b69",
        proof_random_scalar: "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
        outputs: &["1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c"],
    },
    // A.3.3.3, batch size 2.
    TestVector {
        inputs: &["00", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"],
        info: "7465737420696e666f",
        blinds: &["3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364", "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"],
        blinded: &["031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0", "03ca4ff41c12fadd7a0bc92cf856732b21df652e01a3abdf0fa8847da053db213c"],
        evaluated: &["02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2", "02f0b6bcd467343a8d8555a99dc2eed0215c71898c5edb77a3d97ddd0dbad478e8"],
        proof: "8fbd85a32c13aba79db4b42e762c00687d6dbf9c8cb97b2a225645ccb00d9d7580b383c885cdfd07df448d55e06f50f6173405eee5506c0ed0851ff718d13e68",
        proof_random_scalar: "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963",
        outputs: &["193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592", "1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c"],
    },
];

/// The hedge randomness of the known answers below: `0x01..=0x20`.
pub(crate) const HEDGE_RAND: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

// Hedged-proof known answers: for the RFC key, inputs and blinds of test
// vectors 1 and 3 (by index), the proof `c || s` the public `blind_evaluate`
// path must produce when its RNG yields `HEDGE_RAND`. Computed by an
// independent Python model of RFC 9497 plus the hedge (not by this crate),
// and cross-checked there: each proof verifies, and the `voprf` crate accepts
// it. They pin the exact list of values the nonce hash covers.
//
// Deterministic-blind known answers: the blinded element for input `0x00`
// and blind bytes `0x01..=0x40`, from the same model.

#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_VOPRF_HEDGED: &[(usize, &str)] = &[(0, "4ff71280c9263d900de34d9a7bf67d2340df0cd26f3289257f6483c2e84e550361730827d96fee8f332eeb7b20824728f213f40c162a2e9372a5258d64f1370c"), (2, "969360a28e54282fe99aa04adecd7077c8eb4467b1fd6321ea11dc53f29bca007dabedc6ed495e4c8c422bd8410a1bbca810020baec05194bc0ce25bd460a002")];

#[cfg(all(feature = "ristretto255", feature = "hazmat"))]
pub(crate) const RISTRETTO255_VOPRF_DETERMINISTIC: &str =
    "6e368dcdb48354d7d3b3a8d7db6897c7f738a556f99e535fc9575f0bd18a1529";

#[cfg(feature = "ristretto255")]
pub(crate) const RISTRETTO255_POPRF_HEDGED: &[(usize, &str)] = &[(0, "82bf57f8c2f1dfdb76434a4bace6ef4db88eb24a9be3a98b1c8af13da01c0507c2bcf457d2a2801734432dea12d1388f7f74568322b6c5446e3431f52ca3a101"), (2, "042026e990709eb57857baf23d8f86ae4f2abb932747a2a855a7a905388fa90f7153ed53e70b625584b6635240de7c6254f245f4282a46f6e18ca043de8bc708")];

#[cfg(all(feature = "ristretto255", feature = "hazmat"))]
pub(crate) const RISTRETTO255_POPRF_DETERMINISTIC: &str =
    "22242dfef01b2fed042b6005cff6c7b64208b707074d0d343bef11bfb8138c7a";

#[cfg(feature = "p256")]
pub(crate) const P256_VOPRF_HEDGED: &[(usize, &str)] = &[(0, "d2cd82acb69bb7ab29c05613d0a00d7c56738f47574b557ecaac0da7f838092c65b4f6de880eafa12ff759a9c80db8ecc9e479438680069a289ac6953e968967"), (2, "270e531bb15edb9ad3cfc9dc084a624618e7ee784fa0bd73a41bc06a5b12b8120f999604fff715bcabed4cd57837d598091dd7bc0147049aa57853268bb16f78")];

#[cfg(all(feature = "p256", feature = "hazmat"))]
pub(crate) const P256_VOPRF_DETERMINISTIC: &str =
    "02d3544a71c5001476c7169ca3808f91c4940dee57e82f899c92c9e2e6da48b068";

#[cfg(feature = "p256")]
pub(crate) const P256_POPRF_HEDGED: &[(usize, &str)] = &[(0, "9cab84be753eef8cf4b068b71a0bfabf6ad140246da8d009a751cc53d0cbe067e708cc37f25b92b90366da1a2bbf067ee58b52168d8508bf08b76fce575539cd"), (2, "fa514e8dac2c2626644184f1e2f6a2b822765e5253eda51cb9fc55bfbdada6f09bb347f52f86211f3a7a23772fed33edcb8ced743264d6092b727544047be19a")];

#[cfg(all(feature = "p256", feature = "hazmat"))]
pub(crate) const P256_POPRF_DETERMINISTIC: &str =
    "02e50cce2b30d8a6ca398ede001b8be97192e67b39b52229f84cb7ce451c3e2fe7";
