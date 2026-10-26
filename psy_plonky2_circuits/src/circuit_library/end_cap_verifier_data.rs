use plonky2::hash::hash_types::RichField;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_plonky2_basic_helpers::verifier::alt::AltVerifierOnlyCircuitData;

const DUMMY_END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#" {
  "constants_sigmas_cap": [
    "75e43fe3eb30167fcb5157afc75aa867b15e1dac6d784c55aa2a4c812a9e72de",
    "18fe157043baa32efbadbc217ec0d381b457928e5b6a7d32cc629510c9d5c13a",
    "ee8fe8d2e3923fee800d92d4bbfbe1be2c9ff3ebcbd642c386423be697d2e3f8",
    "d73d5b79305d2aa63dea475fbda5b29dee6751fe602790e734e3c68f979afbca",
    "66aa5e48ad2156357ab6397e1f8034806af2b9dd4294fa3150c76234141942cb",
    "5f6c5d092df067f37024da90aa3f242481046097d0b295ba75245b4998391714",
    "46e42a956d05e63ec8bba968dedc01f501534f683f42c392a9d84c03362846da",
    "47b09cf057e7a9ba847649248f5dae5c44eb7ca021fc7f0d1eb0e0708a3b1476",
    "7d2701e51e8c699e07652745851f59304f5e7363b8e47808ff958cfd0fca8dda",
    "ae8ad8c909f4bcd321cf72cd7253b36a26d8bcd6fbe8bcf2cd075e8629ccc148",
    "41160fd3e15c02f8ea4c2624a817cc15a902a4fb3c40d8fa672ee0dc7afa6cfa",
    "f8b46aa81046dfb300e663753c7c8ec7260183ed4bb531a30a294967ab262597",
    "65b63a76bf11b1b655de3538594ec5127fe145e1abacf206cb53aa0c5e81d207",
    "31039274aa406e48e75155a7e05d2698dee5f1f239718d20910dae3faae59794",
    "3fd615f34dc310728c36e590d93e6261d5674cb2a83ed69a5415070d3cda0151",
    "4cbe726f1aa6ed74f0ae58455902feb18ee2ead5631f04286bd392f26f77860b"
  ],
  "circuit_digest": "b2947f9dc3f006c6a26242b11ea186e8443a2243955a648e53075346be800782"
}"#;

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["51401ebb4bd26e6880f6314841c13365660e6e0ae67e368d5e710a3e8a053664","666abd3bb4929fc2b68c64f4551ad40530b0e6e6c5e55c0ae92d1577b96f16da","a16d7e0690db6eea2bab9c8d36b6e71432e3d45fddec3e6ebc1dcdf90d3c5727","70b544ed2d847f11d7a85a3e8a7f72b5e6f16ea70658da55e38140480db0bf79","a526d238bdbe64fa5251cb6a438153964abab74237ec1bc010ad2a49ecb38576","3d8c4b14e0915e31a72b6720eed20db35d1063241d84b7a0b16d9e6f9c6ab344","4e1cff3ebc53ee7acac2452947144d251326f9ae346a40b55788e98c52770f2f","364e70c5db1acfb7f16e32a6067ebce0e1f4183ec7980a3003a1efbf48e67f23","9db724f85ee6e63cb733d9c210bbafc7555736a419828fb818d5bb153c3e8769","8b7ffe318a7d9b513dc39db4913dfeeaeaa8acd1e805d41135126a2543a8b3eb","7752cc3c28e5f5ffc529492a164e72e18efa0ba8a70981887ab9a4942a4a5a2b","54c0760072c64fab1465f394521fab80c56108b6a5bf7ddca4cd901aba332523","67ab80e6a67930cfcd26021ca604e3eb68e4559d777b6904537a2871602a1e7f","e1a518d2814195977e1206e8a3310939ddb0ea1ba5e516a91d5ab546ab7204db","46d97a2f530e0b585e7a3fa8b907aa574597b184d4c03f4d04d6e3e34890daf6","d47564e84108895530e02c285928881cd02996816775129387f91895312f2681"],"circuit_digest":"6743ce7e2664987d7d2b7d16a6538c137b9e894334aa9370788b1003abece164"}"#;

pub fn get_end_cap_alt_verifier_data_for_network<F: RichField>(network: PsyChainNetworkType) -> anyhow::Result<AltVerifierOnlyCircuitData<F>> {
    let end_cap_alt_verifier_data_serialized = match network {
        PsyChainNetworkType::LocalDevnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::PsyTeamDevnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::InternalDevnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::InternalTestnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::InternalPreProduction => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::PsyPublicCanary => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::PsyPublicTestnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        PsyChainNetworkType::PsyMainnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
    };
    serde_json::from_str(end_cap_alt_verifier_data_serialized).map_err(|e| anyhow::anyhow!(e))
}
