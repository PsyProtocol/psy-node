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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{
    "constants_sigmas_cap":[
        "66a089b85c53a76a7dc5811d25d893ad5638e88b1517968e2cfc2d636e262db6",
        "3fba88f3d8bc860b21c0eba984c16e2fe27091e3c202858ab034c84150980a6a",
        "aee6684c997bc2fde21f7e8ee9f7fe66a41e30b8f7c194c6aee1af70b621bc31",
        "e41c993238b31cc778b0168c604a9b3f060f877f92ff5bc75636ed1fe3728ac1",
        "b4e843b5e96bd4c9da58eb9f3d2d9bf0ce0ea95fdddbaf3f2ac507fe178da7d9",
        "50d0642c3fb0be4c59056acadcb2baae1c7383116e79ef9e9710ca390f6259ed",
        "9be2b042ed57704d663ae92affd56b5ee5f778a02e6bc11ad1c0422763407060",
        "cfe04ff776141dc334601e235a8cfd7fa10516ae76763a7521ce9570ea53514e",
        "2a48afc424b1b148bfa9593871d6627dc2eded0b67d0a3fcf94aa90c7b4a6bfd",
        "17184bf0d05d8ca7abb677acc64cd36190df68ffd94a4cc1040dbebfcc2a94f0",
        "415a85cfa5bd9c5bce60f3f424f44d323ff84206266c9dfc5140c7fd27974839",
        "b0563c8c1c99586c046a5c1124202e7efb63d98e4cd68c0c0c039119750ebde3",
        "668d2c064b184db7432a7cef806d8dddb38079a685d04f254537200b9ab6ab33",
        "a11b1a0b4cc7a720d60fbf6b5a0f7289d0a1bad36e86248a03198e659487266f",
        "4336fbdad171bc6d4599d413e4defacb4646dc0e3eedbef23791d555c24ac08e",
        "b6b99af8fe93004fdcc1bf693bb11b4e7b60c1cea5dc6793730d2c02fcbac1a3"
    ],
    "circuit_digest":"155a537127883b716afcbb8c4bd37946ad7c92dc96e84a9f63767a8e15baff8f"
}"#;

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
