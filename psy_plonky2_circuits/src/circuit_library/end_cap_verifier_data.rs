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
    "constants_sigmas_cap": [
        "50355d42412d2fdc7d504e117f599b399cd2252d028ed40bf031c0dcb1d69a0c",
        "0ad44d9e835f9a91a87d4c265d854cd2624ccfb00d2bb11b2908cbbc42adc293",
        "c49b206f82c7c2edf4b133c0488f59687d96f8221a2ed3353b4c6c6f2ed6757b",
        "01412a65156c4de3dfc6430e6652009da4d35f936cf8704f13ab2883a5047b12",
        "6bce2bf53d08e18ad1fae6c50b7992a1d20a6b1bc670a8cb485abadced180908",
        "27b0faf556e9bb754b7761d40c403170a859d5384e94a3b3a6613b2d41bc9a70",
        "0d8773f92825ebfedf189c6ab847dc21cf21a2e34ea1ae078d0b61db57cbd8f2",
        "83d707d0de1f043ad3e1c54916642955f0708fa55787abe03f02f6662b7e9680",
        "551d710902d24d05503e8c4bca28a9d7b56e41b3c6fda18bcda4c2aee363277d",
        "790f002eae60fe658b1d3a44b51a549c8e7cd68ed9a579f9b1209e8cad42fee1",
        "7582e5a5426749d8c44036f681029887f6528b4735161a4559f54f329e5cece3",
        "0888ff6f911382353a16d9d7d5c96ef456cb3e9b59c7b2a649454c0316ce737b",
        "554646ef7fb976fa77cda9eef8fad7a8849db3f4f3c2c0b8ac166ae2608b20ab",
        "bbf247f5182b0633674007e3d6ccffd99e50bdb24bf220e6e25b7fa6a5891234",
        "b6af55400fb4447719173f2cb24ff836b3e1ce2e1e72bfd9c352d8274229bc35",
        "2d437fb73225e3a4df333baacebf4e2d43c058b7fc4c88a0f0441b48b13292df"
    ],
    "circuit_digest": "9a5071a3236d4dcd9fead2d6f994061efaa0a86c5ffbe65c6eb444a26303c968"
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
