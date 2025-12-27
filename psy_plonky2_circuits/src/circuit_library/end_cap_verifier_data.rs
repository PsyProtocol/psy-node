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
        "1b5856de6801c92bb0ad2fd11368056a9a5d0dad82aff9945c5bae6897565b27",
        "1d244fedb2f6501cb68a99df5790ead882cd9dbf00dc10f01014a19878e5f13d",
        "a91d9395232831406551ea542996f10df9323493bb9a622ca172f9a08b33420d",
        "ddec529e5c0eda0802893f88ee339b4ddbe91159054d7cc452087d96a25a720d",
        "b1fe8e8aa32f722753a7138fa7c50ddc131e3f69e794df655e72ab05c27132b6",
        "24d48a0e67b1379268ff20367f208ceaf2050f4ac0d71539b79528e7ed21d816",
        "b0a24455f824e7521022f21da1ed16678ad4b0e4f38223fb3029e2e70df9f1f8",
        "f4ee0801387a8601ebd6cf9fa1286f323cea556be58203be1e03a4cb789fa2db",
        "906d34ee2421a469caabd07ba347ab60879ecb2e2fe6792a41b46ffdf5cbece0",
        "1ba3bb0b9afff4cd09899de1fd4143fca5f2a20ef452a8dfd13e0588c5991c61",
        "0537f4536348db599b5b7ff80d30ab511a7cfb11d7e6b9279a479f02e3a184a0",
        "3ed832defddf3cc38d484ee6f9e8349330b5784d54fae75b92e30bcda9552634",
        "1f1fa9c1c3a517fc172488989d0102ba7ef1ed6504922ef3f2a927c14b8cf353",
        "85bf989c4979c5fe13ff5c771d643a0a761a350189eb402223abfffacdb4bc82",
        "8081f52d148499ddb3c33fa96af8dd8144fa03178cea5c0c63bacb27f66f9254",
        "edc979c7efa9df07e9084d01e4e5b4e5d585f0987495c12e29913ba26ce5de68"
    ],
    "circuit_digest":"c81b3e7dd47fc105d031515c373a22ef4876723c41781fe5849f76a6614aa25f"
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
