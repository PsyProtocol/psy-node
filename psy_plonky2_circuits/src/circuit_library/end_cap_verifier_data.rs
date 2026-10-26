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
        "43c51664c381f49ccc4584cc2e7a6d43d9240ccbe06375047c021e47ecd6f684",
        "c227fc97b9afaff4f83a6cf1ea709ba14099181d6cac9e17cff101d6ff73e91a",
        "3f91b1f8a66992ddab13636718bb387eb0253ab1edeef2fb5590019007b71108",
        "adeba3fda531fe0a061b1fda72e16b96e57b5004ee1a7cfaae8adc4762e4699c",
        "988c24bab5dae45e3923d70491b4b1077af5ffe85993dfccb8c029facc67a17a",
        "efe89920435ef9dd42201d5f85b3c94875afe655f4c73b70658f53aac65d249c",
        "a67f8590e67a05e22eefbe9a718bcc2efb07b4bdf61bb459606d02458f857b6c",
        "c33e7ea5bac60ed48d9546955d61e6462c3915c559366186def8739d4e6c448d",
        "3a4c0dc3f94a94515bbb49063b0798c633d0d465486ca26e52f8b3f28f230b1c",
        "a2a57e6a9fe462a0402a5424557ce1b70de023725713748be42d74bf7386df86",
        "ff77879a06d0d8f2e3571c4345a37c63c1078fa54119de24ca32120cd1f4ffef",
        "e5bdc13e2f52be79b6985634aeee3e25d5c0efe785d2b6379f5bceeed0e6111a",
        "7f297646467e637756725a9c1fcde590ade4d73859b53d0e40853fb0e778aea4",
        "3ebc3d5ec8502ba1200437063cc5bac62c7189b1f4c1b6174b16ed05a77360c8",
        "8802c0e8222ff877397c3b83756ab4c6ace84a4da4c2f111e609374cc04d8a6c",
        "b74611baff625c90647e8edff11909324c1157f0116424732e4b8bd28315a00c"
    ],
    "circuit_digest": "65ba308a80b71ec118a47088f6967df9843aeb07340801febfd71f4e0778aaf6"
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
