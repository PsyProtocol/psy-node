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
        "90404dafebe9cf0608915a0e376a031e77d7d5761c08fedbfab17b70aff921a4",
        "ef020b653d66c7bb377753f10183dc3816f071d488179214956c62c73ec93e69",
        "321a3101474bc4893d642ed4a553ce245e1cef6130a2ee8ea5dfc78463bec1f6",
        "3a6a31f82f0949cf4d042b91d19d7d856521399f046f8ce810baa1d5f024a283",
        "a6b9ac0aed18f3e29c5fb6acec9172868b20feb7e6231ceda222e3b30ec1cc94",
        "d3de52777dc23a03ef517a4f4303a4b07e4c71406fbc09791a4525c1acf3a85f",
        "135b42134ddcb0e199fbfdbcf726007a8f4bbcbb712c7a4d11c48f7b166d460c",
        "486d8ac221ef9c22a05abd9dbb506cc37424c26f9743219d9e1141573100e846",
        "968b3eab5a084ea8d9d58d9012c8af06e0242a023f0f9bf3664d38efda38ec2a",
        "579e577e92b5e5c6e992e10facd597f1059a45fb36f769c2d4a272d06664a321",
        "3c6a69b46bf3cb985bd549697c617630e168fb57c20e91a9cbe01dcc4704b031",
        "5a46c06aba206e3ce36b1411ed52136e91d8e1090e8fe818251c4a9dda12f199",
        "9d6c22f1d284e7ac4fec8db4a197039732a736720f859022b30f97c6915951d5",
        "43ce7df7ac03847cd71923e2759fefe008a6524fa2adc02f94d82a702080f383",
        "548388361b03f0a3d8211f300a70829d654948271c716069b33b40d5cf20d408",
        "ad778c77ce7002a7762866b6cc14c8175eaecf6729dbc98af417ecf127d63e48"
    ],
    "circuit_digest": "820921582066952842870ea02f4fc104bd01d445353a6de44e16a0c4bec085c2"
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
