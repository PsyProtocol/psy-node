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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["2925958f4fe1822604284d243944cf2f13c9b6e2642ad7d7942495d59cef97fb","10e24fea3adb473c12d493e6377de230377fe0f557b13585936abe498f6f1afc","acf1d52956cd044decab1b00d4426ca0a606aa7983d0f96bed2657952eed86a2","a42c8aba27b7997e3c91d1c96d9046665fbfa8876d92ba9bf94db1bc4a70bd33","515564384a777713a0be52f80c8741faa9895e5293960e310a240b54d5f799a4","c9fc5f0eb5cc2db53e0a942f23076e35de3b5e2f89408c2cb4b447d2b79c31b4","3290bc15ada3ad7b3309a34495de8de2e2d3cfa685e218b35ee7487603434840","c31a37439d62b3bf06de795031f3a4ea9dd02aed56c0b818cf2e3fa2be52626e","ac6fc7dc3a3fca41fb4cbac7eb635aa38f8f63d19d1dfdac4806ec34ce91beac","4472931b2c2b22a8e68e95a2a345cf5519181eaf1e727b51ee354a941ee5478d","ce2f801f5714246e5057fdb43fa44ae7fd835166d576cb18191f4517727b6735","27cb009ed4283d7158294de908debc6cae6bb38b02999fd901c57b8c91b5c4e4","39d236d8e234bb714b55ce43a953a233d8bea78eb614a7e33c7594ee4acd76e1","6f8b22afb2bdbcccd3aef6908b4909e3b39b814bfb026d1ad38c394376ac4e41","d1fccec92edebb53de7b1b84035ab4c74fa1b940f6ede6603fb5f4173b8773ad","cb038b9269c32e330584be907332fb73390b63126418de965267f5653b1ca0ae"],"circuit_digest":"9a23e71b3b3eae431c08238375c8089a5b20c2bfd570947c119253a7d9e7649e"}"#;

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
