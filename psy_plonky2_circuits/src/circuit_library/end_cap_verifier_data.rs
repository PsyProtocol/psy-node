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
      "c86feb99f7013eaf5cfb4d178892b7df183d74c0af163cbd48028a597b133e5e",
      "3910ee84260433475e3e055664564d06122ed21670e2f235198867c3270485bb",
      "dd08659e9e52007ea764ee06fabffd375503644b9a51c809d877c52e96e3b325",
      "7aef7a37da269361317d9eceded48469c8b92eba19a374b4619a564f93ea22d2",
      "4de0352b66dcd547cc3c988807bc1f845cdcf19390f1347a8704bab9cfc0a23a",
      "4c1c44648ae179bcdf7bba3d8175d5f9841784ae6825a8cda21bb25ea14dfae7",
      "a6eb5354db416d4cf48bcb08e095cb01de3da6fcfd9f3ec0fb5cce80d93bc150",
      "0379560f3a0e67d9ac362961cf033abd5e7cd6532eb840062e78f9db55374adf",
      "be9bf7caf78fe71bada854c0bb43f490c24f528c8960908663fd3773bd1efb32",
      "40f476af4456e8a3a7090f6a18200b57ed83300603388c9be77b798c98350374",
      "955be7904428c2be491b9206ea2459047e789c2fc3b11348fc8aeffc7c346dde",
      "5aad1eb4b5716f84b71c586199cb8328957f7a6ccdfa6141574ba551e35ea733",
      "068736cea601a05cd5ce668e8f9eef7cbd26c957653b841c79c4a76da9a3c523",
      "10d56b20b27a183c878454013e715746a3b3b8e63ffb79db71f0196502ec4314",
      "37ff0ae51043275985ab52e5cae4dd18e1955a559d9160c4442e55f47ad5c8fc",
      "4f7e206d1e4f1be201835c87470473fe9dea4393d654a93871ad9449121a57ea"
    ],
    "circuit_digest": "c09f99a1e061591b41396e72144e5b27b8fe4419fb8695f8245bc86bc70b2635"
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
