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
      "0f1f5d005a23071d248536c4b75d77298cff651eb8afe857d04a6dc7e958802a",
      "9dce55ec665f02be9e3209d4d3d1f5db11243790228753c0e11822a19eacb75e",
      "c7e64376def5c7b62d72364ab481e3378b82dd18a30d24212d220747645e9835",
      "c7c94cdc4e46c1e69920f3cb00731d470466fe51a9e8848a6b24c12007db79a7",
      "f0e10c76202aed19885d847ac8fb12e4b28969929888a70189308e9ddb4d3388",
      "1e6ce30100c6e549d51c8590264e5a12656c6362a11f77bc02d0ae24ad78eb2c",
      "b38fafc155dcdb0e8aa1266e8ba560c3587f50f1eadf922085c823cd5835d8ed",
      "11417ebe78ba32fc5250ff8c3e0d296d69411e1a8ae0a6428a8073e3efa44181",
      "6eeb1ebec85666d74e245a7975cf41912dd55142fd4f326e8289643bf9b60136",
      "87581ada713787100fc39273f94ae9484c07b99aa6f16ef037a25e818f51cca9",
      "9f7f2cb499768cc2505525205e68bed4ff52cf4f9cf7482d6e08e8490cd1d927",
      "2fb5038eb32eb823da9ee56a4767397936f7b71fc9a3e2cd2ba4ea204c354225",
      "6637a821f319fef659ec9aca02c6f9e624198bad4756b9f134513155b84b8d53",
      "f4641382a0ceee995c63a1e48c80800b1ab05e95663fd052e0e8e6a16d91061c",
      "d003887f689dbf7fa3720e21c0d876e3b340e6a161329f21118c2ac36b767b7b",
      "0a5a8a16308f6de55e2c477f3f8ca207fddfb20bb14de988ff898e193db62c8e"
    ],
    "circuit_digest": "0a86f3f951f1741712dd955bfd75c24e9e7e713265d63bc31631891085c38086"
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
