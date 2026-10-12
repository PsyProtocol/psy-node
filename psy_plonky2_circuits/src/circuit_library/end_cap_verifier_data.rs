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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["339138489c6fb99ca49d6311511694c137b12b8b39c5192d1ff50f20c9c0c158","8834e2d172308a9a53d9a73908cd965b8ee1ca01adaa65f4120eba00363c25e7","aa01a866e3991f8216e0a67e2318cf50b2381685fd440498023a2f1badbad174","0736130dcb07274ccd132bc218088b7af255df0067abe91211fed476b4c543d7","62551e987fb06449398985c229e93b7371a400bc89835b7fb310db82df6c3576","3a0f2949dc02944a5fba017b3c84b8d2762ce0593f4379ff94ab762a9f766a54","a99705fc796493634a115dba99026c1a2505f55a657807288540ac0dcffda9c3","d36e0f4a28e52b037c3a8abfe5e3cee69de202133813827982ffb5fbd136d509","c255202015c83bc74c27cc6f818116451096fdaecc6eaa32647d8b10cfc51e93","38636813552512a4b19599b9f4da016d922d16c74c7c6ad1e4473b70e68254aa","8aada40bdbb200ecfdc97558b3d3cef4feb759ac545ddad33cec5d1910769a2f","7be9429cb8e32925facb4d7ebbe07f260a692742c76a5c6a03c38efc8a67a9b3","693465cb20f4891c498bb3f159ee6f3ea59b0a48795eb595e1fd89d606313fb1","12ebaf1a857a1eaaac701203c4c3d71bea25a66470979806de2ecd117b3048f9","31f7f5687693bc934d482447aa17872f1bcd6e4030d70b698227854e467e2b55","8eb6c4bbd76e0d44d9247205cc91832b9ced9bf5e79d6a6e5f2ca82452749ad1"],"circuit_digest":"f5beee615287d3c7417c786a6157eb001765a3f06c03ad105fedc1d624992121"}"#;

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
