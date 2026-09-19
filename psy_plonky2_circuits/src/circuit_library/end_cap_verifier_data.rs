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
        "ce67e257c3d5e9ae81c84d8428af326c1125ea5089e537385bce9f617015ff3d",
        "502092995c03ece8d743ecea7ae3b64b873ac3f2f62cd15d69a7b7dc202732ca",
        "0f83dc3b0140221ad1d718c4a55099c3a10351223435cda6a3662642895209ef",
        "265ede766a549c3f6a5e0557c77f63c2e076245e8867f99ed2e87d78a4b4bafc",
        "a1db6bbc8eb8d4d3cdb367089aee8652032e649f35cf07079e85d65a63311585",
        "67eb532af2292abf61d6f759d120c8d15a86a5113fb19eedc3421b33c5b477da",
        "7082be961cf2c1d0b67c8cf40bb15bf919ecd3c44bb4e785764c1d35cc017d10",
        "51ff2309b50ed1cf0b20b975766ed357d7845cce3ce9fc19cec5ed4115cfe331",
        "f7b437b27237063e073b70cf65bdff379cadafcea820f8eb132ad5bf54e2af88",
        "2710630f6de56f102e031c70f57fc8ff39b146c6d86648e2473663d7736c10bc",
        "0a31e73968cce4107de81f09f47fe3eaf101aa644aec3bde21b3b7395329a775",
        "bd96bce44d1a69e4fc13b80e7c28def6f0ebad4f7e07c471cf8e2f7cd4e65020",
        "7a58719e4f01a5e9a14acd03f6f1863218771ec2b589aa40072d0ec820d26952",
        "2542a81e4d30abb3369de607c6c1d75a5ea5a1076ed1deca4c0ea609a5432fd6",
        "8aab1f443bc041af82b9941671b375f1c25e6ebd30fc35761f30d8b13caf04a5",
        "f6f315c0a4bd7ade0e5f077061adf226664a78411fccbdf115703f07257ecd51"
    ],
    "circuit_digest": "75852707a0e55fd51096ae2cf80046189cf6bc44595ab1a690c8922af3403051"
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
