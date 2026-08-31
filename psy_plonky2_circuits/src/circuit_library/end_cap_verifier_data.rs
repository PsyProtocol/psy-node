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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["d812579dd61f45901cfb1f9f0b19ebea3f124f38b80d4936a5d9dde21680acfe","a4e7ebedfda489acaedd413ae0b8a0628ff87a26d5a08c59aea94549e42d188b","d382837b6e90d855460bcc63f0a6a4228a1e69baa64cd6be43065eee03c55f3e","4a1488cb45da80a7c41dee201a1a2181fcea053f4d687bd2e480fdb7082ff5eb","bda432defae1b624bc4c90e6386d710423c388919899acbec14457302741ad10","bc10a214da70dca96cb79fda12b4d49f33715e9ee8b1616feee6b2f444463cdb","861d2e6d7e18e26311217793039ada1b7c24edf717a33a65b7f98455dc2acaf2","747acc9458f3019d0ee9772f9fcd70d8a024395c313cd05e45e17991ca0cef78","603dcfbb450337dbcbec71f2a0bc28f49018412d2d91b332bac08e5d45acc020","6f8acba4dba6e03bd7ac4c681e34c873699923775605f4ae67633f09c0672319","335c4176e2179c3cf7f15b5a6d8c490942dc15aa0e0316c612476576b6a491bd","a520169c5f2828ad116b6a81f0e024f24741540dcf8ac7f2fa596bf64e760894","12d82594a7b2d74561e4207547eef4098cc72311c8ad1a52d6fb3f11274e75b6","d9427d05e7439335838305327763761f26679bee7e8fe0763c8f7be254f96ea6","f75dc143b7771883fef5c2b5f32b5b61ec1fce46f4442467c9cfd05297fa0f08","6aa56fdd05683bac04ed682c1864bf50812187c728ab9461236c05e471360737"],"circuit_digest":"d950e6d6a211fad223406fafc011338e52c298d6da80120b6a0cfbdd5bc20a1d"}"#;

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
