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
        "f01aa6f5b3f67c2eabb8bd10c6df95faa3f7af6ca4dafdc16939a233eb905fff",
        "8fa6f872593f21dcbba69515d49e4960b8e1609d0b25e49e1fc803bcc21c2ffb",
        "4048c45dbfdf8fabc2628597a65979307172b695ffeeec0aaa2ceec904c86206",
        "5483c557cb0bf2792af3f91eaee906e2679d8a1b67db90a2b7f5175617a5d979",
        "150c63864846e801d4b3c12e07110d51efd3311e8afbc0aa3bc28c284d62619f",
        "941ba5e05fa601e5e8d7321225102b9e6a8d9aa1ad6920307cf92f55d26d3ccc",
        "2761897b377c63bd57447c332093fdacf91684f73ce52be2668b94b0bb6a34df",
        "b5aa78a1a832f5c682788a9fa0f1bd1fb47bbf3f8b8f5bbc25ee8aae5691e3b3",
        "7751d0d2b3ad142998ee58e29452b4da0136deb2ee92ace9d2cb9d45c3c5297d",
        "7a540bbd302502f67d92c7c9ba4d1af5f171ed8eb9d0f2b0feb28a886591d677",
        "34886637994aeca328d027e1c2bf7b9335b236358158a24d97d707084db5bd50",
        "2f358dc739df2765e728c600c055ce1a04d80ee01f419eae0e2eb97e155f25e4",
        "a4f28d5748a4d084385cd51ed0726a50ece61639a2c0a1bc1e729d0a49e0b863",
        "b168565254e1db89dc36e822873c2c2a27cc7c464d542a769403470af340fc33",
        "7cbe7916052af1bf3023590979ba21d893bac838f64b654568574944728c315a",
        "33d532ab79250dd3e40fe0b2d0f219ac1425841daa56ca517cfdf7f3cecabafa"
    ],
    "circuit_digest": "6185847e276388deaf9b47e73fefc41abb6240a13372c736b1b66c373a69afa8"
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
