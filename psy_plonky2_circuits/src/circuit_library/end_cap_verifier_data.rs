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
        "cd194e038a19a9058b0f5462260b74584daae9b8aba0e6f1b49313b980616adb",
        "80ec73267ec0bddeec66221274f92801da7e80f2984e16330dbdeafd5605fd82",
        "29a443aea0875ca3ed5f0adcb25b34a2bc01ae46eb81d8136b1f8c81bdfc33db",
        "9ead31e4ab43be71044d19da10dedbaed62675486766766874d7a0bed84d927a",
        "140559150290cee35527f6f69c7bfc4c3505e9450eb9845694cceca036519236",
        "33474f7e42581132a329de3aaee232c1a7799401612dcb6ebdc479325fa92c99",
        "c48e4c2ee0b8f7cb6b5664c1b6265f0472fc52606653c8e00704e5dd456d0a50",
        "971fa3b12d6c909e2b1b4e5a06aad6200aa2614226e231b1b0f52df623e04619",
        "eae3ffee472f4d8ebe06ec0c69d2939fd18cc554c87a5891e708e873349446ad",
        "b8fa4c24ae570cdd2f4d30dec6f9268ac56f7ae798afd9ec020d57a56f1c2cf6",
        "905e3ce84bc221cd2eef47912dec70ff6867a2e228f3cb65509f1c7f10c28972",
        "c3a82f831cafd00183163ebc1c2c2013151ed9678c48f2c6e56b0912de93077f",
        "36e5c47286325b53a1d43536f89a08d2b358fba957827c75fac3197a3db5e9a1",
        "80e93a965a9f29093e646990018d248a7eee04f1a739029450e11cd72b87d610",
        "08464c24ffe1773686a08df6e10610bdd3d93bae13366e7b3296bcb8f1870466",
        "7b92b1b16268c694e149849e561953e6e083012ab286fadb1b7434f05db0c326"
    ],
    "circuit_digest": "bacd8005c7bc6ad9cb4d6e9b03e991f0f2964fd56dd7d96a154e1fc1a194ab76"
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
