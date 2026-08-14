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
        "e0cae52f4b68e6e59e8708695a46840f683ca2ee2bfbccaf66e448e8689541e8",
        "228124eb7fcf75c9070aea3d990ae763f4b592aa4c95222e51d6df71c2df512d",
        "5dda73280531cde9b7825cc9f738ae75fa4376365e1e79adf4efba02ae2f5f87",
        "238ad96c40ae7d847efd83a650d06d051273e82efdbbbaebfc6ef95e93b0f519",
        "74e508297a90ef320cc617ee4106dead3daa876145a6f2e7c95dea42905b8461",
        "cdaa9f0b53cc79134d67fae273dccaabfabdaeb15a3a7dd4cac71fcb58656c8a",
        "a29c15fbd52c4fa422ee3e421bdc7c90bea053fe43947ceb1539b545bab59e37",
        "d987d13e2c665605bd5eae9cfa499c200670a4a0f6c47e7955910e3fc2ff8e0f",
        "009ea650923a0c10069bff732b9de52f8a57fc38c49804aaa1cbf34fcaa9177d",
        "57a9a66ecb90def2b2b357926f3a35eac42643dd077794891fc297fc9bfa9565",
        "812556c138b606f2effc3e14b2b4b3fe97c3a0338db415ef6e89b7a2d9d8c902",
        "01cf233ace984676374a08a8fe5f13c4659a7c79faa5c5aab00139d9439ae68b",
        "c4b0b40ffbf74dd32bb32ae7041abd54b69f89e2ec47a1db7b6ff1178e168135",
        "ed8ae34bb299ab82e6ab69310f5d94523cbd7347b556763e6c7e3f07cc54f9a4",
        "fd8771454df8edc10239faaff461d8d4e1159ee5a30919f66962c5d4c340ef22",
        "7493c458c28b19990a7abe864c26c36bb5fdf390fb43307a4d9b140c5be8808f"
    ],
    "circuit_digest": "16c57f84549eac3e4d7a8b3796c353c7d4177364ba993b1e7e4770cd310762c6"
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
