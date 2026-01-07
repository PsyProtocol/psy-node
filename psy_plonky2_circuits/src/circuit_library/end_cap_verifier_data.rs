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
        "d9d103eeb49c3555cce282ebd426cb3622eba7a556786ea02e2362d11e2dc940",
        "5f0bbc23dd41437f298cffd1d323127d76b664f0cc8bff760a1ef67cf8d6061a",
        "b68f4edbdf2046ac40eb58b8e11ff765cbc16acf686c6fcf182160cca75fdc09",
        "3893b4b99cac66a43690b62ad6c1f852fa90cdba11c5166ad8c0ea07c8e3981c",
        "abdca59a9ac606b6f41767c098f1274ffe58650e743ec272c07f2a914c3af7a4",
        "41e9f58a3176dbe66f6df08ec34427a664106e4f83e38a3302c8dea555de02e5",
        "8884c288edce2eb54fdb16255afc19ac1002dd9be035a152c6a157a4b251cf62",
        "eef27653be25d152e8406484c4810cc9aa1d0676ded29488d851fe32f91b8109",
        "bae1e0c4d7bf46a01fd0ab981df59752f973ca6b43a938c8d9d1fcd1cb8e80a4",
        "c883a4a9d1462d846924a20cb3dd4d5b7ad1bb00d7d0f99d241c27403bd5fd68",
        "489e7c7a5efb052eff1c4df8ec4f23f967b3921331307ec40b819d2397075993",
        "846ef0a83f6f8869a6a730fcc19ff5f938789c2ff6dc8936d8458e23469c66a6",
        "34e5ca436b1778172795353a3dbaafd40794ea47c4924fe34c47b0b00f6d3623",
        "22f01dcc534f53d526b9fa0110b2e84a417f2d96466366fa7458d49ec18b78e7",
        "e9a23b18c0408c03ccbed0aa006f89f3e760d4f9219aece5c9af980e15ff4f0f",
        "4c03ed5a1e85deb5c709815b96b8f1e696beb9c28ea19df4f71fb694581c9a15"
    ],
    "circuit_digest": "687003b6ace592d967489e08b00423e70431578fe34837a0de1d4cf687223299"
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
