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
        "b4c94a1939aaf51ddb9b31fbbc95ec74567b227668cbed68daea0ad504579bc9",
        "fb3bdb2ce60211408ab7e570a5cae17a44836016a824ffae610c0c9c06dd9868",
        "c3c8f5f20355bdef624874d8ae69209257b96f337d2ccd6efbff80879b54f0c2",
        "5fa8140f81002c08b71dd80523e39b5ea5304d7a5fcb396589fcd9c1164ae398",
        "e1456aa9bebc4ac09aadb237d3ef0f4da86e65408f26b80a81083829c9847d94",
        "55593739bba4ae8c3635a6566d615c42014f2f2a7de4c6a69c10acd72b957f1f",
        "3fc698c09173894b2ad07c246ef5922010eee6f434debefe6afe40c05eebdf00",
        "4351c1d760a0401c3ee72b41667b4208bd9b7ce51e7578975a139382d82da338",
        "7bd907b5ef9306e236e50b773e76edf2972d641042117c5e9f3603c3d39b50ee",
        "11fa565b0775a9689414026ea6d8e8ce1cac7cde07a50b530ea3cf627284c756",
        "4f364bc6091771eeb3a3a42026e69d30307c1de6b66a6d34d6cd4b72907b3ca3",
        "dc91d3dc42c104f1f99261164b7eb8b8d369087613f0fb504706c7cd62c9a6a5",
        "2bf85d69c36828788ebe7b6840bbf8b86b819a1a8004c713e3415b3d8f9cf6e5",
        "dfc731b4ef499293c26d700bcf4983b47eeaf81b7ed8e10707152f1fdc789feb",
        "ee63d210d26b279b4dbf24ec8039ae333105773cd9e0e0046bd00e7873afa3d5",
        "81189d96eb87c8c9b33afb1cd791ab96fbe4ade468e13a0053f7f1a6a742167a"
    ],
    "circuit_digest": "2232bd459037336305e932dbd368449ef96ad7e89845379c34b3310d23033d21"
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
