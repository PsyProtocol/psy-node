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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["93a4ee80bb07dd157eb0c40ec0463edbe04c8ff052fda12f676c418127148dc5","c9d1ab527b7964358adf41cfa617034bfab1e2ca510f7b46e5f1e8b54ecf9125","b62340c1eeab63b290bd3799ab6228e0c2c4683e354db4111795bfcf36f3a490","81996aecf51f9422118d4d4fe20b79c573fdee54bb206be4081711b47bd020ad","72d779c361b1621eca5f59432806868f8a72c007f195b5d9838bc067c2dac85a","39a9f1cc9a14a303992377bf660ec6faaae5e6000b9ddadab8374e0afd21b28a","87df53e8a7b9e7c7be9a995ec2256e971ef247ea3948582be6139cd4eeaec773","5a6e2dbedf62c635bace657f221b339c5071daa6364afdcbc8df68e792d9d542","bfed8fc4ad06ba6cfa71aeebbf925be02c6d6a0dd93d14db015948aeb693b9cf","119595cb2a7db86e5573b7313541d09484693774006a973ca414cfe6f4bc47a3","d84db7c585ff92139c6c8a149f97fa44617d4077122ef424241363e8d0ae5dba","ac56ce81eaec4a59b2237209d05dfab7a0e434069ebdb3e29e92e5b4a1944e7b","54bd016dc5833801b958fe89d39916b48c0bcce7c72b10e64c0d593cd0f7d579","a80197763776618f521aac9c0b237c2d5595784cfc0b79b1f767189a9b01a2d6","1c9890b859faeaf10792c07139c3fa9b0dcd01c3402b8bcd699c5c4140f3267f","8acc522eb517dc296e04b8772444eea9dfbb30aaa3bfd2730d98ba7ad1dc98a9"],"circuit_digest":"6934680402ad9d0521feb981c72e3990f98e8082c4dd9d758ed27d7142cbb57b"}"#;

pub fn get_end_cap_alt_verifier_data_for_network<F: RichField>(network: PsyChainNetworkType) -> anyhow::Result<AltVerifierOnlyCircuitData<F>> {
    let end_cap_alt_verifier_data_serialized = match network {
        PsyChainNetworkType::LocalDevnet => END_CAP_ALT_VERIFIER_DATA_SERIALIZED,
        _ => return Err(anyhow::anyhow!(
            "EndCap verifier metadata is not validated for network {network:?}"
        )),
    };
    serde_json::from_str(end_cap_alt_verifier_data_serialized).map_err(|e| anyhow::anyhow!(e))
}
