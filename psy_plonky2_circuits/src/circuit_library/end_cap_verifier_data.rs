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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["2b61a038537069f39ff9e0d35609306096074faa586e17b528ed5236ded578af","287ea9bb7a09a958235c696022b90ccaddabf9ef2342a1f5d0c5308ddace65a5","40b9246b767c5d9703e976c1baafd67a69ab570a964e442aa51d0ffcc21da509","ad3098726dc4d07528f42e9537eeee49289275417cdf7c33b2d9a3c55d0eb105","4773635be77e220a70a983391d6937b1257f9999e62a2e1cfe7eb2224941812c","805b83b14f030095925c5176afad54c715c989914e908d8556b01a89335ccb76","7ff15c0fd39384575eaafd87b81beb8878f268fe9943fd4f9c10f681197daa67","948e813e1961e6ea21d364704860572ed0d4b21f6e50f6738bb325741711530c","c58043af184f2268e11b8b37b796356f35b74cee11cef0bc9289ca94e11d1a3c","40f503aad2932aa60fe5dad9ed0ba4022009f5523270f5a36c15575c9b4194e9","ca4952391d10db6145c258b839da2ea2b1610d6c65ed5d6d0f789812c8bb8abc","7f0aebe38b96bd626146be8448ac5a452ebb460aacafca3493f995de193c83e5","cd43937fdac75934b96ce892597ef475f4101461910c2d8fdcf2d0ac01b8ab82","f9fb9779c5fcbc53f1244630af420acbaed7bef132a4a425351a5b18943be1ef","f1707df8bcd911b4e2b4688d97449b6a86a58bae83dcc3f7f204e7e292e7d9d7","60b46b117624020e8dffd63a0833171bae79440d5595b38e9b15aceafc91f5db"],"circuit_digest":"b9bff3f8d4f31a5667f3161215f2c3d511b9cd37832eb4f01a45bf922f7726a9"}"#;

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
