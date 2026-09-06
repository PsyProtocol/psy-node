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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["dc9d714c7a68f1632220ebb34e4cb546b42aadd3ef64ef7bd3957e31cc0796c1","7e86640d66f2a3d132a7e7fdcdd3a033295130fae4babaa36fe7f889f5d9063a","34aebf2e53114ee54e259ad65f81a8b059d592af22495bbbc9ef38f29757edf9","fa8ebb392632fb55688f469dcd9838a3a3feaa17a9ee878198bcedcc4410c5d0","bfd9963e773b553f8ba8780fd78a1f938fb0ef72f81d394052d9b841e244f306","da6d3fcfedff2d58187a43ccdb6feb91c3086d66d475bd92aa0a671340089a88","9af9d6745b54fb6dbf16b81b8b45422d190a7ac3beede25072aa7c76461d9a0f","724ad6cd87bd9f715d10fb543c485cd9f42f33f89eba6df45481686458318bb5","a3ced24e72bef605ae276cdffed444b7de2e710d3c6d52a4a3f5fa39ebded87d","c4b6b7521fbd5e6a58fb36c7d88f33aa6ec7a2e3cbc1a085183a4cc8aa5fad0e","5636d18dfe55e46a8f6cbbb29ebd136ef6f51c76de5208d1d0279a9ed36186fa","3111c258be91a8086c1dff43269fcfb290cb204b2bcd12061f11108101331ec9","ef8db766e7b8dfcbc771895960751c9dc0521bd00aebe3fe78f06d94e026d8ae","834dbee923b17dbef3784cc0f8dbc5897aac3c3fcba6f07a2cf40c28980d2d4f","4904426544640d74c15f7ad8851664b1d26ddea1c10194c134eb59d8207e9279","76dcb9208672ea2b53587342c205e31db7dc1f75626260b794fdffeed1a9fbbd"],"circuit_digest":"ad5fddfa7138ea9fa39e8ecd9021873ffd3ecab018feff181701266a443dffa0"}"#;

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
