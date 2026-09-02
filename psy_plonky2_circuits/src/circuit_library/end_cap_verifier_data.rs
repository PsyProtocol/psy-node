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

const END_CAP_ALT_VERIFIER_DATA_SERIALIZED: &'static str = r#"{"constants_sigmas_cap":["58a7bff577c10461b26fc1927da4f5de1ca48300056ae3179eaec6ba4acaadaf","ba029a9fd4a88ab8cfb2fce5a8a5058084ad7a05ddfb4e0a9645e50bb2536c53","11695324394f84f49e507fbc418eba186e07098ded12c1077ebf9939cda30fe0","fbd70a56c16e03206712aeb4bf166262ada6876458cdf460123f075715d41c1e","d0f8a3d83b556eeb27618b9391788c7be2f86d4a4c0346fc6e82e3c6a563e1f3","4597444fd8234697953eaede7183d7f92df0702997b17bba25e0742b99b8ddb2","f09bb813c02fb148a7f10ef1ca573b6a09c7bb58907dfe50f5c81ffdf388436e","4a04709b114571b6e8aac46ac9f758209ee87c75e99eb29f4c44324f447f5ef3","5d1d55942a3fb9fd0be963741ada224c7a3da330381e9eff64c796bd91416767","79437af6e750f85618b8d80afc30ff600d9031ca2de6aac6629f5ae759b5eb46","3c64223381a98f6e05587d1a62e9a3c84e984edd07d055c70bce82ace51fe29b","ce16940b9acb00c453dd37b4fae296cb437763648fca9a1410f060ec0a47de2c","e2d055977411c38b1a09a09a00eb07ccd66646ff1497215a91f0a52053e5ad3b","88b42f0df7e35e89f989313cfa09e5a89d991d6ab0dd3a42800f3e2dc8e1ff08","5b8c2228d98fadc62504d58f8856716d5fc71a45b08f8fe6e8ec528a8a2ecddd","550fc42be726c297c0953761e2f2eada6b5144a3ed19bb735c31c834924a20b6"],"circuit_digest":"aff7604ad4404c7203ef6ab5886144d92a5eb4b5eaef1c933c61fc7b5dc0e7cf"}"#;

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
