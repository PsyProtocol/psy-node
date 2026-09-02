use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable},
    },
    felt::{QFelt64, ToU64Value},
    protocol::core_types::{Q256BitHash, QFHashBase},
    utils::QPGenRandom,
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{AutoImplementFallbackPsySerializeCanonical, FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    p2p::{validate_goldilocks_limb, DOMAIN_VALIDATOR_LEAF_FELT, ProtocolReader, ProtocolResult, write_fixed, write_u16, write_u64},
    v1::qdata::{
        checkpoint::{PQEDCheckpointLeaf, PQEDCheckpointLeafCompactWithStateRoots},
        user::PQEDUserLeaf,
    },
};

// =================================================================================
// Signature Proof Type
// =================================================================================

pub const SIGNATURE_TYPE_ZK: u8 = 0;
/// Temporary baked rotation configuration until network config propagation lands.
pub const REALM_ROTATION_PERIOD_CHECKPOINTS_PLACEHOLDER: u64 = 10;
pub const REALM_ROTATION_VALIDATOR_SUB_IDS_PLACEHOLDER: [u16; 2] = [1, 2];

// =================================================================================
// Validator Leaf Hash
// =================================================================================

/// Validator Tree leaf: `H_many([PSYVLF01, validator_user_id, node_sha_limbs, bls_sha_limbs])`,
/// mirroring the host `ValidatorLeaf::leaf_hash`.
pub fn realm_validator_leaf_hash<F, Hash, H>(
    validator_user_id: u64,
    node_id_hash_limbs: [u64; 4],
    bls_hash_limbs: [u64; 4],
) -> Hash
where
    F: QFelt64,
    Hash: QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    H::q_hash_many(&[
        F::from_u64_value(DOMAIN_VALIDATOR_LEAF_FELT),
        F::from_u64_value(validator_user_id),
        F::from_u64_value(node_id_hash_limbs[0]),
        F::from_u64_value(node_id_hash_limbs[1]),
        F::from_u64_value(node_id_hash_limbs[2]),
        F::from_u64_value(node_id_hash_limbs[3]),
        F::from_u64_value(bls_hash_limbs[0]),
        F::from_u64_value(bls_hash_limbs[1]),
        F::from_u64_value(bls_hash_limbs[2]),
        F::from_u64_value(bls_hash_limbs[3]),
    ])
}

pub const VALIDATOR_SUB_ID_BITS: u8 = 8;
/// Height of the checkpoint validator tree: coordinator user-tree height (12)
/// plus [`VALIDATOR_SUB_ID_BITS`]. Empty-tree root is `get_zero_hash(this)`,
/// which is not the all-zero hash.
pub const VALIDATOR_TREE_HEIGHT: usize = 12 + VALIDATOR_SUB_ID_BITS as usize;


pub fn validator_tree_index(realm_id: u32, realm_sub_id: u16) -> u64 {
    assert!(
        realm_sub_id <= u8::MAX as u16,
        "realm_sub_id exceeds 8-bit validator-tree range",
    );
    ((realm_id as u64) << VALIDATOR_SUB_ID_BITS) | realm_sub_id as u64
}

/// Fixed chain-domain felt for RealmFinalizeGUTA actions.
pub fn realm_finalize_guta_chain_domain<F, Hash, H>(chain_id: u32) -> Hash
where
    F: QFelt64,
    Hash: QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    H::q_hash_many(&[F::from_u64_value(chain_id as u64)])
}

// =================================================================================
// Action
// =================================================================================

#[pderive::serialize_clone_f_hash]
pub struct RealmFinalizeGUTAAction<F, Hash> {
    pub chain_domain: Hash,
    pub checkpoint_id: F,
    pub realm_id: F,
    pub checkpoint_tree_root: Hash,
    pub validator_tree_root: Hash,
    pub root_guta_header_hash: Hash,
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for RealmFinalizeGUTAAction<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let roots_hash = H::q_two_to_one(
            H::q_two_to_one(self.checkpoint_tree_root, self.validator_tree_root),
            self.root_guta_header_hash,
        );
        let combined = H::q_two_to_one(self.chain_domain, roots_hash);
        let combined_felts = combined.to_4_felts();
        H::q_hash_many(&[
            combined_felts[0], combined_felts[1], combined_felts[2], combined_felts[3],
            self.checkpoint_id,
            self.realm_id,
        ])
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> RealmFinalizeGUTAAction<F, Hash> {
    pub fn action_hash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        <Self as QFieldHashable<F, Hash>>::qfhash::<H>(&self)
    }
}

// =================================================================================
// Public Output
// =================================================================================

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct RealmFinalizeGUTAPublicOutput<F, Hash> {
    pub chain_domain: Hash,
    pub checkpoint_id: F,
    pub realm_id: F,
    pub realm_sub_id: u16,
    pub checkpoint_tree_root: Hash,
    pub validator_tree_root: Hash,
    pub validator_user_id: F,
    pub root_guta_header_hash: Hash,
    pub root_guta_reward_tag: Hash,
    pub action_hash: Hash,
    pub final_guta_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for RealmFinalizeGUTAPublicOutput<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let final_guta_header_hash = self.final_guta_header.qfhash::<H>();
        let checkpoint_binding = H::q_two_to_one(
            H::q_two_to_one(self.chain_domain, self.checkpoint_tree_root),
            self.validator_tree_root,
        );
        let authorization_binding = H::q_two_to_one(
            H::q_two_to_one(self.root_guta_header_hash, self.root_guta_reward_tag),
            self.action_hash,
        );
        let committed_fields = H::q_two_to_one(
            H::q_two_to_one(checkpoint_binding, authorization_binding),
            final_guta_header_hash,
        );
        let committed_felts = committed_fields.to_4_felts();
        H::q_hash_many(&[
            committed_felts[0],
            committed_felts[1],
            committed_felts[2],
            committed_felts[3],
            self.checkpoint_id,
            self.realm_id,
            self.validator_user_id,
            F::from_u64_value(self.realm_sub_id as u64),
        ])
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> RealmFinalizeGUTAPublicOutput<F, Hash> {
    pub fn final_guta_header_hash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.final_guta_header.qfhash::<H>()
    }

    pub fn public_output_hash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        <Self as QFieldHashable<F, Hash>>::qfhash::<H>(&self)
    }
}

/// Canonical 410-byte wire encoding of `RealmFinalizeGUTAPublicOutput`.
///
/// Field order is the frozen P2P finalize-output spec. Hashes are raw 32-byte
/// little-endian limbs via `into_owned_32bytes()`; felts are `to_u64_value()`
/// then `u64_le`. Length is fail-closed: anything other than 410 is an error.
pub fn protocol_encode_finalize_output<F, Hash>(
    output: &RealmFinalizeGUTAPublicOutput<F, Hash>,
) -> anyhow::Result<[u8; 410]>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    let header = &output.final_guta_header;
    let mut out = Vec::with_capacity(410);
    write_fixed(&mut out, &output.chain_domain.into_owned_32bytes());
    write_u64(&mut out, output.checkpoint_id.to_u64_value());
    write_u64(&mut out, output.realm_id.to_u64_value());
    write_u16(&mut out, output.realm_sub_id);
    write_fixed(&mut out, &output.checkpoint_tree_root.into_owned_32bytes());
    write_fixed(&mut out, &output.validator_tree_root.into_owned_32bytes());
    write_u64(&mut out, output.validator_user_id.to_u64_value());
    write_fixed(&mut out, &output.root_guta_header_hash.into_owned_32bytes());
    write_fixed(&mut out, &output.root_guta_reward_tag.into_owned_32bytes());
    write_fixed(&mut out, &output.action_hash.into_owned_32bytes());
    write_fixed(&mut out, &header.guta_circuit_whitelist.into_owned_32bytes());
    write_fixed(&mut out, &header.checkpoint_tree_root.into_owned_32bytes());
    write_fixed(&mut out, &header.state_transition.old_node_value.into_owned_32bytes());
    write_fixed(&mut out, &header.state_transition.new_node_value.into_owned_32bytes());
    write_u64(&mut out, header.state_transition.node_index.to_u64_value());
    write_u64(&mut out, header.state_transition.node_level.to_u64_value());
    write_u64(&mut out, header.stats.guta_fees_collected.to_u64_value());
    write_u64(&mut out, header.stats.da_fees_collected.to_u64_value());
    write_u64(&mut out, header.stats.user_ops_processed.to_u64_value());
    write_u64(&mut out, header.stats.total_transactions.to_u64_value());
    write_u64(&mut out, header.stats.slots_modified.to_u64_value());
    write_u64(&mut out, header.total_aggregation_proofs_generated.to_u64_value());
    if out.len() != 410 {
        anyhow::bail!(
            "realm finalize public output encode length {} != 410",
            out.len()
        );
    }
    let mut encoded = [0u8; 410];
    encoded.copy_from_slice(&out);
    Ok(encoded)
}

/// Strictly decode the canonical 410-byte Realm finalizer output.
pub fn protocol_decode_finalize_output<F, Hash>(
    bytes: &[u8],
) -> ProtocolResult<RealmFinalizeGUTAPublicOutput<F, Hash>>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    fn read_felt<F: QFelt64>(reader: &mut ProtocolReader<'_>) -> ProtocolResult<F> {
        let value = reader.read_u64()?;
        validate_goldilocks_limb(value)?;
        Ok(F::from_u64_value(value))
    }

    fn read_hash<Hash: Q256BitHash>(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Hash> {
        Ok(Hash::from_owned_32bytes(reader.read_hash32_canonical()?))
    }

    let mut reader = ProtocolReader::new(bytes);
    let chain_domain = read_hash(&mut reader)?;
    let checkpoint_id = read_felt(&mut reader)?;
    let realm_id = read_felt(&mut reader)?;
    let realm_sub_id = reader.read_u16()?;
    let checkpoint_tree_root = read_hash(&mut reader)?;
    let validator_tree_root = read_hash(&mut reader)?;
    let validator_user_id = read_felt(&mut reader)?;
    let root_guta_header_hash = read_hash(&mut reader)?;
    let root_guta_reward_tag = read_hash(&mut reader)?;
    let action_hash = read_hash(&mut reader)?;
    let final_guta_header = GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: read_hash(&mut reader)?,
        checkpoint_tree_root: read_hash(&mut reader)?,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: read_hash(&mut reader)?,
            new_node_value: read_hash(&mut reader)?,
            node_index: read_felt(&mut reader)?,
            node_level: read_felt(&mut reader)?,
        },
        stats: GUTAStats {
            guta_fees_collected: read_felt(&mut reader)?,
            da_fees_collected: read_felt(&mut reader)?,
            user_ops_processed: read_felt(&mut reader)?,
            total_transactions: read_felt(&mut reader)?,
            slots_modified: read_felt(&mut reader)?,
        },
        total_aggregation_proofs_generated: read_felt(&mut reader)?,
    };
    reader.finish()?;
    Ok(RealmFinalizeGUTAPublicOutput {
        chain_domain,
        checkpoint_id,
        realm_id,
        realm_sub_id,
        checkpoint_tree_root,
        validator_tree_root,
        validator_user_id,
        root_guta_header_hash,
        root_guta_reward_tag,
        action_hash,
        final_guta_header,
    })
}

// =================================================================================
// Witness Input (private)
// =================================================================================

/// Private witness for the RealmFinalizeGUTA circuit.
///
/// Proofs arrive as fixed-order worker child dependencies:
///   - input_proofs[0] = root GUTA proof
///   - input_proofs[1] = wrapped recursive ZK signature proof
#[pderive::serialize_clone_f_hash]
pub struct RealmFinalizeGUTAInput<F, Hash> {
    pub root_guta_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub root_guta_whitelist_proof: MerkleProofCore<Hash>,

    pub checkpoint_id: F,
    pub realm_sub_id: u16,
    pub anchor_checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub anchor_checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots<Hash>,

    pub old_realm_root_proof: MerkleProofCore<Hash>,

    pub validator_user_id: F,
    pub validator_node_id_hash_limbs: [u64; 4],
    pub validator_bls_hash_limbs: [u64; 4],
    pub validator_tree_proof: MerkleProofCore<Hash>,
    pub validator_user_leaf: PQEDUserLeaf<F, Hash>,
    pub validator_user_tree_proof: MerkleProofCore<Hash>,

    pub validator_public_key_param: Hash,
    pub signature_proof_type: F,

    pub validator_fee_delta_proof: DeltaMerkleProofCore<Hash>,
}

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for RealmFinalizeGUTAInput<F, Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            root_guta_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            root_guta_whitelist_proof: MerkleProofCore::qp_rand_gen(),
            checkpoint_id: F::qp_rand_gen(),
            realm_sub_id: rand::random(),
            anchor_checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            anchor_checkpoint_tree_proof: MerkleProofCore::qp_rand_gen(),
            checkpoint_tree_proof: MerkleProofCore::qp_rand_gen(),
            checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots::qp_rand_gen(),
            old_realm_root_proof: MerkleProofCore::qp_rand_gen(),
            validator_user_id: F::qp_rand_gen(),
            validator_node_id_hash_limbs: rand::random(),
            validator_bls_hash_limbs: rand::random(),
            validator_tree_proof: MerkleProofCore::qp_rand_gen(),
            validator_user_leaf: PQEDUserLeaf::qp_rand_gen(),
            validator_user_tree_proof: MerkleProofCore::qp_rand_gen(),
            validator_public_key_param: Hash::qp_rand_gen(),
            signature_proof_type: F::qp_rand_gen(),
            validator_fee_delta_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for RealmFinalizeGUTAInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash + PsyIOReadWrite> FallbackPsySerializeCanonical for RealmFinalizeGUTAInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.root_guta_header.pio_serialized_size()
            + self.root_guta_whitelist_proof.pio_serialized_size()
            + 8 // checkpoint_id
            + 2 // realm_sub_id
            + self.anchor_checkpoint_leaf.pio_serialized_size()
            + self.anchor_checkpoint_tree_proof.pio_serialized_size()
            + self.checkpoint_tree_proof.pio_serialized_size()
            + self.checkpoint_leaf.pio_serialized_size()
            + self.old_realm_root_proof.pio_serialized_size()
            + 8 // validator_user_id
            + 64 // validator digest limbs (2 x 4 x u64)
            + self.validator_tree_proof.pio_serialized_size()
            + self.validator_user_leaf.pio_serialized_size()
            + self.validator_user_tree_proof.pio_serialized_size()
            + 32 // validator_public_key_param
            + 8 // signature_proof_type
            + self.validator_fee_delta_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.root_guta_header.pio_write_to_io(writer)?;
        self.root_guta_whitelist_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.checkpoint_id.to_u64_value())?;
        writer.psy_write_u16(self.realm_sub_id)?;
        self.anchor_checkpoint_leaf.pio_write_to_io(writer)?;
        self.anchor_checkpoint_tree_proof.pio_write_to_io(writer)?;
        self.checkpoint_tree_proof.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)?;
        self.old_realm_root_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.validator_user_id.to_u64_value())?;
        for limb in self.validator_node_id_hash_limbs {
            writer.psy_write_u64(limb)?;
        }
        for limb in self.validator_bls_hash_limbs {
            writer.psy_write_u64(limb)?;
        }
        self.validator_tree_proof.pio_write_to_io(writer)?;
        self.validator_user_leaf.pio_write_to_io(writer)?;
        self.validator_user_tree_proof.pio_write_to_io(writer)?;
        self.validator_public_key_param.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.signature_proof_type.to_u64_value())?;
        self.validator_fee_delta_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let root_guta_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let root_guta_whitelist_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let checkpoint_id = F::from_owned_u64(reader.psy_read_u64()?);
        let realm_sub_id = reader.psy_read_u16()?;
        let anchor_checkpoint_leaf = PQEDCheckpointLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let anchor_checkpoint_tree_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let checkpoint_tree_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let checkpoint_leaf = PQEDCheckpointLeafCompactWithStateRoots::<Hash>::pio_read_from_io(reader)?;
        let old_realm_root_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let validator_user_id = F::from_owned_u64(reader.psy_read_u64()?);
        let mut validator_node_id_hash_limbs = [0u64; 4];
        for limb in &mut validator_node_id_hash_limbs {
            *limb = reader.psy_read_u64()?;
        }
        let mut validator_bls_hash_limbs = [0u64; 4];
        for limb in &mut validator_bls_hash_limbs {
            *limb = reader.psy_read_u64()?;
        }
        let validator_tree_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let validator_user_leaf = PQEDUserLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let validator_user_tree_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let validator_public_key_param = Hash::pio_read_from_io(reader)?;
        let signature_proof_type = F::from_owned_u64(reader.psy_read_u64()?);
        let validator_fee_delta_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        Ok(Self {
            root_guta_header,
            root_guta_whitelist_proof,
            checkpoint_id,
            realm_sub_id,
            anchor_checkpoint_leaf,
            anchor_checkpoint_tree_proof,
            checkpoint_tree_proof,
            checkpoint_leaf,
            old_realm_root_proof,
            validator_user_id,
            validator_node_id_hash_limbs,
            validator_bls_hash_limbs,
            validator_tree_proof,
            validator_user_leaf,
            validator_user_tree_proof,
            validator_public_key_param,
            signature_proof_type,
            validator_fee_delta_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    RealmFinalizeGUTAInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> AutoImplementFallbackPsySerializeCanonical for RealmFinalizeGUTAInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    RealmFinalizeGUTAInput,
    { parth_core::PF, parth_core::PHash },
    realm_finalize_guta_input_tests
);