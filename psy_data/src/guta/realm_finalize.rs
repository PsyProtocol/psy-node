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
    p2p::{validate_goldilocks_limb, validate_hash32_canonical, DOMAIN_VALIDATOR_LEAF_FELT, ProtocolError, ProtocolReader, ProtocolResult, write_fixed, write_u16, write_u64},
    v1::qdata::{
        checkpoint::{PQEDCheckpointLeaf, PQEDCheckpointLeafCompactWithStateRoots},
        user::PQEDUserLeaf,
    },
};

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
pub fn realm_finalize_guta_chain_domain<F, Hash, H>(chain_id: u64) -> Hash
where
    F: QFelt64,
    Hash: QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    H::q_hash_many(&[F::from_u64_value(chain_id)])
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
// Finalizer Binding (off-circuit BLS authorization material)
// =================================================================================

/// Exact wire length of [`RealmFinalizeBinding`]: 410-byte output + 32-byte tag.
pub const REALM_FINALIZE_BINDING_WIRE_BYTES: usize = 410 + 32;

/// Public binding payload required by the `psy_submit_guta` Realm admission gate.
///
/// It carries the actual canonical circuit output plus the finalizer worker
/// reward tag needed to recompute the circuit reward root. It contains no
/// signature and no secret: authorization is the Coordinator-verified BLS
/// certificate over the proposal identity derived from this output.
///
/// Wire encoding is direct concatenation in declaration order, exactly
/// [`REALM_FINALIZE_BINDING_WIRE_BYTES`]; decoders reject trailing bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmFinalizeBinding {
    /// Actual canonical finalizer output; required, no default.
    pub output: [u8; 410],
    /// Canonical field-hash bytes of the finalizer worker reward tag.
    pub finalizer_worker_reward_tag: [u8; 32],
}

impl RealmFinalizeBinding {
    pub fn protocol_encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REALM_FINALIZE_BINDING_WIRE_BYTES);
        write_fixed(&mut out, &self.output);
        write_fixed(&mut out, &self.finalizer_worker_reward_tag);
        out
    }

    /// Strictly decode a 442-byte binding; rejects wrong length and
    /// noncanonical worker-tag field limbs.
    pub fn protocol_decode(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() != REALM_FINALIZE_BINDING_WIRE_BYTES {
            return Err(ProtocolError::InvalidLength {
                what: "RealmFinalizeBinding",
                got: bytes.len(),
                expected: REALM_FINALIZE_BINDING_WIRE_BYTES,
            });
        }
        let mut output = [0u8; 410];
        output.copy_from_slice(&bytes[..410]);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[410..]);
        validate_hash32_canonical(&tag)?;
        Ok(Self {
            output,
            finalizer_worker_reward_tag: tag,
        })
    }
}

/// Reconstruct the actual finalizer output from the exact planner witness
/// artifacts and the root GUTA reward tag.
///
/// This mirrors the circuit's constrained output construction bit-for-bit and
/// must stay in lockstep with `RealmFinalizeGUTACircuit::expected_public_output`.
pub fn finalize_output_from_witness<F, Hash, H>(
    input: &RealmFinalizeGUTAInput<F, Hash>,
    chain_domain: Hash,
    root_guta_reward_tag: Hash,
) -> RealmFinalizeGUTAPublicOutput<F, Hash>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    let root_guta_header_hash = input.root_guta_header.qfhash::<H>();
    let action = RealmFinalizeGUTAAction {
        chain_domain,
        checkpoint_id: input.checkpoint_id,
        realm_id: input.root_guta_header.state_transition.node_index,
        checkpoint_tree_root: input.root_guta_header.checkpoint_tree_root,
        validator_tree_root: input.checkpoint_leaf.global_state_roots.validator_tree_root,
        root_guta_header_hash,
    };
    let mut final_guta_header = input.root_guta_header.clone();
    final_guta_header.state_transition.new_node_value = input.validator_fee_delta_proof.new_root;
    final_guta_header.total_aggregation_proofs_generated =
        F::from_u64_value(final_guta_header.total_aggregation_proofs_generated.to_u64_value() + 1);
    RealmFinalizeGUTAPublicOutput {
        chain_domain,
        checkpoint_id: input.checkpoint_id,
        realm_id: input.root_guta_header.state_transition.node_index,
        realm_sub_id: input.realm_sub_id,
        checkpoint_tree_root: input.root_guta_header.checkpoint_tree_root,
        validator_tree_root: input.checkpoint_leaf.global_state_roots.validator_tree_root,
        validator_user_id: input.validator_user_id,
        root_guta_header_hash,
        root_guta_reward_tag,
        action_hash: action.action_hash::<H>(),
        final_guta_header,
    }
}


/// Finalizer reward root as the standard tagged tag-tree node:
/// `R63 = H(H(O.root_guta_reward_tag, A), worker_tag)` where
/// `A = output.public_output_hash::<H>()` is the output commitment stored as a
/// value-only right sibling and `O.root_guta_reward_tag` is the root GUTA
/// child's reward value on the left.
pub fn finalize_reward_root63<F, Hash, H>(
    output: &RealmFinalizeGUTAPublicOutput<F, Hash>,
    finalizer_worker_reward_tag: &Hash,
) -> Hash
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    let output_commitment = output.public_output_hash::<H>();
    H::q_two_to_one(
        H::q_two_to_one(output.root_guta_reward_tag, output_commitment),
        *finalizer_worker_reward_tag,
    )
}

/// Expected circuit-63 public input:
/// `PI63 = H(output.final_guta_header_hash(), R63)`.
pub fn finalize_public_input_hash<F, Hash, H>(
    output: &RealmFinalizeGUTAPublicOutput<F, Hash>,
    finalizer_worker_reward_tag: &Hash,
) -> Hash
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    H: FieldQHasher<F, Hash>,
{
    let reward_root63 = finalize_reward_root63::<F, Hash, H>(output, finalizer_worker_reward_tag);
    H::q_two_to_one(output.final_guta_header_hash::<H>(), reward_root63)
}

// =================================================================================
// Witness Input (private)
// =================================================================================

/// Private witness for the RealmFinalizeGUTA circuit.
///
/// The realm finalizer has exactly one worker child dependency:
///   - input_proofs[0] = root GUTA proof
///
/// BLS authorization happens off-circuit at the processor/Coordinator
/// boundary; no wallet key, public-key parameter or signature witness enters
/// this struct.
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
    pub current_validator_user_leaf: PQEDUserLeaf<F, Hash>,
    pub current_validator_user_tree_proof: MerkleProofCore<Hash>,

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
            current_validator_user_leaf: PQEDUserLeaf::qp_rand_gen(),
            current_validator_user_tree_proof: MerkleProofCore::qp_rand_gen(),
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
            + self.current_validator_user_leaf.pio_serialized_size()
            + self.current_validator_user_tree_proof.pio_serialized_size()
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
        self.current_validator_user_leaf.pio_write_to_io(writer)?;
        self.current_validator_user_tree_proof.pio_write_to_io(writer)?;
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
        let current_validator_user_leaf = PQEDUserLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let current_validator_user_tree_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
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
            current_validator_user_leaf,
            current_validator_user_tree_proof,
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

#[cfg(test)]
mod chain_domain_tests {
    use super::*;
    use parth_core::felt::FromPrimitiveValuesFelt;
    use parth_core::pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher};

    #[test]
    fn configured_identity_matches_client_prover() {
        let network = match psy_config::CURRENT_NETWORK {
            "localhost" => psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet,
            "sepolia" => psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicTestnet,
            "ethereum" => psy_core::constants::chain_id::PsyChainNetworkType::PsyMainnet,
            other => panic!("Unsupported configured network: {other}"),
        };
        assert_eq!(network.get_chain_id(), psy_config::PSY_NETWORK_MAGIC);
    }

    #[test]
    fn network_magic_changes_finalizer_domain() {
        let magic = psy_core::constants::chain_id::PSY_CHAIN_ID_LOCAL_DEVNET;
        let domain = realm_finalize_guta_chain_domain::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(magic);
        let old_domain = realm_finalize_guta_chain_domain::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(0);
        assert_ne!(domain, old_domain);
        assert_eq!(domain, PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(magic)]));
    }
}

#[cfg(test)]
mod finalize_binding_tests {
    use super::*;
    use crate::p2p::{GOLDILOCKS_MODULUS, ProtocolError};

    #[test]
    fn binding_roundtrip_accepts_largest_canonical_tag() {
        let mut tag = [0u8; 32];
        tag[24..32].copy_from_slice(&(GOLDILOCKS_MODULUS - 1).to_le_bytes());
        let binding = RealmFinalizeBinding {
            output: [0x11; 410],
            finalizer_worker_reward_tag: tag,
        };
        let encoded = binding.protocol_encode_to_vec();
        assert_eq!(encoded.len(), REALM_FINALIZE_BINDING_WIRE_BYTES);
        assert_eq!(RealmFinalizeBinding::protocol_decode(&encoded).unwrap(), binding);
    }

    #[test]
    fn binding_decode_rejects_noncanonical_tag_and_wrong_length() {
        let mut tag = [0u8; 32];
        tag[24..32].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        let binding = RealmFinalizeBinding {
            output: [0x22; 410],
            finalizer_worker_reward_tag: tag,
        };
        let encoded = binding.protocol_encode_to_vec();
        assert!(matches!(
            RealmFinalizeBinding::protocol_decode(&encoded),
            Err(ProtocolError::NonCanonicalField { .. })
        ));

        let ok_tag = [0u8; 32];
        let mut truncated = RealmFinalizeBinding {
            output: [0x22; 410],
            finalizer_worker_reward_tag: ok_tag,
        }
        .protocol_encode_to_vec();
        truncated.pop();
        assert!(matches!(
            RealmFinalizeBinding::protocol_decode(&truncated),
            Err(ProtocolError::InvalidLength { .. })
        ));
        let mut trailing = RealmFinalizeBinding {
            output: [0x22; 410],
            finalizer_worker_reward_tag: ok_tag,
        }
        .protocol_encode_to_vec();
        trailing.push(0);
        assert!(matches!(
            RealmFinalizeBinding::protocol_decode(&truncated),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }
}

#[cfg(test)]
mod finalize_reward_root63_tests {
    use super::*;
    use parth_core::crypto::hash::tag_tree::{
        compute_tag_tree_root_for_proof, hash_tag_tree_node, TagTreeNodePreimage, TagTreeProofNode,
    };
    use parth_core::felt::FromPrimitiveValuesFelt;
    use parth_core::pgoldilocks::{PGoldilocksFelt, PoseidonHasher};

    type F = parth_core::PF;
    type Hash = parth_core::PHash;

    use parth_core::crypto::hash::traits::ZeroableHash;

    fn sample_output(root_guta_reward_tag: Hash) -> RealmFinalizeGUTAPublicOutput<F, Hash> {
        RealmFinalizeGUTAPublicOutput {
            chain_domain: realm_finalize_guta_chain_domain::<F, Hash, PoseidonHasher>(17),
            checkpoint_id: F::from_u64_value(3),
            realm_id: F::from_u64_value(1),
            realm_sub_id: 1,
            checkpoint_tree_root: Hash::get_zero_value(),
            validator_tree_root: Hash::get_zero_value(),
            validator_user_id: F::from_u64_value(1048576),
            root_guta_header_hash: Hash::get_zero_value(),
            root_guta_reward_tag,
            action_hash: Hash::get_zero_value(),
            final_guta_header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: Hash::get_zero_value(),
                checkpoint_tree_root: Hash::get_zero_value(),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: Hash::get_zero_value(),
                    new_node_value: Hash::get_zero_value(),
                    node_index: F::from_u64_value(1),
                    node_level: F::from_u64_value(12),
                },
                stats: GUTAStats::get_zero_value(),
                total_aggregation_proofs_generated: F::from_u64_value(0),
            },
        }
    }

    #[test]
    fn finalizer_leaf_preimage_and_child_sibling_path_derive_same_root() {
        let t_root = PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(13)]);
        let tag = PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(12)]);
        let zero = Hash::get_zero_value();

        // The root GUTA child's reward value derives from its own mode-0 leaf.
        let child_leaf = TagTreeNodePreimage {
            left: zero,
            right: zero,
            tag: t_root,
        };
        let v_c0 = compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &child_leaf, &[]);

        // A commits the full output including the child's reward value, so
        // the host output tag and the stored tree left value agree by
        // construction.
        let output = sample_output(v_c0);
        let a = output.public_output_hash::<PoseidonHasher>();
        let root = hash_tag_tree_node::<Hash, PoseidonHasher>(&v_c0, &a, &tag);

        // Finalizer worker claim at f: preimage {left: child reward, right: A,
        // tag: worker tag} derives exactly the persisted reward root.
        let finalizer_leaf = TagTreeNodePreimage { left: v_c0, right: a, tag };
        assert_eq!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &finalizer_leaf, &[]),
            root
        );
        assert_eq!(
            finalize_reward_root63::<F, Hash, PoseidonHasher>(&output, &tag),
            root
        );

        // Root-GUTA child worker claim at c=left(f): its own leaf derives
        // V_c0, then one up-step over the stored sibling A with the parent
        // tag lands on the identical root.
        assert_eq!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(
                0, // left child: sibling goes on the right of the up-step
                &child_leaf,
                &[TagTreeProofNode { sibling: a, parent_tag: tag }],
            ),
            root
        );
        assert_eq!(hash_tag_tree_node::<Hash, PoseidonHasher>(&v_c0, &a, &tag), root);
    }

    #[test]
    fn reward_root_rejects_tampered_a_tag_and_child_value() {
        let tag = PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(22)]);
        let t_root = PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(23)]);
        let wrong = PoseidonHasher::q_hash_many(&[PGoldilocksFelt::from_u64_value(99)]);
        let zero = Hash::get_zero_value();
        let child_leaf = TagTreeNodePreimage { left: zero, right: zero, tag: t_root };
        let c0 = compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &child_leaf, &[]);

        let output = sample_output(c0);
        let a = output.public_output_hash::<PoseidonHasher>();
        let true_root = hash_tag_tree_node::<Hash, PoseidonHasher>(&c0, &a, &tag);
        assert_eq!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(
                0, &child_leaf, &[TagTreeProofNode { sibling: a, parent_tag: tag }],
            ),
            true_root
        );

        // Tampered A in the finalizer preimage.
        let tampered_a_leaf = TagTreeNodePreimage { left: c0, right: wrong, tag };
        assert_ne!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &tampered_a_leaf, &[]),
            true_root
        );
        // Tampered worker tag in the finalizer preimage.
        let tampered_tag_leaf = TagTreeNodePreimage { left: c0, right: a, tag: wrong };
        assert_ne!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &tampered_tag_leaf, &[]),
            true_root
        );
        // Tampered child reward value on the left.
        let tampered_c0_leaf = TagTreeNodePreimage { left: wrong, right: a, tag };
        assert_ne!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(0, &tampered_c0_leaf, &[]),
            true_root
        );
        // Tampered sibling on the child worker's up-step.
        assert_ne!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(
                0,
                &child_leaf,
                &[TagTreeProofNode { sibling: wrong, parent_tag: tag }],
            ),
            true_root
        );
        // Tampered parent tag on the child worker's up-step.
        assert_ne!(
            compute_tag_tree_root_for_proof::<Hash, PoseidonHasher>(
                0,
                &child_leaf,
                &[TagTreeProofNode { sibling: a, parent_tag: wrong }],
            ),
            true_root
        );
    }
}