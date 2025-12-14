use hashbrown::HashMap;
use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::MerkleZeroHasher,
    }, protocol::core_types::QZKProofPublicInputsHasherReader}
;
use psy_core::job::job_id::ProvingJobCircuitType;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    utils::{circuit_info_library::{PsyJTMBCircuitInfoLibrary, PsyJTMBCircuitInfoLibraryBuilder, PsyJTMBCircuitInfoLibraryCore}, jtmb_standard_circuit::JTMBCircuitConfig, proof_serialization::deserialize_jtmb_proof},
};

#[pderive::serialize_copy_hash]
pub struct JTMBBasicCircuitInfo<Hash> {
    pub circuit_type: ProvingJobCircuitType,
    pub fingerprint: Hash,
    pub verifier_data: PsyTestJTMBProofVerifierData,
}

#[pderive::serialize_copy]
pub struct JTMBCircuitTypeInclusionMappingKey {
    pub parent: ProvingJobCircuitType,
    pub child: ProvingJobCircuitType,
}

#[pderive::serialize_clone_hash]

pub struct JTMBSerializableSimpleCircuitLibrary<Hash> {
    pub circuits: Vec<JTMBBasicCircuitInfo<Hash>>,
    pub inclusion_proofs: Vec<MerkleProofCore<Hash>>,
    pub inclusion_proof_mapping: Vec<Vec<JTMBCircuitTypeInclusionMappingKey>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JTMBSimpleCircuitLibrary<C: JTMBCircuitConfig> {
    pub info_map: HashMap<ProvingJobCircuitType, JTMBBasicCircuitInfo<C::Hash>>,
    pub inclusion_proofs: Vec<MerkleProofCore<C::Hash>>,
    pub inclusion_map: HashMap<JTMBCircuitTypeInclusionMappingKey, usize>,
}
impl<C: JTMBCircuitConfig> JTMBSimpleCircuitLibrary<C> {
    pub fn new() -> Self {
        Self {
            info_map: HashMap::new(),
            inclusion_proofs: Vec::new(),
            inclusion_map: HashMap::new(),
        }
    }
    pub fn from_serialized(sscl: JTMBSerializableSimpleCircuitLibrary<C::Hash>) -> Self {
        let mut info_map = HashMap::new();
        sscl.circuits.into_iter().for_each(|x| {
            info_map.insert(x.circuit_type, x);
        });
        let mut inclusion_map = HashMap::new();

        let inclusion_proofs_len = sscl.inclusion_proofs.len();
        sscl.inclusion_proof_mapping.iter().enumerate().for_each(|(ind, group)| {
            // ensure there are no out of bounds reads with the check below
            if ind < inclusion_proofs_len {
                group.iter().for_each(|k| {
                    inclusion_map.insert(*k, ind);
                });
            }
        });

        Self {
            info_map,
            inclusion_map,
            inclusion_proofs: sscl.inclusion_proofs,
        }
    }

    pub fn to_serialized(&self) -> JTMBSerializableSimpleCircuitLibrary<C::Hash> {
        let mut circuits = self.info_map.values().map(|x| x.to_owned()).collect::<Vec<_>>();
        circuits.sort_by_key(|x| x.circuit_type as u32); // sort to ensure consistent ordering for serialization
        let inclusion_proofs_len = self.inclusion_proofs.len();
        let mut inclusion_proof_mapping = vec![Vec::new(); inclusion_proofs_len];

        self.inclusion_map.iter().for_each(|(mapping_key, index)| {
            if (*index) < inclusion_proofs_len {
                inclusion_proof_mapping[*index].push(*mapping_key);
            }
        });

        inclusion_proof_mapping
            .iter_mut()
            .for_each(|v| v.sort_by_key(|x| (x.parent as u32, x.child as u32))); // sort to ensure consistent ordering for serialization

        let inclusion_proofs = self.inclusion_proofs.clone();

        JTMBSerializableSimpleCircuitLibrary {
            circuits,
            inclusion_proofs,
            inclusion_proof_mapping,
        }
    }

    fn internal_get_basic_info(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<&JTMBBasicCircuitInfo<C::Hash>> {
        match self.info_map.get(&circuit_type) {
            Some(x) => Ok(x),
            None => anyhow::bail!("circuit type '{:?}' not registered", circuit_type),
        }
    }
    fn internal_register_circuit(&mut self, circuit_type: ProvingJobCircuitType, fingerprint: C::Hash, verifier_data: PsyTestJTMBProofVerifierData) {
        self.info_map.insert(
            circuit_type,
            JTMBBasicCircuitInfo {
                verifier_data,
                fingerprint,
                circuit_type,
            },
        );
    }
    fn internal_add_inclusion_proof(
        &mut self,
        parent_types: &[ProvingJobCircuitType],
        child_type: ProvingJobCircuitType,
        proof: MerkleProofCore<C::Hash>,
    ) {
        let ind = self.inclusion_proofs.len();
        self.inclusion_proofs.push(proof);
        for t in parent_types {
            self.inclusion_map.insert(
                JTMBCircuitTypeInclusionMappingKey {
                    parent: *t,
                    child: child_type,
                },
                ind,
            );
        }
    }
    fn _internal_register_combo(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        verifier_data: PsyTestJTMBProofVerifierData,
        parent_types: &[ProvingJobCircuitType],
        proof: MerkleProofCore<C::Hash>,
    ) {
        self.info_map.insert(
            circuit_type,
            JTMBBasicCircuitInfo {
                verifier_data,
                fingerprint: proof.value,
                circuit_type,
            },
        );
        let ind = self.inclusion_proofs.len();
        self.inclusion_proofs.push(proof);
        for t in parent_types {
            self.inclusion_map.insert(
                JTMBCircuitTypeInclusionMappingKey {
                    parent: *t,
                    child: circuit_type,
                },
                ind,
            );
        }
    }
    fn internal_get_inclusion_proof(
        &self,
        parent_type: ProvingJobCircuitType,
        child_type: ProvingJobCircuitType,
    ) -> anyhow::Result<&MerkleProofCore<C::Hash>> {
        match self.inclusion_map.get(&JTMBCircuitTypeInclusionMappingKey {
            parent: parent_type,
            child: child_type,
        }) {
            Some(v) => Ok(&self.inclusion_proofs[*v]),
            None => anyhow::bail!("could not find inclusion proof for parent = {:?}, child = {:?}", parent_type, child_type),
        }
    }
}

impl<C: JTMBCircuitConfig> PsyJTMBCircuitInfoLibraryBuilder<C::Hash>
    for JTMBSimpleCircuitLibrary<C>
{
    fn register_circuit(&mut self, circuit_type: ProvingJobCircuitType, fingerprint: C::Hash, verifier_data: PsyTestJTMBProofVerifierData) {
        self.internal_register_circuit(circuit_type, fingerprint, verifier_data);
    }

    fn add_inclusion_proof(&mut self, parent_types: &[ProvingJobCircuitType], child_type: ProvingJobCircuitType, proof: MerkleProofCore<C::Hash>) {
        self.internal_add_inclusion_proof(parent_types, child_type, proof);
    }
}

impl<C: JTMBCircuitConfig> PsyJTMBCircuitInfoLibraryCore<C::Hash>
    for JTMBSimpleCircuitLibrary<C>
{
    fn get_fingerprint(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<C::Hash> {
        Ok(self.internal_get_basic_info(circuit_type)?.fingerprint)
    }
    fn get_group_inclusion_proof(
        &self,
        parent_circuit: ProvingJobCircuitType,
        proof_circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<MerkleProofCore<C::Hash>> {
        Ok(self.internal_get_inclusion_proof(parent_circuit, proof_circuit_type)?.to_owned())
    }

    fn get_verifier_data_cap_height(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<usize> {
        let _ = self.internal_get_basic_info(circuit_type)?; // just check existence for now
        Ok(3)
    }

    fn get_agg_whitelist<H: MerkleZeroHasher<C::Hash>>(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<C::Hash> {
        let leaf_fingerprint = self
            .internal_get_basic_info(circuit_type.get_agg_leaf_circuit_type_or_err()?)?
            .fingerprint;
        let agg_fingerprint = self.internal_get_basic_info(circuit_type.get_agg_circuit_type_or_err()?)?.fingerprint;
        let result = H::two_to_one(&leaf_fingerprint, &agg_fingerprint);

        Ok(result)
    }
}
impl<C: JTMBCircuitConfig> QZKProofPublicInputsHasherReader<C::Hash, PsyTestJTMBProof<C::Hash>> for JTMBSimpleCircuitLibrary<C> {
    fn get_proof_public_inputs_hash(proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<C::Hash> {
        Ok(proof.public_inputs_hash)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        deserialize_jtmb_proof(bytes)
    }
}
impl<C: JTMBCircuitConfig> PsyJTMBCircuitInfoLibrary<C::Hash>
    for JTMBSimpleCircuitLibrary<C>
{
    fn get_verifier_data(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<PsyTestJTMBProofVerifierData> {
        Ok(self.internal_get_basic_info(circuit_type)?.verifier_data)
    }

    fn verify_proof_of_type(&self, circuit_type: ProvingJobCircuitType, proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<()> {
        let verifier_data = self.get_verifier_data(circuit_type)?;
        verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(proof)
    }
}