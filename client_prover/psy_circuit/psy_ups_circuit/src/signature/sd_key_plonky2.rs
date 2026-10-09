use std::fmt::Debug;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    gates::gate::GateRef,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_crypto::{hash::traits::hasher::MerkleZeroHasher, signature::zk::wallet::PRIVATE_KEY_CONSTANTS};
use psy_vm::ups::signature::SDKeyPlonky2CircuitWitnessInput;

use crate::signature::state_reader::StateReaderGadget;

type C = PoseidonGoldilocksConfig;
type GF = GoldilocksField;
const D: usize = 2;

#[derive(Debug)]
pub struct SDKeyPlonky2CircuitGadget {
    pub state_reader_gadget: StateReaderGadget<GF, D>,
    pub contract_state_tree_height: u8,
    pub input_len: usize,
    pub circuit_inputs: Vec<Target>,
    pub private_key: HashOutTarget,
    pub sig_hash: HashOutTarget,
    pub circuit_data: Option<CircuitData<GF, C, D>>,
    pub minifier_chain: Option<PsyProofMinifierChain<D, GF, C>>,
}

impl SDKeyPlonky2CircuitGadget {
    pub fn add_virtual_to(builder: &mut CircuitBuilder<GF, D>, contract_state_tree_height: u8, input_len: usize) -> Self {
        let private_key = builder.add_virtual_hash();
        let sig_hash = builder.add_virtual_hash();
        let circuit_inputs = builder.add_virtual_targets(input_len);
        let state_reader_gadget = StateReaderGadget::new(builder, contract_state_tree_height);

        let public_key_param = get_zk_public_key_param::<C, D>(builder, &private_key);
        let public_inputs_hash = builder.hash_two_to_one::<PoseidonHash>(sig_hash, public_key_param);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            state_reader_gadget,
            contract_state_tree_height,
            input_len,
            circuit_inputs,
            private_key,
            sig_hash,
            circuit_data: None,
            minifier_chain: None,
        }
    }

    pub fn add_custom_constraints<F>(&mut self, builder: &mut CircuitBuilder<GF, D>, constraints_fn: F)
    where
        F: FnOnce(&mut CircuitBuilder<GF, D>, &mut StateReaderGadget<GF, D>, &[Target]),
    {
        constraints_fn(builder, &mut self.state_reader_gadget, &self.circuit_inputs);
    }

    pub fn build_circuit(&mut self, builder: CircuitBuilder<GF, D>) -> anyhow::Result<()> {
        let mut builder = builder;
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<GF, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain =
            PsyProofMinifierChain::<D, GF, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        self.circuit_data = Some(circuit_data);
        self.minifier_chain = Some(minifier_chain);
        Ok(())
    }

    pub async fn prove(
        &mut self,
        private_key: QHashOut<GF>,
        input: &SDKeyPlonky2CircuitWitnessInput,
        sig_hash: QHashOut<GF>,
    ) -> anyhow::Result<ProofWithPublicInputs<GF, C, D>> {
        let circuit_data = self.circuit_data.as_ref().ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;
        let minifier_chain = self
            .minifier_chain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Minifier chain not initialized"))?;

        let mut pw = PartialWitness::<GF>::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;
        pw.set_target_arr(&self.circuit_inputs, &input.circuit_inputs)?;

        self.state_reader_gadget.set_witness(&mut pw, &input.state_reader_results)?;

        let inner_proof = circuit_data.prove(pw)?;
        let minified_proof = minifier_chain.prove(&inner_proof)?;
        Ok(minified_proof)
    }

    pub fn get_fingerprint(&self) -> QHashOut<GF> {
        self.minifier_chain
            .as_ref()
            .map(|chain| QHashOut(chain.get_fingerprint()))
            .unwrap_or_default()
    }

    pub fn get_verifier_config_ref(&self) -> Option<&VerifierOnlyCircuitData<C, D>> {
        self.minifier_chain.as_ref().map(|chain| chain.get_verifier_data())
    }
}

pub fn get_zk_public_key_param<C: GenericConfig<D>, const D: usize>(
    builder: &mut CircuitBuilder<C::F, D>,
    private_key: &HashOutTarget,
) -> HashOutTarget
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    let private_key_constants = PRIVATE_KEY_CONSTANTS
        .iter()
        .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
        .collect::<Vec<_>>();
    builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
        private_key_constants[0],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[19],
        private_key.elements[1],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[3],
        private_key_constants[4],
        private_key_constants[5],
        private_key_constants[6],
        private_key.elements[0],
        private_key_constants[7],
        private_key.elements[2],
        private_key_constants[8],
        private_key_constants[9],
        private_key_constants[10],
        private_key_constants[11],
        private_key_constants[12],
        private_key.elements[3],
        private_key_constants[13],
        private_key_constants[14],
        private_key_constants[15],
        private_key_constants[16],
        private_key_constants[17],
        private_key_constants[18],
    ])
}

pub fn get_sdc_public_key_param<F: RichField>(private_key: &QHashOut<F>) -> QHashOut<F> {
    let private_key_constants = PRIVATE_KEY_CONSTANTS.iter().map(|c| F::from_canonical_u64(*c)).collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&[
        private_key_constants[0],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[19],
        private_key.0.elements[1],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[3],
        private_key_constants[4],
        private_key_constants[5],
        private_key_constants[6],
        private_key.0.elements[0],
        private_key_constants[7],
        private_key.0.elements[2],
        private_key_constants[8],
        private_key_constants[9],
        private_key_constants[10],
        private_key_constants[11],
        private_key_constants[12],
        private_key.0.elements[3],
        private_key_constants[13],
        private_key_constants[14],
        private_key_constants[15],
        private_key_constants[16],
        private_key_constants[17],
        private_key_constants[18],
    ]))
}
