use plonky2::{
    field::types::Field,
    gates::gate::GateRef,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use psy_client_common::{data::qhashout::QHashOut, utils::debug_timer::DebugTimer};
use psy_crypto::{
    common::witnesses::zk_signature::PsyZKSignatureCircuitInput, hash::traits::hasher::MerkleZeroHasher, signature::zk::wallet::PRIVATE_KEY_CONSTANTS,
};

use super::super::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit};
use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    proof_minifier::pm_chain::PsyProofMinifierChain,
    serialization::{PsyGateSerializer, PsyGeneratorSerializer},
    u32::gates::comparison::ComparisonGate,
};
#[derive(Debug)]
pub struct PsyBasicZKSignatureCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub private_key: HashOutTarget,
    pub sig_hash: HashOutTarget,
    // end circuit targets
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for PsyBasicZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> PsyBasicZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();

        let mut timer = DebugTimer::new("new zk sign circuit");
        timer.lap("build inner circuit");
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let private_key = builder.add_virtual_hash();
        let private_key_constants = PRIVATE_KEY_CONSTANTS
            .iter()
            .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
            .collect::<Vec<_>>();
        let public_key_param_target = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
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
        ]);

        let sig_hash = builder.add_virtual_hash();
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(sig_hash, public_key_param_target);
        builder.register_public_inputs(&public_inputs_hash.elements);
        let circuit_data = builder.build::<C>();
        timer.lap("build inner circuit done");

        // start add some gates to make it easier to integrate with others
        timer.lap("build minifier circuit");
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));
        timer.lap("build minifier circuit done");
        let fingerprint = QHashOut(minifier_chain.get_fingerprint());
        Self {
            private_key,
            sig_hash,
            circuit_data,
            minifier_chain: minifier_chain,
            fingerprint,
        }
    }
    pub fn prove_base(&self, private_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;
        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier_chain.prove(&inner_proof)
    }
    pub fn prove_base_inner(&self, private_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;
        self.circuit_data.prove(pw)
    }
    pub fn prove_minifier(&self, inner_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.minifier_chain.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + Default, const D: usize> PsyBasicZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn serialize_circuit_data(&self) -> anyhow::Result<Vec<u8>> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();

        let data_bytes = self
            .circuit_data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|_| anyhow::Error::msg("CircuitData serialization failed."))?;

        Ok(data_bytes)
    }

    pub fn new_with_file(file_path: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(file_path)?;
        Self::new_with_serialized_circuit(&bytes)
    }

    pub fn new_with_serialized_circuit(circuit_data_bytes: &[u8]) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut timer = DebugTimer::new("new zk sign circuit with serialized data");
        timer.lap("build inner circuit");
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let private_key = builder.add_virtual_hash();
        let private_key_constants = PRIVATE_KEY_CONSTANTS
            .iter()
            .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
            .collect::<Vec<_>>();
        let _public_key_param_target = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
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
        ]);
        let sig_hash = builder.add_virtual_hash();

        // let circuit_data = builder.build::<C>();
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let circuit_data = CircuitData::<C::F, C, D>::from_bytes(&circuit_data_bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::format_err!("CircuitData deserialization failed. Error: {}", e))?;

        timer.lap("build inner circuit done");

        // start add some gates to make it easier to integrate with others
        timer.lap("build minifier circuit");
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));
        timer.lap("build minifier circuit done");
        let fingerprint = QHashOut(minifier_chain.get_fingerprint());

        Ok(Self {
            private_key,
            sig_hash,
            circuit_data,
            minifier_chain: minifier_chain,
            fingerprint,
        })
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for PsyBasicZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<PsyZKSignatureCircuitInput<C::F>, C, D> for PsyBasicZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &PsyZKSignatureCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input.private_key, input.sig_hash)
    }
}

#[derive(Debug)]
pub struct PsyBasicZKSignatureInnerCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub private_key: HashOutTarget,
    pub sig_hash: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for PsyBasicZKSignatureInnerCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> PsyBasicZKSignatureInnerCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    /// Builds the inner circuit's virtual targets in a fixed, deterministic
    /// order. Shared by `new()` and `new_with_serialized_circuit()` so the
    /// wire indices in the deserialized `circuit_data` line up with these
    /// freshly-created targets.
    fn build_targets(builder: &mut CircuitBuilder<C::F, D>) -> (HashOutTarget, HashOutTarget) {
        let private_key = builder.add_virtual_hash();
        let private_key_constants = PRIVATE_KEY_CONSTANTS
            .iter()
            .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
            .collect::<Vec<_>>();
        let public_key_param_target = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
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
        ]);

        let sig_hash = builder.add_virtual_hash();
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(sig_hash, public_key_param_target);
        builder.register_public_inputs(&public_inputs_hash.elements);
        (private_key, sig_hash)
    }

    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let (private_key, sig_hash) = Self::build_targets(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            private_key,
            sig_hash,
            circuit_data,
        }
    }

    /// Serialize the inner circuit data. Uses `PsyGateSerializer`, a superset
    /// of the stock serializer, so the same serializer works across all Psy
    /// circuits.
    pub fn serialize_circuit_data(&self) -> anyhow::Result<Vec<u8>> {
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        self.circuit_data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("zk sign inner circuit_data serialize failed: {e:?}"))
    }

    pub fn new_with_file(file_path: &str) -> anyhow::Result<Self> {
        Self::new_with_serialized_circuit(&std::fs::read(file_path)?)
    }

    pub fn new_with_serialized_circuit(circuit_data_bytes: &[u8]) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        // Re-create the targets in the exact same order as `new()` so their wire
        // indices match the deserialized circuit data; the builder is then discarded.
        let (private_key, sig_hash) = Self::build_targets(&mut builder);

        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        let circuit_data = CircuitData::<C::F, C, D>::from_bytes(circuit_data_bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::format_err!("zk sign inner circuit_data deserialize failed: {e}"))?;

        Ok(Self {
            private_key,
            sig_hash,
            circuit_data,
        })
    }

    pub fn prove_base(&self, private_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;
        self.circuit_data.prove(pw)
    }
}

mod test {

    #[test]
    fn test_serialize_circuit() -> anyhow::Result<()> {
        use plonky2::plonk::config::PoseidonGoldilocksConfig;
        use psy_client_common::utils::debug_timer::DebugTimer;

        use super::*;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let mut timer = DebugTimer::new("serialize_circuit test");
        timer.lap("init zk sign circuit");
        let zk_circuit = PsyBasicZKSignatureCircuit::<C, D>::new();
        timer.lap("init zk sign circuit done");

        timer.lap("serialize circuit data");
        let circuit_data_bytes = zk_circuit.serialize_circuit_data()?;
        timer.lap("serialize circuit data done");

        timer.lap("deserialize circuit data");
        let zk_circuit2 = PsyBasicZKSignatureCircuit::<C, D>::new_with_serialized_circuit(&circuit_data_bytes)?;
        timer.lap("deserialize circuit data done");
        assert_eq!(zk_circuit.fingerprint, zk_circuit2.fingerprint);
        assert_eq!(zk_circuit.circuit_data, zk_circuit2.circuit_data);
        assert_eq!(zk_circuit.private_key, zk_circuit2.private_key);
        assert_eq!(zk_circuit.sig_hash, zk_circuit2.sig_hash);

        let input = PsyZKSignatureCircuitInput {
            private_key: QHashOut::rand(),
            sig_hash: QHashOut::rand(),
        };
        let mut pw = PartialWitness::new();
        pw.set_hash_target(zk_circuit2.private_key, input.private_key.0)?;
        pw.set_hash_target(zk_circuit2.sig_hash, input.sig_hash.0)?;

        timer.lap("prove inner");
        let inner_proof = zk_circuit2.circuit_data.prove(pw)?;
        timer.lap("prove inner done");

        timer.lap("prove minifier");
        let proof2 = zk_circuit.minifier_chain.prove(&inner_proof)?;
        timer.lap("prove minifier done");

        timer.lap("verify inner proof");
        zk_circuit2.circuit_data.verify(inner_proof)?;
        timer.lap("verify inner proof done");

        timer.lap("verify minifier proof");
        zk_circuit.minifier_chain.verify(proof2)?;
        timer.lap("verify minifier proof done");

        Ok(())
    }
}
