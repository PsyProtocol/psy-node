
use cf_utils::timer::DebugTimer;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs, verifier_v2::verify_standard_proof}};
use psy_plonky2_basic_helpers::{lookalike::standard::get_end_cap_type_e_common_data, verifier::alt::AltVerifierOnlyCircuitData};
use psy_plonky2_circuits::{end_cap::dummy::DummyUPSStandardEndCapCircuit, qstandard::QStandardCircuit};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;
struct DummyProofBenchHelper {
    pub circuit: DummyUPSStandardEndCapCircuit<C, D>,
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}
impl DummyProofBenchHelper {
    pub fn new() -> Self {
        let circuit = DummyUPSStandardEndCapCircuit::<C, D>::new_without_minifier();
        Self {
            circuit,
            proofs: vec![],
        }
    }
    pub fn generate_proofs(&mut self, num_proofs: usize) {
        let mut timer = DebugTimer::new("generate_dummy_proofs");
        let mut inner_timer = DebugTimer::new("generating proofs");
        timer.lap("start generating proofs");
        for _ in 0..num_proofs {
            let public_inputs_hash = QHashOut::<F>::rand();
            let proof = self.circuit.prove_base(public_inputs_hash).unwrap();
            inner_timer.lap("proved dummy");
            self.proofs.push(proof);
        }
        timer.lap_batch("generate_dummy_proofs", "proof", num_proofs);
    }

    pub fn verify_proofs(&self) -> anyhow::Result<()> {
        let verifier_data = AltVerifierOnlyCircuitData::<F>::new_from_verifier_data(self.circuit.get_verifier_config_ref()).to_verifier_data::<C, D>();
        let common_circuit_data = get_end_cap_type_e_common_data::<C,D>();
        let mut timer = DebugTimer::new("verify_dummy_proofs");
        timer.lap("start verifying proofs");
        let mut correct_count = 0;
        let len = self.proofs.len();

        for i in 0..100{
            for j in 0..len {
                let proof = &self.proofs[(i + j)% len];
                let res = verify_standard_proof(
                    proof,
                    &verifier_data,
                    &common_circuit_data,
                );
                correct_count += if res.is_ok() { 1 } else { 0 };
                if res.is_err() {
                    println!("proof verification failed: {:?}", res.err());
                    break;
                }
            }
        }
        timer.lap_batch("verify_dummy_proofs", "proof", self.proofs.len()*100);
        timer.lap_group(&format!("verified {} dummy proofs in total", self.proofs.len()));
        println!("Verified {}/{} dummy proofs", correct_count, self.proofs.len());
        Ok(())
    }
}


fn main() {
    let mut helper = DummyProofBenchHelper::new();
    helper.generate_proofs(100);
    helper.verify_proofs().unwrap();

}