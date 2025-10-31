use cf_utils::timer::DebugTimer;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::Poseidon, plonk::{config::{GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}};
use psy_plonky2_circuits::end_cap::dummy::DummyUPSStandardEndCapCircuit;

fn serialize_deserialize_round_trip_bincode<C: GenericConfig<D>, const D: usize>(proof: &ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<()>{
    let mut timer = DebugTimer::new("serialize_deserialize_round_trip");
    timer.lap("start serialize proof");
    let serialized_proof = bincode::serialize(proof)?;
    timer.lap("end serialize proof");
    timer.lap("start deserialize proof");
    let deserialized_proof: ProofWithPublicInputs<C::F, C, D> = bincode::deserialize(&serialized_proof)?;
    timer.lap("end deserialize proof");

    if deserialized_proof.public_inputs != proof.public_inputs {
        anyhow::bail!("public inputs do not match after round trip");
    }
    Ok(())
}
fn main(){
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    type F = GoldilocksField;
    let dummy_circuit = DummyUPSStandardEndCapCircuit::<C, D>::new_without_minifier();
    let hash = QHashOut::<F>::rand();
    let proof = dummy_circuit.prove_base(hash).unwrap();
    serialize_deserialize_round_trip_bincode::<C,D>(&proof).unwrap();

}