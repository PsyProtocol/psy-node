use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_common::data::alt::AltVerifierOnlyCircuitData;
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::PSY_NETWORK_MAGIC;
use psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub async fn run() -> anyhow::Result<()> {
    let network_magic = PSY_NETWORK_MAGIC;
    let circuit_manager = PsyUPSStepCircuitManager::<C, D>::new_with_config(network_magic);

    let endcap_fingerprint = circuit_manager.ups_end_cap.get_fingerprint();
    let verify_data = circuit_manager.ups_end_cap.get_verifier_config_ref();
    let alt_verify_data = AltVerifierOnlyCircuitData::from(verify_data);

    println!("endcap_fingerprint: {:?}", endcap_fingerprint);
    println!("endcap_fingerprint: {}", endcap_fingerprint);
    println!("alt_verify_data: {:?}", alt_verify_data);
    println!("alt_verify_data: {}", serde_json::to_string(&alt_verify_data)?);

    let zk_fingerprint = circuit_manager.zk_circuit.get_fingerprint();
    let secp_fingerprint = circuit_manager.secp_circuit.get_fingerprint();
    println!("zk_fingerprint: {}", zk_fingerprint);
    println!("secp_fingerprint: {}", secp_fingerprint);

    Ok(())
}
