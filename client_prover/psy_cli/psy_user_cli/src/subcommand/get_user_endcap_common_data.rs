use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::field::types::PrimeField64;
use psy_client_common::data::alt::AltVerifierOnlyCircuitData;
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::{CURRENT_NETWORK, PSY_NETWORK_MAGIC};
use psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager;
use psy_vm::ups::circuit_manager::UPSCircuitManager;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub async fn run() -> anyhow::Result<()> {
    let network_magic = PSY_NETWORK_MAGIC;
    let circuit_manager = PsyUPSStepCircuitManager::<C, D>::new_with_config(network_magic);

    let endcap_fingerprint = circuit_manager.ups_end_cap.get_fingerprint();
    let verify_data = circuit_manager.ups_end_cap.get_verifier_config_ref();
    let alt_verify_data = AltVerifierOnlyCircuitData::from(verify_data);
    let fingerprint_u64x4 = [
        endcap_fingerprint.0.elements[0].to_canonical_u64(),
        endcap_fingerprint.0.elements[1].to_canonical_u64(),
        endcap_fingerprint.0.elements[2].to_canonical_u64(),
        endcap_fingerprint.0.elements[3].to_canonical_u64(),
    ];

    println!("psy_network: {CURRENT_NETWORK}");
    println!("psy_network_magic: 0x{PSY_NETWORK_MAGIC:016x}");
    println!("endcap_fingerprint: {endcap_fingerprint}");
    println!("endcap_fingerprint_u64x4: {fingerprint_u64x4:?}");
    println!("alt_verify_data: {}", serde_json::to_string(&alt_verify_data)?);

    let zk_fingerprint = circuit_manager.zk_signature_minifier_fingerprint().await?;
    let secp_fingerprint = circuit_manager.secp_circuit().get_fingerprint();
    println!("zk_fingerprint: {}", zk_fingerprint);
    println!("secp_fingerprint: {}", secp_fingerprint);

    Ok(())
}
