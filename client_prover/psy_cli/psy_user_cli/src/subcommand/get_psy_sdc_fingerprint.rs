use psy_config::network_constants::{DEFAULT_CALLER_CONTRACT_ID_U64, MAX_CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
use psy_ups_circuit::signature::software_defined::DPNSoftwareDefinedSignatureGadget;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use crate::{result::{CommandResult, FingerprintResult}, subcommand::args::GetPsySdcFingerprintArgs};

type F = plonky2::field::goldilocks_field::GoldilocksField;
const D: usize = 2;
pub async fn run(args: GetPsySdcFingerprintArgs) -> anyhow::Result<CommandResult> {
    let fn_def_str = std::fs::read_to_string(&args.sdc_path).map_err(|e| anyhow::format_err!("read sdc file error: {}", e))?;
    let fn_def =
        serde_json::from_str::<DPNFunctionCircuitDefinition>(&fn_def_str).map_err(|e| anyhow::format_err!("deserialize sdc file error: {}", e))?;
    if !fn_def.is_view_function() {
        anyhow::bail!("Cannot register none-view function as software defined circuit");
    }

    let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);

    let mut gadget = DPNSoftwareDefinedSignatureGadget::add_virtual_to(
        &mut builder,
        &fn_def,
        DEFAULT_CALLER_CONTRACT_ID_U64,
        MAX_CONTRACT_STATE_TREE_HEIGHT,
        UPS_SESSION_PROOF_TREE_HEIGHT,
        false,
    );
    gadget.build_circuit(builder)?;
    let fingerprint = gadget.get_fingerprint();

    tracing::info!("register PSY software defined circuit: {}", fingerprint.to_string());

    Ok(CommandResult::Fingerprint(FingerprintResult { fingerprint: fingerprint.to_string() }))
}
