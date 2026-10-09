use psy_ups_circuit::signature::sd_key_dpn::SDKeyDpnCircuitGadget;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use crate::{result::{CommandResult, FingerprintResult}, subcommand::args::GetPsySdcFingerprintArgs};

pub async fn run(args: GetPsySdcFingerprintArgs) -> anyhow::Result<CommandResult> {
    let fn_def_str = std::fs::read_to_string(&args.sdc_path).map_err(|e| anyhow::format_err!("read sdc file error: {}", e))?;
    let fn_def =
        serde_json::from_str::<DPNFunctionCircuitDefinition>(&fn_def_str).map_err(|e| anyhow::format_err!("deserialize sdc file error: {}", e))?;
    if !fn_def.is_view_function() {
        anyhow::bail!("SD key authorization function must be a read-only view function");
    }

    let config = psy_vm::ups::sd_key::sd_key_config_for_dpn_function(&fn_def);
    let gadget = SDKeyDpnCircuitGadget::build_from_dpn_function(&fn_def, &config)?;
    let fingerprint = gadget.get_fingerprint();

    tracing::info!("SD key DPN circuit fingerprint: {}", fingerprint.to_string());

    Ok(CommandResult::Fingerprint(FingerprintResult { fingerprint: fingerprint.to_string() }))
}
