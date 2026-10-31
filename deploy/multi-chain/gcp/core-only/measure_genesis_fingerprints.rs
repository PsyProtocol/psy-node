// Offline circuit construction against the generator's exact release rlibs.
// Source/config pins are caller-supplied provenance, not a build attestation.
use anyhow::{ensure, Result};
use plonky2::field::types::PrimeField64;
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_client_data::config::store_config::{C, D};
use psy_dpn_circuit::circuits::privacy::{
    deposit_inclusion::DepositInclusionCircuit,
    private_note_inclusion::PrivateNoteInclusionCircuit,
};
use serde_json::json;

fn parse_pins(args: &[String]) -> Result<(&str, &str)> {
    ensure!(args.len() == 4 && args[0] == "--node-source-commit" && args[2] == "--config-sha256",
        "expected --node-source-commit FULL_SHA --config-sha256 SHA256");
    for (pin, size) in [(&args[1], 40), (&args[3], 64)] {
        ensure!(pin.len() == size && pin.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && pin.bytes().any(|c| c != b'0'), "invalid provenance pin");
    }
    Ok((&args[1], &args[3]))
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (source, config) = parse_pins(&args)?;
    ensure!(psy_config::CURRENT_NETWORK == "testnet" && psy_config::PSY_NETWORK_MAGIC == 0x1337CF514544CF69
        && psy_config::CHECKPOINTS_PER_EPOCH == 32
        && psy_client_data::dpn::sd_key::SDKEY_MAX_CALLDATA_WORDS == 192,
        "measurement rlibs are not the epoch32 SD192 testnet cohort");
    let deposit = {
        let circuit = DepositInclusionCircuit::<C, D>::new();
        circuit.get_fingerprint().0.elements.map(|v| v.to_canonical_u64())
    };
    let private = {
        use psy_config::network_constants::{GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT,
            PRIVATE_NOTE_TREE_HEIGHT, TOKEN_CONTRACT_STATE_TREE_HEIGHT};
        let circuit = PrivateNoteInclusionCircuit::<C, D>::new(GLOBAL_USER_TREE_HEIGHT as usize,
            GLOBAL_CONTRACT_TREE_HEIGHT as usize, TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize, PRIVATE_NOTE_TREE_HEIGHT);
        circuit.get_fingerprint().0.elements.map(|v| v.to_canonical_u64())
    };
    println!("{}", serde_json::to_string_pretty(&json!({
        "schema_version": 1, "network": "testnet", "node_source_commit": source,
        "config_sha256": config, "deposit_inclusion_fingerprint": deposit,
        "private_note_inclusion_fingerprint": private,
    }))?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fingerprint measurement failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Vec<String> {
        vec!["--node-source-commit".into(), "a".repeat(40), "--config-sha256".into(), "b".repeat(64)]
    }

    #[test]
    fn accepts_only_complete_lowercase_nonzero_pins() {
        let args = pins();
        assert_eq!(parse_pins(&args).unwrap(), (args[1].as_str(), args[3].as_str()));
        for value in ["", "a", &"0".repeat(40), &"A".repeat(40), &"z".repeat(40)] {
            let mut args = pins();
            args[1] = value.into();
            assert!(parse_pins(&args).is_err());
        }
        for value in ["", "a", &"0".repeat(64), &"B".repeat(64)] {
            let mut args = pins();
            args[3] = value.into();
            assert!(parse_pins(&args).is_err());
        }
    }

    #[test]
    fn rejects_missing_extra_and_misnamed_arguments() {
        let mut args = pins();
        args.push("extra".into());
        assert!(parse_pins(&args).is_err());
        assert!(parse_pins(&args[..3]).is_err());
        let mut args = pins();
        args[0] = "--source".into();
        assert!(parse_pins(&args).is_err());
    }
}
