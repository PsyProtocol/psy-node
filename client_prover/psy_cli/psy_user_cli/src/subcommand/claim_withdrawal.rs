use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_data::bridge_aggregate::{domain_hash, Domain, NetworkConfig};
use psy_plonky2_circuits::bridge::aggregate_circuits::{load_aggregate_setup_config, AggregateCircuitHeights, AggregateCircuits};

use psy_provider::provider::RpcProvider;
use psy_prover::local::bridge_aggregate::{address, digest, word, AggregationClaimRequest, AggregationContext, ClaimClient as PortableClaimClient, ClaimError, ClaimStatus, WithdrawalRecord};
use super::args::ClaimWithdrawalArgs;
use crate::result::CommandResult;


pub(super) struct ClaimClient {
    pub circuits: AggregateCircuits,
    pub policies: Vec<psy_plonky2_circuits::bridge::circuits::bridge_claim::BridgeTokenPolicy>,
    pub client: PortableClaimClient,
}
impl std::ops::Deref for ClaimClient {
    type Target = PortableClaimClient;
    fn deref(&self) -> &Self::Target { &self.client }
}
impl ClaimClient {
    pub fn load(rpc_config: &str, config_file: &str, services_url: &str) -> Result<Self> {
        let setup = load_aggregate_setup_config(std::path::Path::new(config_file))?;
        let config = NetworkConfig::decode(&hex::decode(&setup.network_config)?)?;
        let settings = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
        let network = settings.get_current_network()?;
        let magic = u64::from_str_radix(network.magic.trim_start_matches("0x"), 16)?;
        anyhow::ensure!(magic == config.network_magic, "aggregate/provider network mismatch");
        let network_type = psy_core::constants::chain_id::PsyChainNetworkType::try_from_chain_id(magic)?;
        anyhow::ensure!(network_type == psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet, "source graph supports explicitly selected LocalDevnet only");
        anyhow::ensure!(network.global_user_tree_height == psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT && network.realm_user_tree_height == psy_config::network_constants::REALM_USER_TREE_HEIGHT, "provider tree constants mismatch");
        let (_, coordinator) = psy_plonky2_circuits::circuit_library::get_plonky2_circuit_library_and_prover_for_network::<PoseidonGoldilocksConfig, 2>(network_type)?;
        let chain_indices: Vec<u8> = config.chains.iter().map(|chain| chain.chain_index).collect();
        let (checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint) = {
            use psy_plonky2_circuits::qstandard::QStandardCircuit;
            let checkpoint = &coordinator.checkpoint_root_transition;
            (checkpoint.get_common_circuit_data_ref(), checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(), checkpoint.get_fingerprint())
        };
        let circuits = AggregateCircuits::build::<psy_core::network_config::PsyNetworkLocalDevnetConstants>(&chain_indices, checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, AggregateCircuitHeights { deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize }, setup.withdrawal_policies.clone(), config.ethereum_index)?;
        circuits.validate_config(&config)?;
        Ok(Self { circuits, client: PortableClaimClient::new(config, RpcProvider::new_with_config(network)?, services_url)?, policies: setup.withdrawal_policies })
    }
    pub async fn submit(&self, context: &AggregationContext, request: AggregationClaimRequest) -> Result<()> {
        let claim = STANDARD.decode(&request.record)?;
        let family = match request.kind.as_str() { "withdrawal" => 2, "reward" => 3, _ => anyhow::bail!("invalid claim kind") };
        let claim_id = digest(&[&domain_hash(Domain::LeafCommit), &self.config.config_hash()?, &word(family), &claim]);
        let response = self.http.post(format!("{}/api/v1/bridge/aggregation/claims", self.url)).json(&request).send().await?;
        let mut status: ClaimStatus = self.response(response).await?;
        loop {
            self.validate_status(context, &claim_id, family as u8, &status)?;
            println!("{}", serde_json::to_string(&status)?);
            if status.state == "applied" { return Ok(()); }
            if status.state == "queued" { let current = self.context().await?; if current != *context { return Err(ClaimError::ContextChanged(current).into()); } }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            status = self.response(self.http.get(format!("{}/api/v1/bridge/aggregation/claims/{}", self.url, claim_id)).send().await?).await?;
        }
    }
}

pub async fn run(args: ClaimWithdrawalArgs) -> Result<CommandResult> {
    let client = ClaimClient::load(&args.rpc_config, &args.aggregate_config, &args.services_url)?;
    let chain_index = u8::try_from(args.destination_chain_index)?;
    let matches = client.policies.iter().filter(|policy| policy.chain_index == chain_index).collect::<Vec<_>>();
    anyhow::ensure!(matches.len() == 1, "installed withdrawal policy is not unique for the destination chain");
    let claim = WithdrawalRecord { chain_index, sender_user_id: args.sender_user_id.to_string(), contract_id: matches[0].token_contract_id.to_string(), recipient: args.recipient, amount: args.amount, nonce: args.nonce }.canonical()?;
    anyhow::ensure!(client.config.chains.iter().any(|chain| chain.chain_index == claim.chain_index), "unconfigured withdrawal destination");
    let mut context = client.context().await?;
    loop {
        let attempt: Result<()> = async {
            let request = client.prove_withdrawal(&context, &claim, &client.policies, &client.circuits.withdrawal_claim).await?;
            client.submit(&context, request).await
        }.await;
        match attempt {
            Ok(()) => return Ok(CommandResult::generic("claim-withdrawal")),
            Err(error) => match error.downcast_ref::<ClaimError>() { Some(ClaimError::ContextChanged(current)) => context = current.clone(), _ => return Err(error) },
        }
    }
}
