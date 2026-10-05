use alloy_primitives::U256;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_data::bridge_aggregate::{domain_hash, Domain, NetworkConfig, WithdrawalLeaf};
use psy_plonky2_circuits::bridge::aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits};
use psy_provider::provider::RpcProvider;
use psy_prover::local::bridge_aggregate::{address, digest, word, AdmissionRequest, AggregationContext, ClaimClient as PortableClaimClient, ClaimError, ClaimStatus};
use super::args::ClaimWithdrawalArgs;
use crate::result::CommandResult;


pub(super) struct ClaimClient {
    pub circuits: AggregateCircuits,
    pub client: PortableClaimClient,
}
impl std::ops::Deref for ClaimClient {
    type Target = PortableClaimClient;
    fn deref(&self) -> &Self::Target { &self.client }
}
impl ClaimClient {
    pub fn load(rpc_config: &str, config_file: &str, services_url: &str) -> Result<Self> {
        let config = NetworkConfig::decode(&std::fs::read(config_file)?)?;
        let settings = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
        let network = settings.get_current_network()?;
        let magic = u64::from_str_radix(network.magic.trim_start_matches("0x"), 16)?;
        anyhow::ensure!(magic == config.network_magic, "aggregate/provider network mismatch");
        let network_type = psy_core::constants::chain_id::PsyChainNetworkType::try_from_chain_id(magic)?;
        anyhow::ensure!(network_type == psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet, "source graph supports explicitly selected LocalDevnet only");
        anyhow::ensure!(network.global_user_tree_height == psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT && network.realm_user_tree_height == psy_config::network_constants::REALM_USER_TREE_HEIGHT, "provider tree constants mismatch");
        let (_, coordinator) = psy_plonky2_circuits::circuit_library::get_plonky2_circuit_library_and_prover_for_network::<PoseidonGoldilocksConfig, 2>(network_type)?;
        let chain_indices: Vec<u8> = config.chains.iter().map(|chain| chain.chain_index).collect();
        let circuits = AggregateCircuits::build::<psy_core::network_config::PsyNetworkLocalDevnetConstants>(&chain_indices, &coordinator, AggregateCircuitHeights { deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize, withdrawal_state_tree: psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize })?;
        circuits.validate_config(&config)?;
        Ok(Self { circuits, client: PortableClaimClient::new(config, RpcProvider::new_with_config(network)?, services_url)? })
    }
    pub async fn submit(&self, context: &AggregationContext, request: AdmissionRequest) -> Result<()> {
        let record = STANDARD.decode(&request.record)?;
        let family = match request.kind.as_str() { "withdrawal" => 2, "reward" => 3, _ => anyhow::bail!("invalid claim kind") };
        let claim_id = digest(&[&domain_hash(Domain::LeafCommit), &self.config.config_hash()?, &word(family), &record]);
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
    let leaf = WithdrawalLeaf { chain_index: u8::try_from(args.destination_chain_index)?, sender_user_id: u32::try_from(args.sender_user_id)?, recipient: address(&args.recipient)?, token: address(&args.token_address)?, amount: args.amount.parse::<U256>()?.to_be_bytes(), nonce: args.nonce.parse::<U256>()?.to_be_bytes() };
    leaf.validate()?;
    anyhow::ensure!(client.config.chains.iter().any(|c| c.chain_index == leaf.chain_index), "unconfigured withdrawal destination");
    let mut context = client.context().await?;
    loop {
        let attempt: Result<()> = async {
            let request = client.prove_withdrawal(&context, &leaf, &client.circuits.withdrawal).await?;
            client.submit(&context, request).await
        }.await;
        match attempt {
            Ok(()) => return Ok(CommandResult::generic("claim-withdrawal")),
            Err(error) => match error.downcast_ref::<ClaimError>() { Some(ClaimError::ContextChanged(current)) => context = current.clone(), _ => return Err(error) },
        }
    }
}
