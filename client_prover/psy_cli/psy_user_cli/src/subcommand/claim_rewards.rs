use anyhow::{Context, Result};
use hashbrown::HashMap;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::SignType,
    data::{base_types::hash256::Hash256, qhashout::QHashOut},
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage},
};
use psy_client_data::{
    api::reward::{PsyProoffMinerRewardProof, PsyProoffMinerRewardProofWithRewardPreimage, PsyProvingJobClaimMetadata},
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_provider::provider::RpcProvider;

use super::args::ClaimRewardsArgs;
use crate::result::CommandResult;
use psy_client_data::config::store_config::PsyHasher;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_ups_circuit::signature::reward_authorization::RewardAuthorizationInput;
use psy_vm::{reward_authorization::RewardAuthorizationWitness, ups::multisig::{MultisigAccount, MultisigSignatures}};
use super::claim_withdrawal::ClaimClient;
use psy_prover::local::bridge_aggregate::{address, reward_record, reward_membership, multisig_authorization, select_multisig_signatures, FreshAuthorizationRequired, ClaimError};


fn wallet_authorization(info: &psy_cli_common::key_utils::WalletKeyInfo, message: [u8; 32]) -> Result<RewardAuthorizationWitness> {
    match info.sign_type {
        SignType::ZKSign => Ok(RewardAuthorizationWitness::Zk { private_key: info.private_key }),
        SignType::SECP256K1Sign | SignType::EthPersonalSECP256K1Sign => {
            let wallet = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&Hash256::from(info.private_key).0)?;
            let compressed_public_key = wallet.compressed_public_key();
            if info.sign_type == SignType::SECP256K1Sign { Ok(RewardAuthorizationWitness::Secp { compressed_public_key, signature_rs: wallet.sign_prehash_raw(&message)? }) }
            else { Ok(RewardAuthorizationWitness::PersonalSign { compressed_public_key, signature_rs: wallet.sign_prehash_raw(&psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message))? }) }
        }
        _ => anyhow::bail!("wallet identity is not a supported reward authorization family"),
    }
}

async fn reward_terminal_multisig(
    client: &ClaimClient, context: &psy_prover::local::bridge_aggregate::AggregationContext,
    reward: &psy_client_data::bridge_aggregate::RewardLeaf,
    membership: &psy_ups_circuit::signature::reward_authorization::RewardAuthorizationContext,
    account: &MultisigAccount, signatures_path: &str, message: [u8; 32], authorization_preimage: &[u8],
) -> Result<RewardAuthorizationWitness> {
    let bundles: Vec<MultisigSignatures> = serde_json::from_slice(&std::fs::read(signatures_path)?)?;
    account.public_key_param()?;
    let signatures = match select_multisig_signatures(&bundles, &message)? {
        Some(signatures) => signatures,
        None => {
            let mut request = FreshAuthorizationRequired::new(context, membership)?;
            request.message = format!("0x{}", hex::encode(message));
            use base64::{engine::general_purpose::STANDARD, Engine};
            request.record = STANDARD.encode(authorization_preimage);
            println!("{}", serde_json::to_string(&request)?);
            return Err(request.into());
        }
    };
    let (end, _) = client.validate_context(context)?;
    let contract = client.provider.get_user_contract_tree_merkle_proof(end, u64::from(reward.user_id), account.contract_id).await?;
    let mut policy_slots = [QHashOut::ZERO; 4];
    psy_prover::local::bridge_aggregate::verify_path(&contract, membership.authorization_user_leaf.user_state_tree_root,
        u64::from(account.contract_id), contract.value, psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let mut policy_slot_paths = [[QHashOut::ZERO; 4]; 4];
    for slot in 0..4 {
        let path = client.provider.get_user_contract_state_tree_merkle_proof(end, u64::from(reward.user_id), account.contract_id, 4, slot as u64).await?;
        policy_slots[slot] = path.value;
        psy_prover::local::bridge_aggregate::verify_path(&path, contract.value, slot as u64, path.value, 4)?;
        policy_slot_paths[slot] = path.siblings.try_into().map_err(|_| anyhow::anyhow!("reward policy slot path height"))?;
    }
    let policy = psy_vm::ups::multisig::StoredMultisigPolicy { header: policy_slots[0], members: [policy_slots[1], policy_slots[2], policy_slots[3]] }.policy()?;
    for (index, signature) in signatures.member_indices.iter().zip(&signatures.signatures) {
        let member = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<GoldilocksField, plonky2::hash::poseidon::PoseidonPermutation<GoldilocksField>>(psy_client_common::data::secp256k1::CompressedPublicKey(signature.public_key));
        anyhow::ensure!(policy.member_hashes[usize::from(*index)] == member, "reward signature key is not the selected current policy member");
    }
    Ok(RewardAuthorizationWitness::Multisig {
        contract_id: account.contract_id, initial_policy: account.initial_policy.clone(), policy_slots,
        contract_state_paths: std::array::from_fn(|_| contract.siblings.clone()), policy_slot_paths,
        member_indices: [signatures.member_indices[0], signatures.member_indices[1]],
        compressed_public_keys: [signatures.signatures[0].public_key, signatures.signatures[1].public_key],
        signatures_rs: [signatures.signatures[0].signature, signatures.signatures[1].signature],
    })
}

async fn wait_reward_acceptance(
    client: &ClaimClient, context: &psy_prover::local::bridge_aggregate::AggregationContext,
    user: u32, source: u32, proof_id: [u8; 32], new_root: [u64; 4],
    claim_id: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
    loop {
        let status: psy_prover::local::bridge_aggregate::ClaimStatus = client.response(client.http
            .get(format!("{}/api/v1/bridge/aggregation/claims/{}", client.url, claim_id)).send().await?).await?;
        client.validate_status(context, claim_id, 3, &status)?;
        let snapshot = read_reward_snapshot(client, context, user, source).await?;
        if let Some(own) = &snapshot.own {
            if own.proof_id.strip_prefix("0x").unwrap_or(&own.proof_id) == hex::encode(proof_id) {
                let step = own.verify(client, user, source)?;
                anyhow::ensure!(reward_snapshot_hash(&own.new_root)? == new_root
                    && psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_ledger_state_root(&step.new_state)? == new_root,
                    "accepted reward proof root mismatch");
                return Ok(());
            }
        }
        anyhow::ensure!(!matches!(snapshot.outcome, RewardClaimOutcome::NewWindow), "reward window changed while awaiting acceptance");
        anyhow::ensure!(tokio::time::Instant::now() < deadline, "reward claim acceptance timed out; submission must not be repeated blindly");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}



pub async fn run(args: ClaimRewardsArgs) -> Result<CommandResult> {
    anyhow::ensure!(args.multisig_account.is_some() == args.signatures.is_some(), "--multisig-account and --signatures must be supplied together");
    let user_id = u32::try_from(args.user_id)?;
    let recipient = address(&args.recipient)?;
    anyhow::ensure!(recipient != [0; 20], "reward recipient must be nonzero");
    let account: Option<MultisigAccount> = if let Some(path) = &args.multisig_account {
        anyhow::ensure!(args.wallet.private_key.is_none() && args.wallet.keystore_path.is_none() && args.wallet.fingerprint.is_none() && args.wallet.wallet_password.is_none(), "multisig authorization conflicts with secret wallet inputs");
        let account: MultisigAccount = serde_json::from_slice(&std::fs::read(path)?)?;
        account.public_key_param()?;
        Some(account)
    } else { None };
    let wallet = if account.is_none() {
        anyhow::ensure!(matches!(args.wallet.sign_type, SignType::ZKSign | SignType::SECP256K1Sign | SignType::EthPersonalSECP256K1Sign), "unsupported reward wallet identity");
        Some(load_wallet_key_info(&args.wallet, false)?)
    } else { None };
    let client = ClaimClient::load(&args.rpc_config, &args.aggregate_config, &args.services_url)?;
    let jobs = validate_and_deduplicate_jobs(load_job_ids_from_file(&args.jobs_file)?, args.user_id, &args.jobs_file)?;
    anyhow::ensure!(jobs.jobs_len() != 0, "no reward jobs selected");
    let mut proofs = build_realm_proofs(&client.provider, jobs.realm_jobs).await?;
    for (checkpoint, batch) in build_proofs(&client.provider, jobs.coordinator_jobs, 2).await? { proofs.entry(checkpoint).or_default().extend(batch); }
    let mut selected = std::collections::BTreeMap::new();
    let mut checkpoints: Vec<_> = proofs.keys().copied().collect();
    checkpoints.sort_unstable();
    for checkpoint in checkpoints {
        for proof in &proofs[&checkpoint] {
            let (record, tag) = reward_record(checkpoint, user_id, recipient, proof)?;
            selected.entry(checkpoint).or_insert_with(Vec::new).push((record, tag, proof.inner.tag_tree_proof.root));
        }
    }
    anyhow::ensure!(!selected.is_empty(), "no reward witnesses returned");
    let mut context = client.context().await?;
    for (_source_checkpoint, source_jobs) in selected {
      let mut nullifiers = RewardSessionNullifiers::default();
      let mut accepted_window = None;
      let job_count = source_jobs.len();
      for (job_index, (reward, tag, tag_root)) in source_jobs.into_iter().enumerate() {
        let mut submitted = false;
        loop {
            let attempt: Result<()> = async {
                let mut snapshot = read_reward_snapshot(&client, &context, user_id, u32::try_from(reward.claim_checkpoint_id)?).await?;
                let queued_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
                while matches!(snapshot.outcome, RewardClaimOutcome::ClaimQueued) {
                    let claim_id = snapshot.queued_claim_id.as_deref().context("queued reward snapshot has no claim id")?;
                    anyhow::ensure!(tokio::time::Instant::now() < queued_deadline, "reward claim {claim_id} remained queued for 600 seconds");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    snapshot = read_reward_snapshot(&client, &context, user_id, u32::try_from(reward.claim_checkpoint_id)?).await?;
                }
                anyhow::ensure!(snapshot.context_id == context.context_id && snapshot.user_id == user_id.to_string()
                    && snapshot.source_checkpoint_id == reward.claim_checkpoint_id.to_string(), "reward snapshot identity mismatch");
                {
                    snapshot.validate()?;
                    let window = snapshot.window.decode()?;
                    let (end_id, end_root) = client.validate_context(&context)?;
                    anyhow::ensure!(window.config_hash == client.config.config_hash()?
                        && window.economic_domain == client.config.clone().load()?.economic_domain()
                        && u64::from(window.end_checkpoint_id) == end_id && window.end_checkpoint_root == end_root,
                        "reward snapshot window differs from configured context");
                    let state = snapshot.state.decode()?;
                    match &snapshot.tip {
                        Some(tip) => {
                            let step = tip.verify(&client)?;
                            anyhow::ensure!(step.new_state == state && tip.new_root == snapshot.expected_root, "reward snapshot tip differs from state");
                            if let Some(parent) = &snapshot.predecessor_root {
                                anyhow::ensure!(psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_ledger_state_root(&step.old_state)? == reward_snapshot_hash(parent)?, "reward snapshot parent root mismatch");
                            }
                        }
                        None => anyhow::ensure!(snapshot.revision == "0" && snapshot.predecessor_root.is_none()
                            && reward_snapshot_hash(&snapshot.expected_root)? == psy_client_data::bridge_aggregate::origin_state_root(), "reward snapshot lacks an authenticated predecessor"),
                    }
                }
                let membership = reward_membership(&client, &context, &reward).await?;
                anyhow::ensure!(membership.claim_checkpoint_leaf.stats.pm_rewards_commitment.gutas_root == tag_root, "reward proof does not reach authenticated full GUTA root");
                use base64::{engine::general_purpose::STANDARD, Engine};
                use plonky2::{field::types::PrimeField64, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
                use psy_plonky2_circuits::bridge::circuits::{reward_ledger, reward_session::{RewardSessionJobWitness, RewardSessionWitness}};
                let window = snapshot.window.decode()?;
                if let Some(previous_window) = accepted_window {
                    anyhow::ensure!(previous_window == window.window_id, "reward window changed after an accepted session step");
                }
                snapshot.validate()?;
                let old_state = snapshot.state.decode()?;
                let own_step = snapshot.own.as_ref().map(|own| own.verify(&client, user_id, u32::try_from(reward.claim_checkpoint_id)?)).transpose()?;
                anyhow::ensure!(own_step.as_ref().is_none_or(|step| !step.is_final_step), "reward session is already finalized");
                anyhow::ensure!(own_step.is_none() == (job_index == 0), "reward session continuation does not match locally accepted jobs");
                let decode_proof = |bytes: Vec<u8>| ProofWithPublicInputs::<GoldilocksField, PoseidonGoldilocksConfig, 2>::from_bytes(bytes, &client.circuits.reward_session.circuit_data.common)
                    .map_err(|error| anyhow::anyhow!("reward session predecessor decoding: {error}"));
                let own_proof = own_step.as_ref().map(|step| decode_proof(step.proof.clone())).transpose()?;
                let global_proof = snapshot.tip.as_ref().map(|tip| STANDARD.decode(&tip.proof).map_err(anyhow::Error::from).and_then(decode_proof)).transpose()?;
                let own_fields = own_proof.as_ref().map(|proof| psy_client_data::bridge_aggregate::RewardSessionProofFields::from_public_inputs(
                    &proof.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>())).transpose()?;
                let source = u32::try_from(reward.claim_checkpoint_id)?;
                let key = (u64::from(source) << 31) | (u64::from(reward.height) << 26) | u64::from(reward.path_index);
                let job = RewardSessionJobWitness { height: reward.height, path_index: reward.path_index,
                    tag: psy_plonky2_circuits::bridge::circuits::reward_inclusion::RewardTagWitness {
                        tag_preimage: tag.tag_preimage, leaf_left: tag.leaf_left, leaf_right: tag.leaf_right,
                        leaf_tag: tag.leaf_tag, siblings: tag.siblings, parent_tags: tag.parent_tags,
                    }, nullifier_siblings: nullifiers.siblings(key)? };
                let jobs = [job];
                let old_session_root = own_step.as_ref().map(|step| step.session_root).unwrap_or(reward_ledger::reward_issued_empty_hash(63)?);
                let session_root = reward_ledger::reward_session_root(source, old_session_root, &jobs)?;
                let recipient_words: [u32; 5] = std::array::from_fn(|index| u32::from_be_bytes(recipient[(4-index)*4..(5-index)*4].try_into().expect("fixed recipient width")));
                let source_hash = membership.claim_checkpoint_leaf.qfhash::<PsyHasher>().0.elements.map(|value| value.to_canonical_u64());
                let seed = reward_session_seed(&window, source, user_id, recipient_words, source_hash);
                let reward_amount: [u32; 8] = std::array::from_fn(|index| u32::from_be_bytes(client.config.reward_per_claim[(7-index)*4..(8-index)*4].try_into().expect("fixed reward amount width")));
                let previous_count = own_fields.as_ref().map_or(0, |fields| fields.count);
                anyhow::ensure!(usize::try_from(previous_count)? == job_index, "reward session accepted job count mismatch");
                let mut statement = psy_client_data::bridge_aggregate::RewardSessionProofFields {
                    checkpoint_tree_root: window.end_checkpoint_root, user_id,
                    recipient: std::array::from_fn(|index| if index < 5 { recipient_words[index] } else { 0 }),
                    total_amount: reward_add_amount(own_fields.as_ref().map_or([0; 8], |fields| fields.total_amount), reward_amount)?,
                    count: previous_count.checked_add(1).context("reward session count overflow")?,
                    jobs_commitment: reward_step_commitment(own_fields.as_ref().map_or(seed, |fields| fields.jobs_commitment), previous_count, &reward,
                        reward_amount, tag.leaf_tag.0.elements.map(|value| value.to_canonical_u64()))?,
                    old_ledger_state_root: reward_ledger::reward_ledger_state_root(&old_state)?, new_ledger_state_root: [0; 4],
                };
                let is_final_step = job_index + 1 == job_count;
                let (_, window_hash) = reward_ledger::window_hash(&window, &client.circuits.reward_session.circuit_data.verifier_only)?;
                let new_state = reward_next_state(&snapshot, &mut statement, seed, session_root, window_hash, is_final_step)?;
                let scheme = if account.is_some() { 3 } else { match wallet.as_ref().context("missing reward wallet")?.sign_type {
                    SignType::ZKSign => 0, SignType::SECP256K1Sign => 1, SignType::EthPersonalSECP256K1Sign => 2,
                    _ => anyhow::bail!("unsupported reward session signature scheme"),
                }};
                let parameter = if let Some(account) = &account { account.public_key_param()? } else { wallet.as_ref().context("missing reward wallet")?.public_key_param };
                let public_key_param = parameter.0.elements.map(|value| value.to_canonical_u64());
                let identity = client.circuits.reward_session.identity_fingerprint_for_scheme(scheme)?;
                let registered = psy_crypto::signature::zk::data::ZKPublicKeyInfo {
                    fingerprint: QHashOut::from_values(identity[0], identity[1], identity[2], identity[3]), public_key_param: parameter,
                }.qfhash::<PsyHasher>();
                anyhow::ensure!(membership.authorization_user_leaf.public_key == registered, "reward terminal account identity mismatch");
                let authorization_preimage = reward_terminal_preimage(&window, &statement, &membership, identity, public_key_param)?;
                let message = psy_prover::local::bridge_aggregate::hex32(&psy_prover::local::bridge_aggregate::digest(&[&authorization_preimage]))?;
                let authorization = if !is_final_step { None } else if let Some(account) = &account {
                    Some(reward_terminal_multisig(&client, &context, &reward, &membership, account,
                        args.signatures.as_ref().context("missing multisig signatures path")?, message,
                        &authorization_preimage).await?)
                } else { Some(wallet_authorization(wallet.as_ref().context("missing reward wallet")?, message)?) };
                let to_words = |hash: &QHashOut<GoldilocksField>| hash.0.elements.map(|value| value.to_canonical_u64());
                let witness = RewardSessionWitness {
                    statement, config: client.config.clone(), economic_domain: window.economic_domain, window_id: window.window_id,
                    start_root: window.start_root, source_checkpoint_id: source, end_checkpoint_id: window.end_checkpoint_id,
                    source_leaf: membership.claim_checkpoint_leaf, source_path: membership.claim_checkpoint_path.iter().map(to_words).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward source path height"))?,
                    old_state, new_state, own_state: own_step.as_ref().map_or(old_state, |step| step.new_state),
                    old_summary: reward_snapshot_hash(&snapshot.own_summary)?, old_session_root,
                    session_siblings: reward_snapshot_siblings(&snapshot.session_siblings)?, own_siblings: reward_snapshot_siblings(&snapshot.own_siblings)?,
                    ledger_siblings: reward_snapshot_siblings(&snapshot.issued_siblings)?, own_previous: own_proof.as_ref(), global_previous: global_proof.as_ref(),
                    jobs: &jobs, is_final_step, end_leaf: membership.end_checkpoint_leaf,
                    end_path: membership.end_checkpoint_path.iter().map(to_words).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward end path height"))?,
                    end_roots: membership.end_global_state_roots, user_leaf: membership.authorization_user_leaf,
                    user_path: membership.authorization_user_path.iter().map(to_words).collect(), public_key_param, authorization: authorization.as_ref(),
                };
                let transition = client.prove_reward_session(&context, &client.circuits.reward_session, &witness, &window, statement.old_ledger_state_root)?;
                let request = psy_prover::local::bridge_aggregate::RewardSessionClaimRequest {
                    version: 2, context_id: context.context_id.clone(), kind: "reward".to_owned(),
                    record: STANDARD.encode(transition.source_payout.as_ref().map(|leaf| leaf.encode()).transpose()?.unwrap_or_default()),
                    transition: STANDARD.encode(&transition.transition_bytes),
                };
                use psy_prover::local::bridge_aggregate::{digest, hex32, word};
                use psy_client_data::bridge_aggregate::{domain_hash, Domain};
                let record = STANDARD.decode(&request.record)?;
                let transition_hash = hex32(&digest(&[&transition.transition_bytes]))?;
                let claim_id = digest(&[&domain_hash(Domain::LeafCommit), &window.config_hash, &word(3), &record, &transition_hash]);
                submitted = true;
                let status = client.submit_reward_session(&context, &request).await?;
                client.validate_status(&context, &claim_id, 3, &status)?;
                wait_reward_acceptance(&client, &context, user_id, source, transition.proof_id, statement.new_ledger_state_root, &claim_id).await?;
                nullifiers.accept(key, session_root)?;
                accepted_window = Some(window.window_id);
                Ok(())
            }.await;
            match attempt {
                Ok(()) => break,
                Err(error) => match error.downcast_ref::<ClaimError>() {
                    Some(ClaimError::ContextChanged(current)) if !submitted => context = current.clone(),
                    _ => return Err(error),
                },
            }
        }
      }
    }
    Ok(CommandResult::generic("claim-rewards"))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum RewardClaimOutcome { NewWindow, ClaimAccepted, ClaimQueued, SameWindowAdvanced }

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RewardSnapshotWindow {
    config_hash: String,
    economic_domain: String,
    window_id: String,
    end_checkpoint_id: String,
    end_checkpoint_root: String,
    start_root: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RewardSnapshotState {
    ledger_window_hash: String,
    ledger_root: String,
    user_root: String,
    session_count: String,
    unfinished_session_count: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RewardSnapshotTip {
    proof_id: String,
    proof: String,
    transition: String,
    new_root: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RewardSnapshotOwn {
    proof_id: String,
    proof: String,
    transition: String,
    new_root: String,
    own_state: RewardSnapshotState,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RewardClaimSnapshot {
    outcome: RewardClaimOutcome,
    context_id: String,
    user_id: String,
    source_checkpoint_id: String,
    revision: String,
    expected_root: String,
    predecessor_root: Option<String>,
    window: RewardSnapshotWindow,
    state: RewardSnapshotState,
    tip: Option<RewardSnapshotTip>,
    own: Option<RewardSnapshotOwn>,
    own_summary: String,
    session_siblings: Vec<String>,
    own_siblings: Vec<String>,
    issued_siblings: Vec<String>,
    queued_claim_id: Option<String>,
}

impl RewardSnapshotTip {
    fn verify(&self, client: &ClaimClient) -> Result<psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerStep> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use plonky2::{field::types::PrimeField64, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
        use psy_plonky2_circuits::bridge::circuits::reward_ledger::{deserialize_reward_ledger_transition, reward_hash_bytes, reward_ledger_proof_id, reward_ledger_state_root, verify_reward_ledger_step};
        let bytes = STANDARD.decode(&self.proof)?;
        let transition = STANDARD.decode(&self.transition)?;
        anyhow::ensure!(bytes.len() <= 16_777_216 && transition.len() <= 16_777_216
            && STANDARD.encode(&bytes) == self.proof && STANDARD.encode(&transition) == self.transition, "invalid reward snapshot proof encoding");
        let circuit = &client.circuits.reward_session.circuit_data;
        let proof = ProofWithPublicInputs::<GoldilocksField, PoseidonGoldilocksConfig, 2>::from_bytes(bytes.clone(), &circuit.common)
            .map_err(|error| anyhow::anyhow!("reward snapshot proof decoding: {error}"))?;
        let fields = psy_client_data::bridge_aggregate::RewardSessionProofFields::from_public_inputs(
            &proof.public_inputs.iter().map(|field| field.to_canonical_u64()).collect::<Vec<_>>())?;
        let (window, step, nodes) = deserialize_reward_ledger_transition(&transition)?;
        anyhow::ensure!(step.proof == bytes && fields.new_ledger_state_root == reward_snapshot_hash(&self.new_root)?, "reward snapshot proof/root mismatch");
        let verified = verify_reward_ledger_step(&circuit.common, &circuit.verifier_only, &window, reward_ledger_state_root(&step.old_state)?, &step)?;
        anyhow::ensure!(verified.transition_bytes == transition && verified.nodes == nodes
            && verified.new_root == reward_hash_bytes(fields.new_ledger_state_root)?
            && self.proof_id.strip_prefix("0x").unwrap_or(&self.proof_id) == hex::encode(reward_ledger_proof_id(&circuit.verifier_only, &bytes)?), "reward snapshot transition identity mismatch");
        Ok(step)
    }
}


impl RewardSnapshotWindow {
    fn decode(&self) -> Result<psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues> {
        fn bytes32(text: &str) -> Result<[u8; 32]> {
            let text = text.strip_prefix("0x").unwrap_or(text);
            anyhow::ensure!(text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid reward window bytes");
            hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("reward window byte width"))
        }
        Ok(psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues {
            config_hash: bytes32(&self.config_hash)?, economic_domain: bytes32(&self.economic_domain)?,
            window_id: bytes32(&self.window_id)?, end_checkpoint_id: reward_snapshot_u32(&self.end_checkpoint_id)?,
            end_checkpoint_root: reward_snapshot_hash(&self.end_checkpoint_root)?, start_root: reward_snapshot_hash(&self.start_root)?,
        })
    }
}

#[derive(Default)]
struct RewardSessionNullifiers {
    nodes: std::collections::BTreeMap<(u8, u64), [u64; 4]>,
}

impl RewardSessionNullifiers {
    fn siblings(&self, key: u64) -> Result<[[u64; 4]; 63]> {
        use psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_issued_parent_hash;
        anyhow::ensure!(key < (1u64 << 63), "reward session nullifier key exceeds 63 bits");
        anyhow::ensure!(!self.nodes.contains_key(&(0, key)), "reward job is already consumed by this session");
        let mut empty = [0; 4];
        let mut siblings = [[0; 4]; 63];
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.nodes.get(&(u8::try_from(height)?, (key >> height) ^ 1)).copied().unwrap_or(empty);
            empty = reward_issued_parent_hash(empty, empty)?;
        }
        Ok(siblings)
    }

    fn accept(&mut self, key: u64, expected_root: [u64; 4]) -> Result<()> {
        use psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_issued_parent_hash;
        let siblings = self.siblings(key)?;
        let mut value = [1, 0, 0, 0];
        let mut path = Vec::with_capacity(64);
        path.push(((0, key), value));
        for (height, sibling) in siblings.into_iter().enumerate() {
            value = if (key >> height) & 1 == 0 { reward_issued_parent_hash(value, sibling)? } else { reward_issued_parent_hash(sibling, value)? };
            path.push(((u8::try_from(height + 1)?, key >> (height + 1)), value));
        }
        anyhow::ensure!(value == expected_root, "accepted reward session nullifier root mismatch");
        self.nodes.extend(path);
        Ok(())
    }
}
fn reward_poseidon_bytes(bytes: &[u8]) -> [u64; 4] {
    use plonky2::{field::types::{Field, PrimeField64}, hash::poseidon::PoseidonHash, plonk::config::Hasher};
    PoseidonHash::hash_no_pad(&bytes.iter().map(|byte| GoldilocksField::from_canonical_u8(*byte)).collect::<Vec<_>>())
        .elements.map(|value| value.to_canonical_u64())
}

fn reward_append_hash(bytes: &mut Vec<u8>, hash: [u64; 4]) {
    for limb in hash { bytes.extend_from_slice(&limb.to_le_bytes()); }
}

fn reward_step_commitment(
    previous: [u64; 4], previous_count: u32, reward: &psy_client_data::bridge_aggregate::RewardLeaf,
    amount: [u32; 8], leaf_tag: [u64; 4],
) -> Result<[u64; 4]> {
    let mut bytes = b"PsyRewardJobs/Step/1".to_vec();
    reward_append_hash(&mut bytes, previous);
    for count in [previous_count, 1, previous_count.checked_add(1).context("reward session count overflow")?] {
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    bytes.extend_from_slice(&u32::try_from(reward.claim_checkpoint_id)?.to_le_bytes());
    bytes.push(reward.height);
    for value in [reward.path_index, reward.nullifier_index, reward.user_id] { bytes.extend_from_slice(&value.to_le_bytes()); }
    for value in amount { bytes.extend_from_slice(&value.to_le_bytes()); }
    reward_append_hash(&mut bytes, leaf_tag);
    bytes.extend_from_slice(&[0, 1]);
    Ok(reward_poseidon_bytes(&bytes))
}

fn reward_add_amount(previous: [u32; 8], increment: [u32; 8]) -> Result<[u32; 8]> {
    let mut amount = [0; 8];
    let mut carry = 0u64;
    for index in 0..8 {
        let sum = u64::from(previous[index]) + u64::from(increment[index]) + carry;
        amount[index] = sum as u32;
        carry = sum >> 32;
    }
    anyhow::ensure!(carry == 0, "reward session amount overflow");
    Ok(amount)
}

fn reward_session_seed(
    window: &psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues,
    source: u32, user: u32, recipient: [u32; 5], source_hash: [u64; 4],
) -> [u64; 4] {
    let mut bytes = b"PsyRewardJobs/Session/1".to_vec();
    bytes.extend_from_slice(&window.economic_domain);
    bytes.extend_from_slice(&source.to_le_bytes());
    bytes.extend_from_slice(&user.to_le_bytes());
    for limb in recipient { bytes.extend_from_slice(&limb.to_le_bytes()); }
    reward_append_hash(&mut bytes, window.end_checkpoint_root);
    reward_append_hash(&mut bytes, source_hash);
    reward_poseidon_bytes(&bytes)
}

fn reward_session_summary(
    statement: &psy_client_data::bridge_aggregate::RewardSessionProofFields,
    seed: [u64; 4], session_root: [u64; 4], is_final_step: bool,
) -> Result<[u64; 4]> {
    let fields = statement.to_public_inputs()?;
    let mut bytes = b"PsyRewardSession/Summary/1".to_vec();
    for field in &fields[..30] { bytes.extend_from_slice(&field.to_le_bytes()); }
    reward_append_hash(&mut bytes, seed);
    reward_append_hash(&mut bytes, session_root);
    bytes.push(u8::from(is_final_step));
    Ok(reward_poseidon_bytes(&bytes))
}

fn reward_issued_leaf(
    window: &psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues,
    source: u32, statement: &psy_client_data::bridge_aggregate::RewardSessionProofFields,
    window_hash: [u64; 4],
) -> [u64; 4] {
    let mut bytes = b"PsyRewardLedger/Issued/1".to_vec();
    bytes.extend_from_slice(&window.economic_domain);
    bytes.extend_from_slice(&source.to_le_bytes());
    bytes.extend_from_slice(&statement.user_id.to_le_bytes());
    for limb in statement.total_amount.iter().chain(&statement.recipient[..5]) {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    reward_append_hash(&mut bytes, statement.jobs_commitment);
    reward_append_hash(&mut bytes, window_hash);
    reward_poseidon_bytes(&bytes)
}

fn reward_next_state(
    snapshot: &RewardClaimSnapshot,
    statement: &mut psy_client_data::bridge_aggregate::RewardSessionProofFields,
    seed: [u64; 4], session_root: [u64; 4], window_hash: [u64; 4], is_final_step: bool,
) -> Result<psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::{reward_issued_parent_hash, reward_ledger_state_root};
    let window = snapshot.window.decode()?;
    let old_state = snapshot.state.decode()?;
    let first_global = reward_ledger_state_root(&old_state)? == window.start_root;
    let first_own = snapshot.own.is_none();
    let mut next = old_state;
    next.ledger_window_hash = window_hash;
    next.session_count = if first_global { 0 } else { old_state.session_count };
    next.unfinished_session_count = if first_global { 0 } else { old_state.unfinished_session_count };
    if first_own {
        next.session_count = next.session_count.checked_add(1).context("reward session count overflow")?;
        if !is_final_step {
            next.unfinished_session_count = next.unfinished_session_count.checked_add(1).context("reward unfinished session count overflow")?;
        }
    } else if is_final_step {
        next.unfinished_session_count = next.unfinished_session_count.checked_sub(1).context("reward session was not open")?;
    }
    statement.old_ledger_state_root = reward_ledger_state_root(&old_state)?;
    let summary = reward_session_summary(statement, seed, session_root, is_final_step)?;
    next.user_root = reward_summary_root(statement.user_id, summary, &reward_snapshot_siblings::<32>(&snapshot.session_siblings)?)?;
    if is_final_step {
        let source = reward_snapshot_u32(&snapshot.source_checkpoint_id)?;
        let key = u64::from(statement.user_id) | (u64::from(source) << 32);
        let mut root = reward_issued_leaf(&window, source, statement, window_hash);
        for (height, sibling) in reward_snapshot_siblings::<64>(&snapshot.issued_siblings)?.into_iter().enumerate() {
            root = if (key >> height) & 1 == 0 { reward_issued_parent_hash(root, sibling)? } else { reward_issued_parent_hash(sibling, root)? };
        }
        next.ledger_root = root;
    }
    anyhow::ensure!(next.unfinished_session_count <= next.session_count, "reward session counters are inconsistent");
    statement.new_ledger_state_root = reward_ledger_state_root(&next)?;
    Ok(next)
}

fn reward_terminal_preimage(
    window: &psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues,
    statement: &psy_client_data::bridge_aggregate::RewardSessionProofFields,
    membership: &psy_ups_circuit::signature::reward_authorization::RewardAuthorizationContext,
    identity_fingerprint: [u64; 4], public_key_param: [u64; 4],
) -> Result<Vec<u8>> {
    use plonky2::field::types::PrimeField64;
    use psy_vm::reward_authorization::{reward_session_authorization_preimage, RewardSessionAuthorization};
    reward_session_authorization_preimage(&RewardSessionAuthorization {
        config_hash: window.config_hash, economic_domain: window.economic_domain, window_id: window.window_id,
        source_checkpoint_id: u32::try_from(membership.reward.claim_checkpoint_id)?,
        end_checkpoint_id: window.end_checkpoint_id, user_id: statement.user_id,
        checkpoint_tree_root: statement.checkpoint_tree_root,
        source_checkpoint_leaf_hash: membership.claim_checkpoint_leaf.qfhash::<PsyHasher>().0.elements.map(|value| value.to_canonical_u64()),
        end_checkpoint_leaf_hash: membership.end_checkpoint_leaf.qfhash::<PsyHasher>().0.elements.map(|value| value.to_canonical_u64()),
        user_leaf_hash: membership.authorization_user_leaf.qfhash::<PsyHasher>().0.elements.map(|value| value.to_canonical_u64()),
        identity_fingerprint, public_key_param, nonce: membership.authorization_user_leaf.nonce.to_canonical_u64(),
        jobs_commitment: statement.jobs_commitment, count: statement.count, amount: statement.total_amount,
        recipient: std::array::from_fn(|index| statement.recipient[index]),
    })
}

impl RewardSnapshotOwn {
    fn verify(&self, client: &ClaimClient, user_id: u32, source_checkpoint_id: u32) -> Result<psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerStep> {
        let tip = RewardSnapshotTip { proof_id: self.proof_id.clone(), proof: self.proof.clone(), transition: self.transition.clone(), new_root: self.new_root.clone() };
        let step = tip.verify(client)?;
        anyhow::ensure!(step.new_state == self.own_state.decode()? && step.source_checkpoint_id == source_checkpoint_id,
            "reward own proof state/source mismatch");
        use plonky2::{field::types::PrimeField64, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
        let proof = ProofWithPublicInputs::<GoldilocksField, PoseidonGoldilocksConfig, 2>::from_bytes(step.proof.clone(), &client.circuits.reward_session.circuit_data.common)
            .map_err(|error| anyhow::anyhow!("reward own proof decoding: {error}"))?;
        anyhow::ensure!(proof.public_inputs[4].to_canonical_u64() == u64::from(user_id), "reward own proof user mismatch");
        Ok(step)
    }
}

fn reward_snapshot_siblings<const N: usize>(values: &[String]) -> Result<[[u64; 4]; N]> {
    anyhow::ensure!(values.len() == N, "reward snapshot requires {N} siblings");
    let mut siblings = [[0; 4]; N];
    for (sibling, value) in siblings.iter_mut().zip(values) { *sibling = reward_snapshot_hash(value)?; }
    Ok(siblings)
}

fn reward_summary_root(user_id: u32, mut value: [u64; 4], siblings: &[[u64; 4]; 32]) -> Result<[u64; 4]> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_user_parent_hash;
    for (height, sibling) in siblings.iter().copied().enumerate() {
        let (left, right) = if (user_id >> height) & 1 == 0 { (value, sibling) } else { (sibling, value) };
        value = reward_user_parent_hash(u8::try_from(height + 1)?, left, right)?;
    }
    Ok(value)
}

fn reward_snapshot_hash(text: &str) -> Result<[u64; 4]> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    anyhow::ensure!(text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid reward snapshot hash encoding");
    let bytes = hex::decode(text)?;
    let mut hash = [0; 4];
    for (limb, bytes) in hash.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(bytes.try_into()?);
        anyhow::ensure!(*limb < 0xffff_ffff_0000_0001, "noncanonical reward snapshot hash limb");
    }
    Ok(hash)
}

fn reward_snapshot_u32(text: &str) -> Result<u32> {
    let value: u32 = text.parse()?;
    anyhow::ensure!(value.to_string() == text, "noncanonical reward snapshot integer");
    Ok(value)
}

impl RewardSnapshotState {
    fn decode(&self) -> Result<psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues> {
        Ok(psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues {
            ledger_window_hash: reward_snapshot_hash(&self.ledger_window_hash)?,
            ledger_root: reward_snapshot_hash(&self.ledger_root)?,
            user_root: reward_snapshot_hash(&self.user_root)?,
            session_count: reward_snapshot_u32(&self.session_count)?,
            unfinished_session_count: reward_snapshot_u32(&self.unfinished_session_count)?,
        })
    }
}

impl RewardClaimSnapshot {
    fn validate(&self) -> Result<()> {
        use psy_plonky2_circuits::bridge::circuits::reward_ledger::{reward_ledger_state_root, reward_user_parent_hash, reward_issued_parent_hash, reward_user_empty_hash};
        let state = self.state.decode()?;
        anyhow::ensure!(reward_ledger_state_root(&state)? == reward_snapshot_hash(&self.expected_root)?, "reward snapshot state root mismatch");
        anyhow::ensure!(self.session_siblings.len() == 32 && self.own_siblings.len() == 32 && self.issued_siblings.len() == 64, "reward snapshot path height mismatch");
        let user = reward_snapshot_u32(&self.user_id)?;
        let source = reward_snapshot_u32(&self.source_checkpoint_id)?;
        let mut summary = reward_snapshot_hash(&self.own_summary)?;
        for (height, sibling) in self.session_siblings.iter().enumerate() {
            let sibling = reward_snapshot_hash(sibling)?;
            let (left, right) = if (user >> height) & 1 == 0 { (summary, sibling) } else { (sibling, summary) };
            summary = reward_user_parent_hash(u8::try_from(height + 1)?, left, right)?;
        }
        let first_global = reward_snapshot_hash(&self.expected_root)? == reward_snapshot_hash(&self.window.start_root)?;
        let user_root = if first_global { reward_user_empty_hash(32)? } else { state.user_root };
        anyhow::ensure!(summary == user_root, "reward snapshot summary path mismatch");
        let key = u64::from(user) | (u64::from(source) << 32);
        let mut issued = [0; 4];
        for (height, sibling) in self.issued_siblings.iter().enumerate() {
            let sibling = reward_snapshot_hash(sibling)?;
            issued = if (key >> height) & 1 == 0 { reward_issued_parent_hash(issued, sibling)? } else { reward_issued_parent_hash(sibling, issued)? };
        }
        anyhow::ensure!(issued == state.ledger_root, "reward source credit is occupied or issued path differs");
        Ok(())
    }
}

async fn read_reward_snapshot(
    client: &ClaimClient, context: &psy_prover::local::bridge_aggregate::AggregationContext,
    user_id: u32, source_checkpoint_id: u32,
) -> Result<RewardClaimSnapshot> {
    let response = client.http.get(format!("{}/api/v1/bridge/aggregation/reward-ledger", client.url))
        .query(&[("contextId", context.context_id.clone()), ("userId", user_id.to_string()),
            ("sourceCheckpointId", source_checkpoint_id.to_string())]).send().await?;
    anyhow::ensure!(response.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE, "reward ledger is not initialized");
    client.response(response).await
}

#[derive(Debug, serde::Serialize)]
struct ClaimRewardJobsWithRealm {
    realm_jobs: Vec<(u64, u64, QProvingJobDataIDWithRewardPreimage)>,
    coordinator_jobs: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
}

impl ClaimRewardJobsWithRealm {
    fn new_empty() -> Self {
        Self {
            realm_jobs: vec![],
            coordinator_jobs: vec![],
        }
    }

    fn jobs_len(&self) -> usize {
        self.realm_jobs.len() + self.coordinator_jobs.len()
    }
}

fn validate_and_deduplicate_jobs(
    jobs: ClaimRewardJobsWithRealm,
    expected_user_id: u64,
    jobs_file: &str,
) -> Result<ClaimRewardJobsWithRealm> {
    let mut seen: HashMap<QProvingJobDataID, (Option<u64>, u64, u64, QHashOut<GoldilocksField>)> = HashMap::new();
    let mut deduplicated = ClaimRewardJobsWithRealm::new_empty();
    for (realm_id, unique_pending_id, job) in jobs.realm_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, &format!("realm_id={realm_id}"))?;
        let identity = (Some(realm_id), unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!("jobs file {} contains conflicting duplicate job_id {:?}", jobs_file, job.inner.job_data_id),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.realm_jobs.push((realm_id, unique_pending_id, job));
            }
        }
    }
    for (unique_pending_id, job) in jobs.coordinator_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, "coordinator")?;
        let identity = (None, unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!("jobs file {} contains conflicting duplicate job_id {:?}", jobs_file, job.inner.job_data_id),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.coordinator_jobs.push((unique_pending_id, job));
            }
        }
    }
    Ok(deduplicated)
}

fn validate_reward_preimage_user(
    job: &QProvingJobDataIDWithRewardPreimage,
    expected_user_id: u64,
    jobs_file: &str,
    source: &str,
) -> Result<()> {
    let preimage_user_id = job.reward_tree_tag_preimage.0.elements[0].0;
    anyhow::ensure!(
        preimage_user_id == expected_user_id,
        "jobs file {} contains a reward for user_id {}, but current wallet user_id is {}: {}, job_id={:?}",
        jobs_file,
        preimage_user_id,
        expected_user_id,
        source,
        job.inner.job_data_id,
    );
    Ok(())
}

fn index_reward_preimages(
    jobs: &[QProvingJobDataIDWithRewardPreimage],
) -> Result<HashMap<QProvingJobDataID, QHashOut<GoldilocksField>>> {
    let mut index = HashMap::new();
    for job in jobs {
        if let Some(existing) = index.insert(job.inner.job_data_id, job.reward_tree_tag_preimage) {
            anyhow::ensure!(existing == job.reward_tree_tag_preimage, "conflicting reward preimages for duplicate job_id {:?}", job.inner.job_data_id);
        }
    }
    Ok(index)
}

fn attach_reward_preimages(
    proofs: Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>,
    preimages: &HashMap<QProvingJobDataID, QHashOut<GoldilocksField>>,
    source: &str,
) -> Result<Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>> {
    let mut matched = HashMap::new();
    let mut attached = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let reward_tree_tag_preimage = preimages
            .get(&proof.job_id)
            .copied()
            .with_context(|| format!("missing reward preimage for {} proof job {:?}", source, proof.job_id))?;
        anyhow::ensure!(
            matched.insert(proof.job_id, ()).is_none(),
            "duplicate {} proof for job {:?}",
            source,
            proof.job_id,
        );
        attached.push(PsyProoffMinerRewardProofWithRewardPreimage { inner: proof, reward_tree_tag_preimage });
    }
    if matched.len() != preimages.len() {
        let missing = preimages
            .keys()
            .filter(|job_id| !matched.contains_key(*job_id))
            .copied()
            .collect::<Vec<_>>();
        anyhow::bail!("{} proofs are missing requested job_ids {:?}", source, missing);
    }
    Ok(attached)
}

fn require_checkpoint_id(checkpoint_id: Option<u64>, source: &str) -> Result<u64> {
    checkpoint_id.with_context(|| format!("{} has no checkpoint id", source))
}

pub async fn build_realm_proofs(
    provider: &RpcProvider,
    job_ids: Vec<(u64, u64, QProvingJobDataIDWithRewardPreimage)>,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_realm_and_unique_pending_id: HashMap<(u64, u64), Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, (realm_id, unique_pending_id, job)| {
            map.entry((realm_id, unique_pending_id)).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id: HashMap<
        u64,
        Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>,
    > = HashMap::new();

    for ((realm_id, unique_pending_id), job_id_with_preimages) in job_ids_with_realm_and_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let preimages = index_reward_preimages(job_id_with_preimages)?;

        let checkpoint_id = require_checkpoint_id(
            provider
                .get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(*realm_id, *unique_pending_id)
                .await?,
            &format!("realm {} unique_pending_id {}", realm_id, unique_pending_id),
        )?;
        let proofs = provider
            .generate_realm_batch_proof_miner_reward_proofs_by_realm_id(*realm_id, *unique_pending_id, job_ids)
            .await?;


        total_proofs += proofs.len();
        tracing::info!(
            "Including realm {} unique_pending_id {} checkpoint {} jobs={} proofs={}",
            realm_id,
            unique_pending_id,
            checkpoint_id,
            job_id_with_preimages.len(),
            proofs.len()
        );

        let proof_with_reward_preimages = attach_reward_preimages(proofs, &preimages, "realm")?;
        proofs_with_unique_pending_id
            .entry(checkpoint_id)
            .or_default()
            .extend(proof_with_reward_preimages);
    }
    tracing::info!("Total realm proofs: {}", total_proofs);

    Ok(proofs_with_unique_pending_id)
}

pub async fn build_proofs(
    provider: &RpcProvider,
    job_ids: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
    node_type: u8,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_unique_pending_id: HashMap<u64, Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, (unique_pending_id, job)| {
            map.entry(unique_pending_id).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id: HashMap<
        u64,
        Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>,
    > = HashMap::new();

    for (unique_pending_id, job_id_with_preimages) in job_ids_with_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let preimages = index_reward_preimages(job_id_with_preimages)?;

        let (checkpoint_id, proofs) = if node_type == 1 {
            let checkpoint_id = require_checkpoint_id(
                provider.get_realm_checkpoint_id_for_unique_pending_id(*unique_pending_id).await?,
                &format!("realm unique_pending_id {}", unique_pending_id),
            )?;
            let proofs = provider
                .generate_realm_batch_proof_miner_reward_proofs(*unique_pending_id, job_ids)
                .await?;
            (checkpoint_id, proofs)
        } else {
            let checkpoint_id = require_checkpoint_id(
                provider
                    .get_coordinator_checkpoint_id_for_unique_pending_id(*unique_pending_id)
                    .await?,
                &format!("coordinator unique_pending_id {}", unique_pending_id),
            )?;
            let proofs = provider
                .generate_coordinator_batch_proof_miner_reward_proofs(*unique_pending_id, job_ids)
                .await?;
            (checkpoint_id, proofs)
        };


        total_proofs += proofs.len();
        tracing::info!(
            "Including coordinator unique_pending_id {} checkpoint {} jobs={} proofs={}",
            unique_pending_id,
            checkpoint_id,
            job_id_with_preimages.len(),
            proofs.len()
        );

        let proof_with_reward_preimages = attach_reward_preimages(proofs, &preimages, "coordinator")?;
        proofs_with_unique_pending_id
            .entry(checkpoint_id)
            .or_default()
            .extend(proof_with_reward_preimages);
    }
    tracing::info!("Total proofs: {}", total_proofs);

    Ok(proofs_with_unique_pending_id)
}


fn load_job_ids_from_file(path: &str) -> Result<ClaimRewardJobsWithRealm> {
    let buffer = std::fs::read(path)?;
    let mut claim_jobs = ClaimRewardJobsWithRealm::new_empty();

    if buffer.is_empty() {
        tracing::info!("Backup file is empty");
        return Ok(claim_jobs);
    }

    let record_size = PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::record_size();
    anyhow::ensure!(
        buffer.len() % record_size == 0,
        "jobs backup length {} is not a multiple of record size {}",
        buffer.len(),
        record_size
    );

    for (record_index, record_data) in buffer.chunks_exact(record_size).enumerate() {
        let offset = record_index * record_size;
        let metadata = PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::psy_ser_from_slice(record_data)
            .with_context(|| format!("failed to parse jobs backup record at offset {}", offset))?;
        let job = QProvingJobDataIDWithRewardPreimage::new(
            metadata.job_id,
            metadata.reward_tree_node_key.index,
            metadata.reward_tree_tag_preimage,
        );
        if metadata.node_type == 1 {
            claim_jobs.realm_jobs.push((metadata.realm_id, metadata.unique_pending_id, job));
        } else {
            claim_jobs.coordinator_jobs.push((metadata.unique_pending_id, job));
        }
    }

    Ok(claim_jobs)
}


#[cfg(test)]
mod tests {
    use super::*;
    use psy_client_common::job::id::{
        ProvingJobCircuitType, ProvingJobDataType, QJobTopic,
    };

    fn job(task_index: u32, user_id: u64, marker: u64) -> QProvingJobDataIDWithRewardPreimage {
        QProvingJobDataIDWithRewardPreimage::new(
            QProvingJobDataID::new(
                QJobTopic::GenerateStandardProof,
                11,
                0,
                0,
                0,
                task_index,
                ProvingJobCircuitType::AppendUserRegistrationTree,
                ProvingJobDataType::InputWitness,
                0,
            ),
            marker,
            QHashOut::from_values(user_id, 0, marker, marker + 1),
        )
    }

    #[test]
    fn mismatched_preimage_user_is_rejected() {
        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, job(1, 8, 10))],
        };
        let error = validate_and_deduplicate_jobs(jobs, 7, "worker.backup").unwrap_err();
        assert!(error.to_string().contains("current wallet user_id is 7"));
    }

    #[test]
    fn identical_duplicates_are_deduplicated_but_conflicts_fail() {
        let first = job(1, 7, 10);
        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, first.clone()), (21, first)],
        };
        assert_eq!(validate_and_deduplicate_jobs(jobs, 7, "worker.backup").unwrap().jobs_len(), 1);

        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, job(1, 7, 10)), (22, job(1, 7, 11))],
        };
        assert!(validate_and_deduplicate_jobs(jobs, 7, "worker.backup")
            .unwrap_err()
            .to_string()
            .contains("conflicting duplicate job_id"));
    }

    #[test]
    fn proofs_are_matched_to_preimages_by_job_id_not_position() {
        let first = job(1, 7, 10);
        let second = job(2, 7, 20);
        let preimages = index_reward_preimages(&[first.clone(), second.clone()]).unwrap();
        let proofs = vec![
            PsyProoffMinerRewardProof {
                job_id: second.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
        ];
        let attached = attach_reward_preimages(proofs, &preimages, "test").unwrap();
        assert_eq!(attached[0].reward_tree_tag_preimage, second.reward_tree_tag_preimage);
        assert_eq!(attached[1].reward_tree_tag_preimage, first.reward_tree_tag_preimage);
    }

    #[test]
    fn proof_set_must_exactly_match_requested_jobs() {
        let first = job(1, 7, 10);
        let second = job(2, 7, 20);
        let preimages = index_reward_preimages(&[first.clone(), second.clone()]).unwrap();
        let missing = vec![PsyProoffMinerRewardProof {
            job_id: first.inner.job_data_id,
            tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
        }];
        assert!(attach_reward_preimages(missing, &preimages, "test")
            .unwrap_err()
            .to_string()
            .contains("missing requested job_ids"));

        let duplicate = vec![
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
        ];
        assert!(attach_reward_preimages(duplicate, &preimages, "test")
            .unwrap_err()
            .to_string()
            .contains("duplicate test proof"));
    }


    #[test]
    fn unavailable_checkpoint_is_fail_closed() {
        assert!(require_checkpoint_id(None, "coordinator unique_pending_id 11")
            .unwrap_err()
            .to_string()
            .contains("has no checkpoint id"));
    }

    #[test]
    fn malformed_backup_length_is_rejected() {
        let path = std::env::temp_dir().join(format!("claim-rewards-truncated-{}", std::process::id()));
        std::fs::write(&path, [0u8]).unwrap();
        let error = load_job_ids_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("not a multiple of record size"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn backup_preserves_unique_pending_id() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;

        let metadata = PsyProvingJobClaimMetadata {
            job_id: job(1, 7, 10).inner.job_data_id,
            reward_tree_tag: QHashOut::from_values(1, 2, 3, 4),
            reward_tree_tag_preimage: QHashOut::from_values(7, 0, 10, 11),
            proving_duration_ms: 1,
            job_submitted_at: 2,
            unique_pending_id: 987,
            realm_id: 3,
            realm_sub_id: 0,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 1, index: 10 },
            reward_tree_hash_mode: 0,
            reward_tree_node_children: 0,
            node_type: 1,
            api_url_hash: [0; 32],
        };
        let path = std::env::temp_dir().join(format!("claim-rewards-metadata-{}", std::process::id()));
        std::fs::write(&path, metadata.psy_ser_to_bytes().unwrap()).unwrap();
        let loaded = load_job_ids_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.realm_jobs[0].0, 3);
        assert_eq!(loaded.realm_jobs[0].1, 987);
        std::fs::remove_file(path).unwrap();
    }
}
