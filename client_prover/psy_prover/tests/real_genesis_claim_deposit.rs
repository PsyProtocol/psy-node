//! Real production token CFC acceptance, NOT checkpoint/UPS/EndCap acceptance.
//! Inputs are hash-pinned public Genesis files. No RPC, signing keys, or disk writes.
//! State is a synthetic in-memory checkpoint with a known deposit root. Contract
//! CBOR is used unmodified; the new artifact's canonical layout is authenticated.
#![cfg(not(target_arch = "wasm32"))]

use std::{fs::File, io::{BufReader, Seek, SeekFrom}, process::{Command, Stdio}};
use anyhow::{ensure, Context};
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::{field::{goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash as H, plonk::config::PoseidonGoldilocksConfig as C};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    privacy::deposit_inclusion::DepositInclusionInput,
    qblock::cmds::deploy_contract::{QBCDeployContract, get_code_root_by_code_hashes},
    qdata::{checkpoint::PsyCheckpointLeaf, contract::PsyContractLeaf,
        imt_contract_state::IMTContractStateLeaf, user::PsyUserLeaf},
    qstore::{controllers::proving_session::PsyLocalProvingSessionStore,
        imm::{cache::PsyCmdStoreWithCache, cmd::{QSRIMTCmdGetLeafIndexForKey, QSRIMTCmdGetLeafPreimage}}},
    traits::qdatastore::{qmetadata::{QMetaDataStoreReaderSync, QMetaDataStoreWriterSync},
        qtreedata::{QTreeDataStoreReaderSync, QTreeDataStoreWriterSync}},
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::network_constants::{CONTRACT_FUNCTION_TREE_HEIGHT, GLOBAL_DEPOSIT_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
use psy_crypto::hash::{merkle::utils::simple_merkle_tree::SimpleMerkleTree,
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable}};
use psy_data::v1::qdata::contract::CanonicalLayoutManifest;
use psy_dpn_circuit::circuits::{cfc::DapenContractFunctionCircuit, privacy::deposit_inclusion::DepositInclusionCircuit};
use psy_vm::{dpn::{contract::{cfc_code_definition_to_dapen_fc, hash_dpn_function},
        ops::op_types::DPNOpType, vm::def::DPNFunctionCircuitDefinition},
    vm::{cfc_input::DapenContractFunctionCircuitInput, exec::PsyEvalSessionResult}};
use serde::Deserialize;

type Hash = QHashOut<F>;
type Tree = SimpleMerkleTree<H, Hash>;
type Session = PsyLocalProvingSessionStore<F, KVQSimpleMemoryBackingStore, H>;
const CHECKPOINT: u64 = 33;
const USER: u64 = 2;
const RELAYER: u64 = 524288;
const TOKEN: u64 = 4;
const DEPOSIT_CONTRACT: u64 = 2;
const AMOUNT: u64 = 1_000_000;
const BALANCE: u64 = 2_000_000;
const CAPACITY: u64 = 1_048_576;

#[derive(Deserialize)]
struct PublicContracts {
    // Serde skips users and all other Genesis fields without retaining them.
    contracts: Vec<serde_json::Value>,
}

fn public_contracts(path_var: &str, hash_var: &str) -> anyhow::Result<PublicContracts> {
    let path = std::env::var(path_var).with_context(|| format!("missing {path_var}"))?;
    let expected = std::env::var(hash_var).with_context(|| format!("missing {hash_var}"))?;
    ensure!(expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()), "invalid public SHA256");
    let mut file = File::open(&path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= 1024 * 1024 * 1024, "expected public Genesis <= 1 GiB");
    // Hash the same open file descriptor subsequently decoded; never echo content.
    let hash = Command::new("sha256sum").stdin(Stdio::from(file.try_clone()?)).output()?;
    ensure!(hash.status.success(), "sha256sum failed");
    let actual = String::from_utf8(hash.stdout)?;
    ensure!(actual.split_whitespace().next() == Some(expected.to_ascii_lowercase().as_str()), "public Genesis hash mismatch");
    file.seek(SeekFrom::Start(0))?;
    let result: PublicContracts = serde_json::from_reader(BufReader::new(file))?;
    ensure!(result.contracts.len() == 6, "expected six production contracts");
    println!("public fixture {path_var}: sha256={expected}, bytes={}", metadata.len());
    Ok(result)
}

fn deploy(contracts: &PublicContracts, id: u64) -> anyhow::Result<QBCDeployContract<F>> {
    Ok(serde_json::from_value(contracts.contracts[id as usize].clone())?)
}

fn layout(contracts: &PublicContracts, id: u64) -> anyhow::Result<CanonicalLayoutManifest<parth_core::PHash>> {
    let layout: CanonicalLayoutManifest<parth_core::PHash> =
        serde_json::from_value(contracts.contracts[id as usize]["state_layout"].clone())?;
    layout.validate::<parth_core::pgoldilocks::PoseidonHasher, parth_core::PF>()?;
    ensure!(u16::from(layout.state_tree_height) == deploy(contracts, id)?.code_definition.state_tree_height,
        "layout/contract height mismatch");
    Ok(layout)
}

fn method(deploy: &QBCDeployContract<F>) -> anyhow::Result<(usize, DPNFunctionCircuitDefinition)> {
    let definitions = deploy.code_definition.functions.iter()
        .map(cfc_code_definition_to_dapen_fc).collect::<anyhow::Result<Vec<_>>>()?;
    let hashes = definitions.iter().map(hash_dpn_function::<F>).collect::<Vec<_>>();
    ensure!(get_code_root_by_code_hashes::<F, H>(&hashes, CONTRACT_FUNCTION_TREE_HEIGHT - 1) == deploy.code_root,
        "production code root differs from decoded CBOR");
    ensure!(deploy.function_whitelist.len() == definitions.len() * 2, "whitelist shape");
    let (index, definition) = definitions.into_iter().enumerate().find(|(_, d)| d.name == "claim_deposit")
        .context("production claim_deposit missing")?;
    ensure!(definition.method_id == 1577908089 && definition.circuit_inputs.len() == 105,
        "unexpected production claim ABI");
    Ok((index, definition))
}

fn field(v: u64) -> F { F::from_canonical_u64(v) }

fn words(hash: Hash, big_endian_pairs: bool) -> Vec<F> {
    hash.0.elements.into_iter().flat_map(|x| {
        let x = x.to_canonical_u64();
        let pair = [field(x & 0xffff_ffff), field(x >> 32)];
        if big_endian_pairs { [pair[1], pair[0]] } else { pair }
    }).collect()
}

fn deposit_input() -> DepositInclusionInput<F> {
    let nullifier_secret = [field(71), field(72), field(73), field(74)];
    let note_secret = [field(81), field(82), field(83), field(84)];
    let shield_address = H::q_hash_many(&[field(USER), field(1337), field(7), field(8)]);
    let note_commitment = H::q_hash_many(&[nullifier_secret, note_secret].concat());
    let token_address = [0, 0, 0, 0, 0, 0, 0, 1234];
    let l2_token_contract_id = [0, 0, 0, 0, 0, 0, 0, TOKEN as u32];
    let amount = [0, 0, 0, 0, 0, 0, 0, AMOUNT as u32];
    let mut preimage = words(shield_address, true);
    for array in [token_address, l2_token_contract_id, amount] {
        preimage.extend(array.into_iter().map(F::from_canonical_u32));
    }
    preimage.push(field(1));
    preimage.extend(words(note_commitment, true));
    let mut tree = Tree::new(GLOBAL_DEPOSIT_TREE_HEIGHT);
    tree.set_leaf(0, H::q_hash_many(&preimage));
    DepositInclusionInput {
        nullifier_secret, note_secret, shield_address, deposit_index: 0,
        token_address, l2_token_contract_id, amount, source_chain_index: 1,
        deposit_root: tree.get_root(), deposit_proof: tree.get_leaf(0),
    }
}

fn claim_inputs(input: &DepositInclusionInput<F>, proof_tree: &Tree) -> Vec<F> {
    let mut values = H::q_hash_many(&input.nullifier_secret).0.elements.to_vec();
    values.extend(input.shield_address.0.elements);
    values.extend(input.token_address.into_iter().map(F::from_canonical_u32));
    values.extend(input.amount.into_iter().map(F::from_canonical_u32));
    values.push(field(u64::from(input.source_chain_index)));
    // Contract deposit_root is internal low/high pairs, unlike the L1 leaf encoding.
    values.extend(words(input.deposit_root, false));
    values.extend(H::q_hash_many(&[input.nullifier_secret, input.note_secret].concat()).0.elements);
    values.extend([field(input.deposit_index), field(7), field(8)]);
    for sibling in proof_tree.get_leaf(0).siblings { values.extend(sibling.0.elements); }
    values.push(F::ZERO);
    assert_eq!(values.len(), 105);
    values
}

async fn session(
    token: &QBCDeployContract<F>, deposit: &QBCDeployContract<F>,
    token_layout: &CanonicalLayoutManifest<parth_core::PHash>,
    deposit_layout: &CanonicalLayoutManifest<parth_core::PHash>,
    input: &DepositInclusionInput<F>, proof_root: Hash,
) -> anyhow::Result<Session> {
    let store = KVQSimpleMemoryBackingStore::new();
    for (id, artifact, layout) in [(TOKEN, token, token_layout), (DEPOSIT_CONTRACT, deposit, deposit_layout)] {
        let committed = &layout.layout.contract_layout;
        let root = store.set_contract_function_whitelist(CHECKPOINT, id, &artifact.function_whitelist)?;
        let leaf = PsyContractLeaf {
            deployer: field(artifact.deployer), function_tree_root: root, code_root: artifact.code_root,
            state_tree_height: field(u64::from(artifact.code_definition.state_tree_height)),
            state_layout_root: serde_json::from_value(serde_json::to_value(committed.state_layout_root)?)?,
            state_layout_field_count: field(committed.state_layout_field_count),
            state_layout_slot_count: field(committed.state_layout_slot_count),
        };
        store.set_contract_leaf_data(CHECKPOINT, id, &leaf)?;
        store.set_contract_code_definition(CHECKPOINT, id, &artifact.code_definition)?;
        store.set_contract_tree_leaf_hash(CHECKPOINT, id, leaf.qfhash::<H>())?;
    }
    let token_height = u8::try_from(token.code_definition.state_tree_height)?;
    let deposit_height = u8::try_from(deposit.code_definition.state_tree_height)?;
    let balance_root = store.set_user_state_tree_leaf_hash(CHECKPOINT, USER, TOKEN as u32,
        token_height, 0, Hash::from_values(BALANCE, 0, 0, 0))?.new_root;
    store.set_user_contract_tree_leaf_hash(CHECKPOINT, USER, TOKEN as u32, balance_root)?;

    // Production known_roots field (field 8), with a genuine membership proof
    // rooted in the synthetic bridge user's state. No mocked 'known=true'.
    let known = deposit_layout.layout.contract_layout.fields.get(7).context("known_roots layout missing")?;
    ensure!(known.field_id == 8 && known.slot_count == CAPACITY * 4, "known_roots layout changed");
    let base = (known.start_slot + known.payload_offset).div_ceil(4);
    let root_key = H::q_hash_many(&words(input.deposit_root, false));
    let mut namespaced = vec![field(u64::from(input.source_chain_index))];
    namespaced.extend(root_key.0.elements);
    let key = H::q_hash_many(&namespaced);
    let membership = IMTContractStateLeaf::new(key, Hash::from_values(1, 0, 0, 0), Hash::ZERO, F::ZERO);
    let sentinel = IMTContractStateLeaf::new(Hash::ZERO, Hash::ZERO, key, field(base + 1));
    store.set_user_state_tree_leaf_hash(CHECKPOINT, RELAYER, DEPOSIT_CONTRACT as u32,
        deposit_height, base, sentinel.qfhash::<H>())?;
    let known_root = store.set_user_state_tree_leaf_hash(CHECKPOINT, RELAYER, DEPOSIT_CONTRACT as u32,
        deposit_height, base + 1, membership.qfhash::<H>())?.new_root;
    store.set_user_contract_tree_leaf_hash(CHECKPOINT, RELAYER, DEPOSIT_CONTRACT as u32, known_root)?;
    for user in [USER, RELAYER] {
        let leaf = PsyUserLeaf {
            public_key: Hash::from_values(user, 2, 3, 4),
            user_state_tree_root: store.get_user_contract_tree_root(CHECKPOINT, user).await?,
            balance: F::ZERO, nonce: F::ZERO, last_checkpoint_id: field(CHECKPOINT),
            event_index: F::ZERO, user_id: field(user),
        };
        store.set_user_leaf_data(CHECKPOINT, &leaf)?;
        store.set_user_tree_leaf_hash(CHECKPOINT, user, leaf.qfhash::<H>())?;
    }
    let mut checkpoint = PsyCheckpointLeaf::<F>::default();
    checkpoint.global_chain_root = store.get_checkpoint_global_state_roots(CHECKPOINT).await?.qfhash::<H>();
    store.set_checkpoint_leaf_data(CHECKPOINT, &checkpoint)?;
    store.set_checkpoint_tree_leaf_hash(CHECKPOINT, checkpoint.qfhash::<H>())?;
    let mut commands = PsyCmdStoreWithCache::new(CHECKPOINT, store);
    commands.cache.imt_index_cache.insert(QSRIMTCmdGetLeafIndexForKey {
        checkpoint_id: CHECKPOINT, user_id: RELAYER, contract_id: DEPOSIT_CONTRACT as u32,
        key: key.0.elements.map(|v| v.to_canonical_u64()), state_slot_base: base, capacity: CAPACITY,
    }, base + 1);
    commands.cache.imt_leaf_preimage_cache.insert(QSRIMTCmdGetLeafPreimage {
        checkpoint_id: CHECKPOINT, user_id: RELAYER, contract_id: DEPOSIT_CONTRACT as u32, leaf_index: base + 1,
    }, membership);
    let mut session = Session::new_at_with_cmd_store(commands, field(CHECKPOINT), field(USER),
        F::ONE, F::ZERO, UPS_SESSION_PROOF_TREE_HEIGHT as usize);
    session.set_proof_tree_root(proof_root);
    Ok(session)
}

#[tokio::test]
#[ignore = "requires an explicitly hash-pinned public Genesis; no proof generation"]
async fn real_token4_claim_rejects_high_amount_words_without_claim_witness() -> anyhow::Result<()> {
    let contracts = public_contracts("PSY_CLAIM_GENESIS", "PSY_CLAIM_GENESIS_SHA256")?;
    let token = deploy(&contracts, TOKEN)?;
    let deposit = deploy(&contracts, DEPOSIT_CONTRACT)?;
    let token_layout = layout(&contracts, TOKEN)?;
    let deposit_layout = layout(&contracts, DEPOSIT_CONTRACT)?;
    let (_, definition) = method(&token)?;
    let proof_tree = Tree::new(UPS_SESSION_PROOF_TREE_HEIGHT);
    for word in 0..6 {
        let mut input = deposit_input();
        input.amount[word] = 1;
        let args = claim_inputs(&input, &proof_tree);
        let mut state = session(&token, &deposit, &token_layout, &deposit_layout, &input, proof_tree.get_root()).await?;
        let before = state.get_contract_state_slot(field(TOKEN), F::ZERO).await?;
        ensure!(before.value.0.elements[0] == field(BALANCE), "fixture balance differs: {:?}", before.value);
        let error = PsyEvalSessionResult::new().exec_contract_call(&mut state, field(TOKEN), &definition, args)
            .await.err().context("token accepted a high amount word")?;
        ensure!(error.to_string().contains("amount exceeds uint64 range"),
            "high amount word was rejected for an unrelated reason: {error}");
        // VM assertions run after speculative writes. Discard the failed session;
        // only its immutable checkpoint store is evidence of committed balance.
        let balance = state.get_read_store().get_user_contract_state_tree_merkle_proof(
            CHECKPOINT, USER, TOKEN as u32, u8::try_from(token.code_definition.state_tree_height)?, 0,
        ).await?;
        ensure!(balance.value == before.value && balance.root == before.root,
            "failed claim changed checkpoint balance");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "expensive real Plonky2 proof; requires explicitly hash-pinned public new/old Genesis"]
async fn real_token4_claim_deposit_new_passes_old_fingerprint_fails() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_NETWORK").as_deref() == Ok("testnet"), "set PSY_NETWORK=testnet at build and execution");
    ensure!(psy_config::PSY_NETWORK_MAGIC == 0x1337CF514544CF69, "wrong compiled network magic");
    let new = public_contracts("PSY_CLAIM_GENESIS", "PSY_CLAIM_GENESIS_SHA256")?;
    let old = public_contracts("PSY_CLAIM_OLD_GENESIS", "PSY_CLAIM_OLD_GENESIS_SHA256")?;
    let token = deploy(&new, TOKEN)?;
    let old_token = deploy(&old, TOKEN)?;
    let deposit = deploy(&new, DEPOSIT_CONTRACT)?;
    let token_layout = layout(&new, TOKEN)?;
    let deposit_layout = layout(&new, DEPOSIT_CONTRACT)?;
    let (function_index, definition) = method(&token)?;
    let (_, old_definition) = method(&old_token)?;
    ensure!(definition != old_definition, "negative artifact must differ");
    for limb in [12102704748894912577, 2605816805097074474, 270858441303242900, 1525812673267139438] {
        ensure!(old_definition.definitions.iter().any(|d| d.op_type == DPNOpType::Constant && d.inputs == vec![limb]),
            "negative artifact does not contain the retained stale fingerprint");
    }
    ensure!(token.code_definition.state_tree_height == old_token.code_definition.state_tree_height,
        "negative fixture height differs");

    let input = deposit_input();
    let inclusion = DepositInclusionCircuit::<C, 2>::new();
    for limb in inclusion.get_fingerprint().0.elements.map(|v| v.to_canonical_u64()) {
        ensure!(definition.definitions.iter().any(|d| d.op_type == DPNOpType::Constant && d.inputs == vec![limb]),
            "new artifact does not contain the measured inclusion fingerprint");
    }
    let proof = inclusion.prove(&input).context("real deposit inclusion proving")?;
    inclusion.minifier_chain.verify(proof.clone()).context("real deposit inclusion verification")?;
    ensure!(proof.public_inputs.len() == 4, "unexpected inclusion PI shape");
    let pi = Hash::from_values(proof.public_inputs[0].to_canonical_u64(), proof.public_inputs[1].to_canonical_u64(),
        proof.public_inputs[2].to_canonical_u64(), proof.public_inputs[3].to_canonical_u64());
    let mut tampered_proof = proof.clone();
    tampered_proof.public_inputs[0] += F::ONE;
    ensure!(inclusion.minifier_chain.verify(tampered_proof).is_err(), "tampered inclusion PI accepted");
    let mut proof_tree = Tree::new(UPS_SESSION_PROOF_TREE_HEIGHT);
    proof_tree.set_leaf(0, H::q_two_to_one(inclusion.get_fingerprint(), pi));
    println!("real deposit inclusion proof verified; tampered PI rejected");
    drop(inclusion);
    let args = claim_inputs(&input, &proof_tree);

    // Same real proof, real old CBOR, and identical synthetic state. Reusing
    // the validated new layout here isolates old bytecode, not old layout support.
    let mut stale = session(&old_token, &deposit, &token_layout, &deposit_layout, &input, proof_tree.get_root()).await?;
    let error = PsyEvalSessionResult::new().exec_contract_call(&mut stale, field(TOKEN), &old_definition, args.clone())
        .await.err().context("old artifact unexpectedly accepted real proof")?;
    ensure!(error.to_string().contains("assertion failed: proof tree root mismatch"),
        "negative control failed for another reason: {error}");
    println!("old artifact: EXPECTED proof tree root mismatch");
    drop(stale);

    let mut fresh = session(&token, &deposit, &token_layout, &deposit_layout, &input, proof_tree.get_root()).await?;
    let witness: DapenContractFunctionCircuitInput<F> = PsyEvalSessionResult::new()
        .exec_contract_call(&mut fresh, field(TOKEN), &definition, args).await.context("real new claim VM")?;
    ensure!(witness.events.len() == 1 && witness.events[0].data.len() == 15, "missing production deposit event");
    ensure!(witness.events[0].data[8] == field(AMOUNT), "deposit event amount differs");
    let balance = fresh.get_contract_state_slot(field(TOKEN), F::ZERO).await?;
    ensure!(balance.value.0.elements[0] == field(BALANCE + AMOUNT), "claim did not credit token balance");
    println!("new production claim VM passed; balance/event checked; constructing CFC");
    let cfc = DapenContractFunctionCircuit::<C, 2>::new(&definition,
        usize::from(token.code_definition.state_tree_height), UPS_SESSION_PROOF_TREE_HEIGHT as usize, false);
    ensure!(cfc.get_fingerprint() == token.function_whitelist[function_index * 2],
        "rebuilt claim CFC differs from Genesis whitelist");
    let claim_proof = cfc.prove_base(&witness).context("production claim CFC proving")?;
    cfc.minifier_chain.verify(claim_proof).context("production claim CFC verification")?;
    let mut tampered_witness = witness;
    tampered_witness.session_proof_tree_root.0.elements[0] += F::ONE;
    ensure!(cfc.prove_base(&tampered_witness).is_err(), "CFC accepted altered session proof root");
    println!("PASS token4: real deposit proof + full production claim VM/CFC verified; old artifact and tampered inputs rejected");
    println!("BOUNDARY: synthetic checkpoint/state; no UPS, EndCap, fee, Guardian, Faucet, private_claim, or chain inclusion acceptance");
    Ok(())
}
