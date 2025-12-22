use std::sync::Arc;

use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::user_id::get_user_registration_id_from_user_id;
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    v1::qdata::contract::{DashMapContractHeightCache, PSimpleContractHeightCache},
};
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};

use crate::{
    api::combo_dummy_fetcher::PsyDummyProverComboFetcher,
    lite::user_state::{DPContractUpdate, DPLocalUser},
};

pub struct DPUserSimulationChainState<Hasher, Hash: Copy + PartialEq + Default, F, DF: PsyDummyProverComboFetcher<F, Hash> + Send + Sync + 'static> {
    pub checkpoint_id: u64,
    pub checkpoint_root: Hash,
    pub user_ids: Vec<u64>,
    pub users: Vec<DPLocalUser<Hasher, Hash, F>>,
    pub global_contract_tree_height: u8,
    pub coordinator_global_user_tree_height: u8,
    pub realm_global_user_tree_height: u8,
    pub group_realm_height: u8,
    pub global_user_tree_height: u8,
    pub min_state_updates_per_call: u32,
    pub max_state_updates_per_call: u32,
    pub max_contract_calls_per_uop: u32,
    pub contract_height_cache: DashMapContractHeightCache<Hash>,
    pub allowed_contracts: Vec<u32>,
    pub data_fetcher: Arc<DF>,
}

impl<
        Hasher: FieldQHasher<F, Hash>,
        Hash: Q256BitHash + QFHashBase<F>,
        F: QFelt64,
        DF: PsyDummyProverComboFetcher<F, Hash> + Send + Sync + 'static,
    > DPUserSimulationChainState<Hasher, Hash, F, DF>
{
    pub async fn new_populate_first_100_contract_ids(
        user_ids: Vec<u64>,
        global_contract_tree_height: u8,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
        min_state_updates_per_call: u32,
        max_state_updates_per_call: u32,
        max_contract_calls_per_uop: u32,
        data_fetcher: Arc<DF>,
    ) -> anyhow::Result<Self> {
        let contract_height_cache = DashMapContractHeightCache::new();
        let contract_ids: Vec<u64> = (0..100).collect();
        let heights = data_fetcher.df_get_contract_state_heights(u64::MAX, contract_ids.clone()).await?;
        if heights.contains(&0) {
            anyhow::bail!("Some contract heights are zero, cannot proceed");
        }
        for (contract_id, height) in contract_ids.iter().zip(heights.iter()) {
            contract_height_cache.add_contract(*contract_id as u32, *height, Hasher::get_zero_hash(*height as usize));
        }

        Ok(Self::new(
            user_ids,
            global_contract_tree_height,
            coordinator_global_user_tree_height,
            realm_global_user_tree_height,
            group_realm_height,
            min_state_updates_per_call,
            max_state_updates_per_call,
            max_contract_calls_per_uop,
            data_fetcher,
            contract_height_cache,
        ))
    }
    pub fn new(
        user_ids: Vec<u64>,
        global_contract_tree_height: u8,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
        min_state_updates_per_call: u32,
        max_state_updates_per_call: u32,
        max_contract_calls_per_uop: u32,
        data_fetcher: Arc<DF>,
        contract_height_cache: DashMapContractHeightCache<Hash>,
    ) -> Self {
        let allowed_contracts = contract_height_cache.mapping.iter().map(|dm| *dm.key()).collect();
        Self {
            global_user_tree_height: coordinator_global_user_tree_height + realm_global_user_tree_height,
            coordinator_global_user_tree_height,
            realm_global_user_tree_height,
            group_realm_height,
            checkpoint_id: 0,
            checkpoint_root: Hash::default(),
            users: user_ids
                .iter()
                .map(|&user_id| DPLocalUser::new_empty(user_id, global_contract_tree_height))
                .collect(),
            global_contract_tree_height,
            contract_height_cache,
            data_fetcher,
            user_ids,
            min_state_updates_per_call,
            max_state_updates_per_call,
            max_contract_calls_per_uop,
            allowed_contracts,
        }
    }
    pub fn total_users(&self) -> usize {
        self.users.len()
    }
    pub async fn init_first(&mut self) -> anyhow::Result<()> {
        println!("Initializing first checkpoint data for {} users", self.users.len());
        let latest_checkpoint = self.data_fetcher.df_get_latest_checkpoint().await?;
        self.checkpoint_id = latest_checkpoint;
        println!("fetched latest checkpoint id: {}", latest_checkpoint);
        let checkpoint_root = self.data_fetcher.df_get_checkpoint_tree_merkle_proof(self.checkpoint_id).await?.root;

        println!("fetched checkpoint root from remote: {:?}", checkpoint_root);
        self.checkpoint_root = checkpoint_root;

        println!("Fetching user leaves from remote for {} users", self.user_ids.len());
        let mut user_leaves = self
            .data_fetcher
            .df_get_user_leaves_batch(self.checkpoint_id, self.user_ids.clone())
            .await?;
        let user_registration_ids = self
            .user_ids
            .iter()
            .map(|&uid| {
                get_user_registration_id_from_user_id(
                    uid,
                    self.coordinator_global_user_tree_height,
                    self.realm_global_user_tree_height,
                    self.group_realm_height,
                )
            })
            .collect::<Vec<_>>();
        let public_key_hashes = self.data_fetcher.cf_get_user_public_key_hashes(&user_registration_ids).await?;
        let hash_zero_value = Hash::get_zero_value();
        for (i, (leaf, pk_hash)) in user_leaves.iter_mut().zip(public_key_hashes.iter()).enumerate() {
            if pk_hash == &hash_zero_value{
                anyhow::bail!("user {} (user registration id {}) has not been registered and has a zero public key hash, cannot proceed", i, user_registration_ids[i]);
            }
            leaf.public_key = *pk_hash;

        }
        println!("fetched all user leaves from remote");
        let chunk_size = 16;
        let data_fetcher = self.data_fetcher.clone();
        let checkpoint_id = self.checkpoint_id;
        for (chunk_index, chunk) in user_leaves.chunks(chunk_size).enumerate() {
            let start_index = chunk_index * chunk_size;
            let end_index = start_index + chunk.len();
            let futs = self.users[start_index..end_index]
                .iter_mut()
                .zip(chunk.iter())
                .map(|(local_user, remote_leaf)| {
                    local_user.sync_to_latest(data_fetcher.clone(), &self.contract_height_cache, checkpoint_id, *remote_leaf)
                });

            futures::future::try_join_all(futs).await?;
        }
        Ok(())
    }
    pub fn get_random_contract_updates(&self) -> Vec<DPContractUpdate<Hash>> {
        let mut rng = rand::thread_rng();
        let num_contract_calls = rng.gen_range(1..=self.max_contract_calls_per_uop);
        let mut updates = Vec::new();

        for _ in 0..num_contract_calls {
            let contract_id = *self.allowed_contracts.choose(&mut rng).unwrap();
            let num_updates = rng.gen_range(self.min_state_updates_per_call..=self.max_state_updates_per_call);

            let mut dp_update = DPContractUpdate {
                contract_id: contract_id as u32,
                leaves: Vec::with_capacity(num_updates as usize),
            };
            for _ in 0..num_updates {
                let slot_index = rng.gen_range(0..(1u64 << self.contract_height_cache.get_contract_height(contract_id).unwrap_or(0) as u64));
                let value = Hash::rand_hash();
                dp_update.leaves.push((slot_index, value));
            }
            updates.push(dp_update);
        }

        updates
    }
    pub async fn prepare_end_cap_inputs(&mut self, count: usize) -> anyhow::Result<Vec<SubmitUserEndCapNonProofInput<F, Hash>>> {
        if count > self.users.len() {
            return Err(anyhow::anyhow!("Requested count {} exceeds number of users {}", count, self.users.len()));
        }
        let inds = if count == self.users.len() {
            (0..self.users.len()).collect()
        } else {
            (0..self.users.len()).choose_multiple(&mut rand::thread_rng(), count)
        };
        let mut inputs = Vec::with_capacity(count);
        let latest_checkpoint_id = self.data_fetcher.df_get_latest_checkpoint().await?;
        self.checkpoint_id = latest_checkpoint_id;
        let checkpoint_root = self.data_fetcher.df_get_checkpoint_tree_merkle_proof(self.checkpoint_id).await?.root;
        self.checkpoint_root = checkpoint_root;

        for &ind in inds.iter() {
            let contract_updates = self.get_random_contract_updates();
            let input = self.users[ind].run_ups(&self.contract_height_cache, latest_checkpoint_id, checkpoint_root, &contract_updates)?;
            inputs.push(input);
        }

        Ok(inputs)
    }
}
