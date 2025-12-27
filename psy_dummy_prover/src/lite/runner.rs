use std::{sync::Arc, time::Duration};

use cf_utils::timer::TraceTimer;
use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use tokio::time::sleep;

use crate::{api::combo_dummy_fetcher::PsyDummyProverComboFetcher, lite::chain_state::DPUserSimulationChainState, traits::DummyUPSProver};

pub async fn run_dummy_prover_lite<
    Hasher: FieldQHasher<F, Hash>,
    DF: PsyDummyProverComboFetcher<F, Hash> + Send + Sync + 'static,
    Prover: DummyUPSProver<F, Hash> + Send + Sync,
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
>(
    data_fetcher: Arc<DF>,
    prover: &Prover,
    start_user_id: u64,
    end_user_id: u64,
    min_state_updates_per_call: u32,
    max_state_updates_per_call: u32,
    max_contract_calls_per_uop: u32,
    global_contract_tree_height: u8,
    coordinator_global_user_tree_height: u8,
    realm_global_user_tree_height: u8,
    group_realm_height: u8,
    mut run_count: usize,
) -> anyhow::Result<()> {
    let mut timer = TraceTimer::new("dp_lite");
    let total_users = end_user_id - start_user_id;
    let total_users_usize = total_users as usize;
    let mut chain = DPUserSimulationChainState::<Hasher, Hash, F, DF>::new_populate_first_100_contract_ids(
        (start_user_id..end_user_id).collect::<Vec<_>>(),
        global_contract_tree_height,
        coordinator_global_user_tree_height,
        realm_global_user_tree_height,
        group_realm_height,
        min_state_updates_per_call,
        max_state_updates_per_call,
        max_contract_calls_per_uop,
        data_fetcher.clone(),
    )
    .await?;
let global_user_tree_height = coordinator_global_user_tree_height + realm_global_user_tree_height;
    timer.lap("create simulation chain state");
    chain.init_first().await?;
    timer.lap_batch("init_first", "user", total_users as usize);

    sleep(Duration::from_millis(2000)).await;
    timer.lap("cooldown after init");

    run_count = if run_count == 0 { usize::MAX } else { run_count };
    const BATCH_SUBMIT_SIZE: usize = 64;

    for i in 0..run_count {
        timer.event(format!("started batch #{i} of {total_users} users, waiting for next checkpoint id"));
        let mut current_checkpoint_id = data_fetcher.df_get_latest_checkpoint().await?;
        if current_checkpoint_id <= chain.checkpoint_id {
            println!(
                "waiting for checkpoint id {}, current is {}",
                chain.checkpoint_id + 1,
                current_checkpoint_id
            );
        }
        while current_checkpoint_id <= chain.checkpoint_id {
            sleep(Duration::from_millis(500)).await;
            current_checkpoint_id = data_fetcher.df_get_latest_checkpoint().await?;
        }
        timer.event(format!("detected new checkpoint id {}, preparing user end inputs", current_checkpoint_id));
        let end_cap_inputs = chain.prepare_end_cap_inputs(total_users_usize).await?;
        timer.lap_batch("prepared end cap inputsfor users", "user", total_users_usize);
        let proofs = end_cap_inputs
            .iter()
            .map(|input| prover.prove_end_cap_dummy_ups(global_user_tree_height, input))
            .collect::<anyhow::Result<Vec<_>>>()?;
        timer.lap_batch("generated end cap proofs for users", "user", total_users_usize);

        let mut current_chunk = Vec::with_capacity(BATCH_SUBMIT_SIZE);

        for (i, (ec, p)) in end_cap_inputs.into_iter().zip(proofs.into_iter()).enumerate() {
            current_chunk.push(data_fetcher.df_submit_end_cap_proof(ec, p));
            if current_chunk.len() == BATCH_SUBMIT_SIZE || i == total_users_usize - 1 {
                let submit_futs = current_chunk.drain(..).collect::<Vec<_>>();
                futures::future::try_join_all(submit_futs).await?;
            }
        }
        timer.lap_batch("submitted end cap proofs for users", "user", total_users_usize);
        println!(
            "completed batch #{i} of end cap proofs for users {} to {}, sleeping for 2 seconds",
            start_user_id, end_user_id
        );
        sleep(Duration::from_millis(2000)).await;
    }

    Ok(())
}
