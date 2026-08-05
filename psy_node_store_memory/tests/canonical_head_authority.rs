use std::sync::Arc;

use parth_core::data::hash::hash256::Hash256;
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    NetworkId,
};
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    CanonicalHeadReadState, CanonicalHeadTransition,
    CanonicalHeadWriteOutcome, CoordinatorCanonicalHeadReader,
    CoordinatorCanonicalHeadStore,
};
use psy_node_store_memory::cbs_store::InMemoryCoreStore;

type Store = InMemoryCoreStore<Hash256, CoreSha256Hasher>;

fn hash(seed: u8) -> Hash256 {
    Hash256([seed; 32])
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(0x6979_7350).unwrap()
}

fn canonical_ref(checkpoint: u64, hash_seed: u8) -> CanonicalChainRef<Hash256> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(hash_seed)),
        ),
    )
}

fn genesis() -> CanonicalHeadBootstrap<Hash256> {
    CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        canonical_ref(0, 1),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bootstrap_has_one_applied_and_idempotent_retries() {
    let store = Arc::new(Store::new());
    let bootstrap = genesis();
    let tasks = (0..64).map(|_| {
        let store = Arc::clone(&store);
        tokio::spawn(async move { store.bootstrap_canonical_head(&bootstrap).await.unwrap() })
    });

    let mut applied = 0;
    let mut idempotent = 0;
    for task in tasks {
        match task.await.unwrap() {
            CanonicalHeadWriteOutcome::Applied(_) => applied += 1,
            CanonicalHeadWriteOutcome::Idempotent(_) => idempotent += 1,
            CanonicalHeadWriteOutcome::Conflict { .. } => panic!("identical bootstrap conflicted"),
        }
    }

    assert_eq!(applied, 1);
    assert_eq!(idempotent, 63);
    assert_eq!(
        store.read_canonical_head(network()).await.unwrap(),
        CanonicalHeadReadState::Current(*bootstrap.candidate())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_cas_has_one_winner_and_revision_blocks_stale_retry() {
    let store = Arc::new(Store::new());
    let bootstrap = genesis();
    assert!(store
        .bootstrap_canonical_head(&bootstrap)
        .await
        .unwrap()
        .was_applied());

    let tasks = (2_u8..66).map(|hash_seed| {
        let store = Arc::clone(&store);
        let sealed = CanonicalHeadTransition::normal_checkpoint_advance(
            *bootstrap.candidate(),
            canonical_ref(1, hash_seed),
        )
        .unwrap()
        .seal();
        tokio::spawn(async move {
            let outcome = store
                .compare_and_set_canonical_head(&sealed)
                .await
                .unwrap();
            (sealed, outcome)
        })
    });

    let mut applied = Vec::new();
    let mut conflicts = 0;
    for task in tasks {
        let (sealed, outcome) = task.await.unwrap();
        match outcome {
            CanonicalHeadWriteOutcome::Applied(_) => applied.push(sealed),
            CanonicalHeadWriteOutcome::Conflict { .. } => conflicts += 1,
            CanonicalHeadWriteOutcome::Idempotent(_) => {
                panic!("distinct candidates cannot be idempotent")
            }
        }
    }

    assert_eq!(applied.len(), 1);
    assert_eq!(conflicts, 63);
    let winner = applied[0];
    assert_eq!(
        store.read_canonical_head(network()).await.unwrap(),
        CanonicalHeadReadState::Current(*winner.candidate())
    );

    let stale_candidate = canonical_ref(1, 99);
    let stale = CanonicalHeadTransition::normal_checkpoint_advance(
        *bootstrap.candidate(),
        stale_candidate,
    )
    .unwrap()
    .seal();
    assert!(matches!(
        store.compare_and_set_canonical_head(&stale).await.unwrap(),
        CanonicalHeadWriteOutcome::Conflict { current }
            if current == *winner.candidate()
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_authority_reads_only_observe_complete_published_identities() {
    let store = Arc::new(Store::new());
    let bootstrap = genesis();
    store.bootstrap_canonical_head(&bootstrap).await.unwrap();

    let writer_store = Arc::clone(&store);
    let writer = tokio::spawn(async move {
        let mut expected = *bootstrap.candidate();
        for checkpoint in 1_u8..=64 {
            let sealed = CanonicalHeadTransition::normal_checkpoint_advance(
                expected,
                canonical_ref(u64::from(checkpoint), checkpoint),
            )
            .unwrap()
            .seal();
            let outcome = writer_store
                .compare_and_set_canonical_head(&sealed)
                .await
                .unwrap();
            expected = match outcome {
                CanonicalHeadWriteOutcome::Applied(current) => current,
                other => panic!("single writer must advance: {other:?}"),
            };
            tokio::task::yield_now().await;
        }
    });

    let readers = (0..32).map(|_| {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            for _ in 0..128 {
                let CanonicalHeadReadState::Current(current) =
                    store.read_canonical_head(network()).await.unwrap()
                else {
                    panic!("bootstrapped authority cannot become uninitialized");
                };
                let wire = current.canonical_ref().to_canonical_bytes();
                let decoded: CanonicalChainRef<Hash256> =
                    CanonicalChainRef::from_canonical_bytes(&wire).unwrap();
                let checkpoint = decoded.checkpoint().checkpoint_id().get();
                assert_eq!(decoded.network_id(), network());
                assert_eq!(decoded.chain_epoch().get(), 0);
                let expected_hash_seed = if checkpoint == 0 {
                    1
                } else {
                    checkpoint as u8
                };
                assert_eq!(
                    decoded.checkpoint().checkpoint_hash().as_inner(),
                    &hash(expected_hash_seed),
                    "a reader must not combine a height from one publish with a hash from another"
                );
                tokio::task::yield_now().await;
            }
        })
    });

    for reader in readers {
        reader.await.unwrap();
    }
    writer.await.unwrap();
}
