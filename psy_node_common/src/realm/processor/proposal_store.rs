//! Disk-backed Proposal objects.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use psy_data::p2p::{
    BodyChunkRequest, BodyChunkResponse, Proposal, ProposalLookupEntry, ProposalLookupRequest,
    ProposalLookupResponse, ProtocolEncode, BODY_CHUNK_MAX_BYTES, MAX_PROPOSAL_BODY_BYTES,
    PROPOSAL_WIRE_BYTES,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem, TokioStdFileSystem};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::realm::processor::consensus::decode_proposal_body;

const STATE_UPDATES_ROOTS_OFFSET: usize = 40;
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RealmTransition {
    pub from_root: [u8; 32],
    pub to_root: [u8; 32],
}

struct TransitionRecord<T> {
    body_file: T,
    body_len_bytes: u64,
    body_hash: [u8; 32],
    proposal: Proposal,
}

/// Owns one staged body file. Dropping it removes the staging file through the
/// store's filesystem abstraction, so an abandoned candidate cannot leak.
pub struct StagedProposal {
    path: String,
    transition: RealmTransition,
    proposal_id: [u8; 32],
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for StagedProposal {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

/// In-memory tables over the retained bodies, guarded by the store's single
/// lock: records keyed by transition plus the O(1) proposal-id lookup index.
struct RetainedBodies<T> {
    by_transition: HashMap<RealmTransition, TransitionRecord<T>>,
    by_proposal_id: HashMap<[u8; 32], RealmTransition>,
}

pub struct ProposalStore<F: TokioLikeFileSystem = TokioStdFileSystem> {
    fs: std::sync::Arc<F>,
    root: PathBuf,
    inner: tokio::sync::Mutex<RetainedBodies<F::File>>,
    staged_seq: AtomicU64,
    instance_id: u64,
}

impl ProposalStore<TokioStdFileSystem> {
    pub async fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_fs(root, TokioStdFileSystem).await
    }
}

impl<F: TokioLikeFileSystem + 'static> ProposalStore<F> {
    pub async fn open_with_fs(root: impl AsRef<Path>, fs: F) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs.file_like_fs_create_dir_all(&path_string(&root.join("bodies"))).await?;
        let root = if root.is_absolute() { root } else { std::env::current_dir()?.join(root) };
        let store = Self {
            fs: std::sync::Arc::new(fs),
            root,
            inner: tokio::sync::Mutex::new(RetainedBodies {
                by_transition: HashMap::new(),
                by_proposal_id: HashMap::new(),
            }),
            staged_seq: AtomicU64::new(1),
            instance_id: std::hash::RandomState::new().build_hasher().finish(),
        };
        remove_staged_files(&store.root.join("bodies")).await?;
        {
            let mut inner = store.inner.lock().await;
            for transition in store.read_stored_transitions().await? {
                let _ = store.load_transition_record(&mut inner, &transition).await;
            }
        }
        Ok(store)
    }

    // Trusted local consensus/replay writes bypass fetched-body isolation staging verification.
    pub async fn save_proposal(&self, proposal: &Proposal, body: &[u8]) -> anyhow::Result<()> {
        let staged = self.create_staged(proposal, body).await?;
        self.install(staged).await
    }

    pub async fn create_staged(&self, proposal: &Proposal, body: &[u8]) -> anyhow::Result<StagedProposal> {
        let transition = verify_complete_object(proposal, body)?;
        let path = self.write_staging_file(&encode_object(proposal, body)).await?;
        let cleanup_fs = self.fs.clone();
        let cleanup_path = path.clone();
        let handle = tokio::runtime::Handle::current();
        Ok(StagedProposal {
            path,
            transition,
            proposal_id: proposal.proposal_id,
            cleanup: Some(Box::new(move || {
                let _ = handle.spawn(async move {
                    if let Err(error) = cleanup_fs.file_like_remove_file(&cleanup_path).await {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            tracing::debug!("staged body cleanup failed error={error}");
                        }
                    }
                });
            })),
        })
    }

    pub async fn read_staged(&self, staged: &StagedProposal) -> anyhow::Result<(Proposal, Vec<u8>)> {
        let bytes = self.read_object_file(&staged.path).await?;
        let object = decode_verified_object(&bytes, &staged.transition)?;
        anyhow::ensure!(object.0.proposal_id == staged.proposal_id, "staged identity mismatch");
        Ok(object)
    }

    pub async fn lookup_proposal(&self, request: &ProposalLookupRequest) -> anyhow::Result<ProposalLookupResponse> {
        let mut entries = Vec::new();
        let mut wire_bytes = 5;
        for pair in &request.pairs {
            let candidates = self.lookup_transition(&pair.old_root, &pair.new_root).await?
                .into_iter().filter(|proposal| proposal.chain_id == request.chain_id && proposal.realm_id == request.realm_id).collect::<Vec<_>>();
            wire_bytes += 65 + candidates.len() * PROPOSAL_WIRE_BYTES;
            if wire_bytes > psy_data::p2p::MAX_PROPOSAL_LOOKUP_RESPONSE_BYTES {
                return Ok(ProposalLookupResponse::truncated(entries));
            }
            entries.push(ProposalLookupEntry { transition: *pair, candidates });
        }
        Ok(ProposalLookupResponse::candidates(entries))
    }

    /// The store retains one body per transition, so this yields zero or one
    /// proposal even though the wire answer carries room for two candidates.
    /// Cache hits skip disk reads; later on-disk corruption surfaces only on
    /// the verified load paths (load_proposal / read_body_chunk I/O).
    pub async fn lookup_transition(&self, old_root: &[u8; 32], new_root: &[u8; 32]) -> anyhow::Result<Vec<Proposal>> {
        {
            let inner = self.inner.lock().await;
            if let Some(record) = inner
                .by_transition
                .get(&RealmTransition { from_root: *old_root, to_root: *new_root })
            {
                return Ok(vec![record.proposal.clone()]);
            }
        }
        match self.load_proposal(old_root, new_root).await {
            Ok(Some((proposal, _))) => Ok(vec![proposal]),
            Ok(None) => Ok(Vec::new()),
            Err(_) => Ok(Vec::new()),
        }
    }

    pub async fn load_proposal(&self, old_root: &[u8; 32], new_root: &[u8; 32]) -> anyhow::Result<Option<(Proposal, Vec<u8>)>> {
        let mut inner = self.inner.lock().await;
        match self
            .load_transition_record(&mut inner, &RealmTransition { from_root: *old_root, to_root: *new_root })
            .await
        {
            Ok(object) => Ok(Some(object)),
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn read_body_chunk(&self, request: &BodyChunkRequest) -> anyhow::Result<BodyChunkResponse> {
        anyhow::ensure!(request.max_bytes > 0 && request.max_bytes <= BODY_CHUNK_MAX_BYTES, "range size outside bounds");
        let mut inner = self.inner.lock().await;
        let transition = *inner
            .by_proposal_id
            .get(&request.proposal_id)
            .context("proposal is missing")?;
        let state = inner
            .by_transition
            .get_mut(&transition)
            .context("proposal is missing")?;
        let (body_len, body_hash) = (state.body_len_bytes, state.body_hash);
        let file = &mut state.body_file;
        anyhow::ensure!(request.offset <= body_len, "range offset past body length");
        let take = (body_len - request.offset).min(request.max_bytes as u64) as usize;
        let start = (PROPOSAL_WIRE_BYTES as u64).checked_add(request.offset).context("range seek overflow")?;
        let mut data = vec![0; take];
        let result = async {
            file.seek(std::io::SeekFrom::Start(start)).await?;
            file.read_exact(&mut data).await?;
            Ok::<_, std::io::Error>(())
        }.await;
        if let Err(error) = result {
            self.remove_transition(&mut inner, &transition).await;
            return Err(error.into());
        }
        Ok(BodyChunkResponse { offset: request.offset, eof: request.offset + take as u64 == body_len, data, body_len, body_hash })
    }

    async fn load_transition_record(
        &self,
        inner: &mut RetainedBodies<F::File>,
        transition: &RealmTransition,
    ) -> anyhow::Result<(Proposal, Vec<u8>)> {
        let result = async {
            let mut file = self.fs.file_like_fs_open(&self.transition_path(transition)).await?;
            let mut bytes = Vec::new();
            (&mut file).take((PROPOSAL_WIRE_BYTES + MAX_PROPOSAL_BODY_BYTES + 1) as u64).read_to_end(&mut bytes).await?;
            let (proposal, body) = decode_verified_object(&bytes, transition)?;
            if let Some(state) = inner.by_transition.get(transition) {
                anyhow::ensure!(
                    state.proposal.proposal_id == proposal.proposal_id,
                    "proposal identity mismatch"
                );
            }
            let proposal_id = proposal.proposal_id;
            inner.by_proposal_id.insert(proposal_id, *transition);
            inner.by_transition.insert(*transition, TransitionRecord {
                body_file: file,
                body_len_bytes: body.len() as u64,
                body_hash: proposal.body_hash,
                proposal: proposal.clone(),
            });
            Ok((proposal, body))
        }.await;
        if result.is_err() {
            self.remove_transition(inner, transition).await;
        }
        result
    }

    /// A transition whose bytes do not verify is dropped entirely: the pair goes
    /// back to absent so an honest body can be staged and installed again.
    async fn remove_transition(&self, inner: &mut RetainedBodies<F::File>, transition: &RealmTransition) {
        if let Some(record) = inner.by_transition.remove(transition) {
            inner.by_proposal_id.remove(&record.proposal.proposal_id);
        }
        let path = self.transition_path(transition);
        if let Err(error) = self.fs.file_like_remove_file(&path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    "failed to remove unverified transition pair=({},{}) error={error}",
                    hex::encode(transition.from_root),
                    hex::encode(transition.to_root)
                );
            }
        }
    }

    /// Verifies the staged bytes and installs them as the pair's retained body.
    pub async fn install(&self, staged: StagedProposal) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let mut file = self.fs.file_like_fs_open(&staged.path).await?;
        let mut bytes = Vec::new();
        (&mut file).take((PROPOSAL_WIRE_BYTES + MAX_PROPOSAL_BODY_BYTES + 1) as u64).read_to_end(&mut bytes).await?;
        anyhow::ensure!(bytes.len() >= PROPOSAL_WIRE_BYTES, "short proposal header");
        let proposal = Proposal::decode_exact(&bytes[..PROPOSAL_WIRE_BYTES]).map_err(|error| anyhow::anyhow!("proposal header: {error}"))?;
        let body = &bytes[PROPOSAL_WIRE_BYTES..];
        anyhow::ensure!(
            verify_complete_object(&proposal, body)? == staged.transition,
            "proposal transition mismatch"
        );
        anyhow::ensure!(proposal.proposal_id == staged.proposal_id, "staged identity mismatch");
        let path = self.transition_path(&staged.transition);
        self.fs.file_like_rename(&staged.path, &path).await?;
        let proposal_id = proposal.proposal_id;
        let previous = inner.by_transition.insert(staged.transition, TransitionRecord {
            body_file: file,
            body_len_bytes: body.len() as u64,
            body_hash: proposal.body_hash,
            proposal,
        });
        if let Some(previous) = previous {
            if previous.proposal.proposal_id != proposal_id {
                inner.by_proposal_id.remove(&previous.proposal.proposal_id);
            }
        }
        inner.by_proposal_id.insert(proposal_id, staged.transition);
        self.fs.file_like_fs_sync_parent_dir(&path).await?;
        Ok(())
    }

    async fn read_stored_transitions(&self) -> anyhow::Result<Vec<RealmTransition>> {
        let mut transitions = Vec::new();
        let mut dir = tokio::fs::read_dir(self.root.join("bodies")).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let Some(transition) = parse_transition_file_name(&entry.file_name().to_string_lossy()) {
                transitions.push(transition);
            }
        }
        transitions.sort_unstable();
        Ok(transitions)
    }

    async fn write_staging_file(&self, bytes: &[u8]) -> anyhow::Result<String> {
        let tmp = path_string(&self.root.join("bodies").join(format!(
            ".tmp-{}-{}",
            self.instance_id,
            self.staged_seq.fetch_add(1, Ordering::Relaxed)
        )));
        let result = async {
            let mut file = self.fs.file_like_fs_create(&tmp).await?;
            file.write_all(bytes).await?;
            file.file_like_set_len(bytes.len() as u64).await?;
            self.fs.file_like_fs_flush_file_with_path(&tmp, &mut file).await?;
            self.fs.file_like_fs_sync_file_with_path(&tmp, &mut file).await?;
            Ok::<_, anyhow::Error>(())
        }.await;
        if result.is_err() {
            let _ = self.fs.file_like_remove_file(&tmp).await;
        }
        result.map(|_| tmp)
    }

    async fn read_object_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let file = self.fs.file_like_fs_open(path).await?;
        let mut bytes = Vec::new();
        file.take((PROPOSAL_WIRE_BYTES + MAX_PROPOSAL_BODY_BYTES + 1) as u64).read_to_end(&mut bytes).await?;
        Ok(bytes)
    }

    fn transition_path(&self, transition: &RealmTransition) -> String {
        path_string(&self.root.join("bodies").join(format!(
            "{}_{}",
            hex::encode(transition.from_root),
            hex::encode(transition.to_root)
        )))
    }
}

fn path_string(path: &Path) -> String { path.to_string_lossy().into_owned() }

fn encode_object(proposal: &Proposal, body: &[u8]) -> Vec<u8> {
    let mut bytes = proposal.protocol_encode_to_vec();
    bytes.extend_from_slice(body);
    bytes
}

fn decode_verified_object(bytes: &[u8], transition: &RealmTransition) -> anyhow::Result<(Proposal, Vec<u8>)> {
    anyhow::ensure!(bytes.len() >= PROPOSAL_WIRE_BYTES, "short proposal header");
    let proposal = Proposal::decode_exact(&bytes[..PROPOSAL_WIRE_BYTES]).map_err(|error| anyhow::anyhow!("proposal header: {error}"))?;
    let body = &bytes[PROPOSAL_WIRE_BYTES..];
    anyhow::ensure!(
        verify_complete_object(&proposal, body)? == *transition,
        "proposal transition mismatch"
    );
    Ok((proposal, body.to_vec()))
}

fn verify_complete_object(proposal: &Proposal, body: &[u8]) -> anyhow::Result<RealmTransition> {
    anyhow::ensure!(body.len() <= MAX_PROPOSAL_BODY_BYTES, "proposal body exceeds length limit");
    anyhow::ensure!(proposal.compute_proposal_id() == proposal.proposal_id, "proposal identity mismatch");
    let decoded = decode_proposal_body(proposal, body).map_err(|error| anyhow::anyhow!("proposal body: {error}"))?;
    realm_roots_from_state_updates(&decoded.state_updates)
}

fn realm_roots_from_state_updates(state_updates: &[u8]) -> anyhow::Result<RealmTransition> {
    anyhow::ensure!(state_updates.len() >= STATE_UPDATES_ROOTS_OFFSET + 64, "state_updates missing old/new realm roots");
    let mut old_root = [0; 32];
    let mut new_root = [0; 32];
    old_root.copy_from_slice(&state_updates[STATE_UPDATES_ROOTS_OFFSET..STATE_UPDATES_ROOTS_OFFSET + 32]);
    new_root.copy_from_slice(&state_updates[STATE_UPDATES_ROOTS_OFFSET + 32..STATE_UPDATES_ROOTS_OFFSET + 64]);
    Ok(RealmTransition { from_root: old_root, to_root: new_root })
}

async fn remove_staged_files(dir: &Path) -> anyhow::Result<()> {
    let mut dir = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = dir.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        if parse_transition_file_name(&entry.file_name().to_string_lossy()).is_none() {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

fn parse_transition_file_name(name: &str) -> Option<RealmTransition> {
    let (from, to) = name.split_once('_')?;
    let mut transition = RealmTransition { from_root: [0; 32], to_root: [0; 32] };
    if hex::decode_to_slice(from, &mut transition.from_root).is_ok()
        && hex::decode_to_slice(to, &mut transition.to_root).is_ok()
    {
        Some(transition)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::p2p::{encode_proposal_body, proposal_from_parts, sha256, MAX_FINALIZER_OUTPUT_BYTES};

    fn sample_object(salt: u8) -> (Proposal, Vec<u8>) {
        let output = vec![salt; MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xAB; 32];
        let mut updates = vec![0; STATE_UPDATES_ROOTS_OFFSET + 64 + 20];
        updates[40..72].fill(1);
        updates[72..104].fill(2);
        let body = encode_proposal_body(&output, &proof, &updates, &[0x11; 32]).unwrap();
        let proposal = proposal_from_parts(1, 0, 99, 1, [salt; 32], sha256(&output), sha256(&proof), sha256(&updates), sha256(&body));
        (proposal, body)
    }

    #[tokio::test]
    async fn transition_record_round_trip_and_read_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let (proposal, body) = sample_object(1);
        let store = ProposalStore::open(dir.path()).await.unwrap();
        store.save_proposal(&proposal, &body).await.unwrap();
        drop(store);
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let loaded = store.load_proposal(&[1; 32], &[2; 32]).await.unwrap().unwrap();
        assert_eq!(loaded.0.proposal_id, proposal.proposal_id);
        assert_eq!(loaded.1, body);
        let mut request = BodyChunkRequest { proposal_id: proposal.proposal_id, offset: 0, max_bytes: 64 };
        assert_eq!(store.read_body_chunk(&request).await.unwrap().data, body[..64]);
        let path = store.transition_path(&RealmTransition { from_root: [1; 32], to_root: [2; 32] });
        let moved = dir.path().join("cached-object");
        tokio::fs::rename(&path, &moved).await.unwrap();
        request.offset = 64;
        let second = store.read_body_chunk(&request).await.unwrap();
        assert_eq!(second.data, body[64..128]);
        assert_eq!(second.body_hash, proposal.body_hash);
        assert_eq!(second.body_len, body.len() as u64);
        tokio::fs::rename(&moved, &path).await.unwrap();
        request.offset = body.len() as u64;
        let end = store.read_body_chunk(&request).await.unwrap();
        assert!(end.eof);
        assert!(end.data.is_empty());
        request.offset += 1;
        assert!(store.read_body_chunk(&request).await.is_err());
        request.offset = 0;
        request.max_bytes = 0;
        assert!(store.read_body_chunk(&request).await.is_err());
        request.max_bytes = BODY_CHUNK_MAX_BYTES + 1;
        assert!(store.read_body_chunk(&request).await.is_err());
    }

    #[tokio::test]
    async fn staging_order_and_slot_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (first, first_body) = sample_object(1);
        let (second, second_body) = sample_object(2);
        let first_stage = store.create_staged(&first, &first_body).await.unwrap();
        let second_stage = store.create_staged(&second, &second_body).await.unwrap();
        assert!(store.load_proposal(&[1; 32], &[2; 32]).await.unwrap().is_none());
        assert!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap().is_empty());
        assert_eq!(store.read_staged(&second_stage).await.unwrap().1, second_body);
        store.install(second_stage).await.unwrap();
        assert_eq!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap(), vec![second.clone()]);
        assert_eq!(store.read_staged(&first_stage).await.unwrap().1, first_body);
        store.install(first_stage).await.unwrap();
        assert_eq!(store.load_proposal(&[1; 32], &[2; 32]).await.unwrap().unwrap().0.proposal_id, first.proposal_id);
        assert_eq!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap(), vec![first.clone()]);
        let replaced = BodyChunkRequest { proposal_id: second.proposal_id, offset: 0, max_bytes: 64 };
        assert!(store.read_body_chunk(&replaced).await.is_err());
        store.save_proposal(&second, &second_body).await.unwrap();
        assert_eq!(store.read_body_chunk(&replaced).await.unwrap().data, second_body[..64]);
        store.save_proposal(&first, &first_body).await.unwrap();
        assert_eq!(store.load_proposal(&[1; 32], &[2; 32]).await.unwrap().unwrap().1, first_body);
    }

    #[tokio::test]
    async fn damaged_transition_is_dropped_and_reinstallable() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (proposal, body) = sample_object(1);
        store.save_proposal(&proposal, &body).await.unwrap();
        let path = store.transition_path(&RealmTransition { from_root: [1; 32], to_root: [2; 32] });
        let mut corrupted = encode_object(&proposal, &body);
        *corrupted.last_mut().unwrap() ^= 1;
        tokio::fs::write(&path, corrupted).await.unwrap();
        let request = BodyChunkRequest { proposal_id: proposal.proposal_id, offset: 0, max_bytes: 64 };
        // Cache hit: the installed header is served without touching disk.
        assert_eq!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap(), vec![proposal.clone()]);
        // The verified load is the corruption discovery point: the damaged body
        // is dropped (record + file) so the pair returns to absent.
        assert!(store.load_proposal(&[1; 32], &[2; 32]).await.is_err());
        assert!(!path_exists(&path).await);
        assert!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap().is_empty());
        assert!(store.read_body_chunk(&request).await.is_err());
        let stage = store.create_staged(&proposal, &body).await.unwrap();
        assert_eq!(store.read_staged(&stage).await.unwrap().1, body);
        store.install(stage).await.unwrap();
        assert_eq!(store.read_body_chunk(&request).await.unwrap().data, body[..64]);
        tokio::fs::write(&path, &[]).await.unwrap();
        assert!(store.read_body_chunk(&request).await.is_err());
        assert!(store.lookup_transition(&[1; 32], &[2; 32]).await.unwrap().is_empty());
        assert!(!path_exists(&path).await);
        store.save_proposal(&proposal, &body).await.unwrap();
        assert_eq!(store.read_body_chunk(&request).await.unwrap().data, body[..64]);
    }

    async fn path_exists(path: &str) -> bool {
        tokio::fs::metadata(path).await.is_ok()
    }
}
