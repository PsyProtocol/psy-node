//! Bounded in-memory proposal body reassembly.
//!
//! A `ReassemblyBook` tracks at most `max_in_flight` (default 2) concurrent
//! proposal reassemblies. Each `ProposalReassembly` buffers chunk bytes in
//! memory at their declared offset and tracks a `BTreeMap` of recovered
//! ranges plus the contiguous prefix. On completion the assembled body is
//! hashed with SHA-256 and checked against `Proposal::body_hash` before a
//! `VerifiedProposalBody` is handed out.
//!
//! Expired entries (default 1 800 s) are reported by `ReassemblyBook::expire`
//! so the driving loop can emit `ProposalExpired`. This slim port is
//! memory-backed (no tempfile / tokio-fs dependency); a future file-backed
//! variant can swap the storage without changing the public surface.

use crate::realm::network::NetworkError;
use psy_data::p2p::{sha256, Proposal, MAX_PROPOSAL_BODY_BYTES, MAX_PROPOSAL_PARTS};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct CompleteProposalBody {
    pub proposal: Proposal,
    pub body: VerifiedProposalBody,
}

/// An assembled proposal body whose SHA-256 commitment matched the Proposal.
#[derive(Clone, Debug)]
pub struct VerifiedProposalBody {
    storage: std::sync::Arc<VerifiedProposalBodyStorage>,
}

#[derive(Debug)]
struct VerifiedProposalBodyStorage {
    bytes: std::sync::Arc<[u8]>,
    hash: [u8; 32],
}

impl VerifiedProposalBody {
    pub fn len(&self) -> u64 {
        self.storage.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.storage.bytes.is_empty()
    }

    pub fn hash(&self) -> [u8; 32] {
        self.storage.hash
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.storage.bytes
    }

    pub fn read_range(&self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proposal body range overflow"))?;
        if end > self.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "proposal body range out of bounds"));
        }
        Ok(self.storage.bytes[offset as usize..end as usize].to_vec())
    }

    /// Durably persist the verified body to `destination` (blocking std::fs).
    pub fn persist_to(&self, destination: &Path) -> io::Result<()> {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, &*self.storage.bytes)?;
        if let Some(parent) = destination.parent() {
            if let Ok(file) = std::fs::File::open(parent) {
                let _ = file.sync_all();
            }
        }
        Ok(())
    }
}

/// One in-flight proposal reassembly.
#[derive(Debug)]
pub struct ProposalReassembly {
    proposal: Proposal,
    total_parts: u32,
    body_len: u64,
    ranges: BTreeMap<u64, u32>,
    contiguous: u64,
    body: Vec<u8>,
    created_at: Instant,
    last_request_at: Option<Instant>,
    direct_request_active: bool,
}

impl ProposalReassembly {
    pub fn new(
        proposal: Proposal,
        total_parts: u32,
        body_len: u64,
        now: Instant,
    ) -> Result<Self, NetworkError> {
        validate_start(total_parts, body_len)?;
        let body = vec![0u8; body_len as usize];
        Ok(Self {
            proposal,
            total_parts,
            body_len,
            ranges: BTreeMap::new(),
            contiguous: 0,
            body,
            created_at: now,
            last_request_at: None,
            direct_request_active: false,
        })
    }

    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }

    pub fn proposal_id(&self) -> [u8; 32] {
        self.proposal.proposal_id
    }

    pub fn total_parts(&self) -> u32 {
        self.total_parts
    }

    pub fn body_len(&self) -> u64 {
        self.body_len
    }

    pub fn contiguous(&self) -> u64 {
        self.contiguous
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    pub fn last_request_at(&self) -> Option<Instant> {
        self.last_request_at
    }
    pub fn direct_request_active(&self) -> bool {
        self.direct_request_active
    }

    pub fn set_direct_request_active(&mut self, active: bool, now: Instant) {
        self.direct_request_active = active;
        if active {
            self.last_request_at = Some(now);
        }
    }

    pub fn is_expired(&self, now: Instant, expiry: Duration) -> bool {
        now.duration_since(self.last_request_at.unwrap_or(self.created_at)) >= expiry
    }

    /// Insert a body chunk. Returns `Duplicate` for an already-recovered
    /// range and `Complete` when the contiguous prefix reaches `body_len`.
    pub fn insert_chunk(&mut self, offset: u64, data: &[u8], now: Instant) -> Result<InsertOutcome, NetworkError> {
        let length = data.len() as u32;
        if length == 0 {
            return Err(NetworkError::Reassembly("chunk data is empty".into()));
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| NetworkError::Reassembly("chunk offset+length overflow".into()))?;
        if end > self.body_len {
            return Err(NetworkError::Reassembly("chunk range exceeds body length".into()));
        }
        self.last_request_at = Some(now);
        if self.overlaps(offset, length) {
            return Ok(InsertOutcome::Duplicate);
        }
        self.body[offset as usize..end as usize].copy_from_slice(data);
        self.ranges.insert(offset, length);
        self.recompute_contiguous();
        if self.contiguous >= self.body_len {
            Ok(InsertOutcome::Complete)
        } else {
            Ok(InsertOutcome::Inserted)
        }
    }

    pub fn is_complete(&self) -> bool {
        self.contiguous >= self.body_len
    }

    /// Finalize and verify the assembled body. Consumes `self`.
    pub fn into_verified_body(self) -> Result<VerifiedProposalBody, NetworkError> {
        if !self.is_complete() {
            return Err(NetworkError::Reassembly("proposal body is not complete".into()));
        }
        let hash = sha256(&self.body);
        if hash != self.proposal.body_hash {
            return Err(NetworkError::Reassembly("proposal body hash mismatch".into()));
        }
        Ok(VerifiedProposalBody {
            storage: std::sync::Arc::new(VerifiedProposalBodyStorage {
                bytes: std::sync::Arc::from(self.body),
                hash,
            }),
        })
    }

    fn overlaps(&self, offset: u64, length: u32) -> bool {
        let end = offset + length as u64;
        for (&existing_offset, &existing_length) in self.ranges.range(..=offset) {
            if existing_offset + existing_length as u64 > offset {
                return true;
            }
        }
        // `offset..end` overlaps any range starting inside it.
        if let Some((&next_offset, _)) = self.ranges.range(offset..end).next() {
            if next_offset < end {
                return true;
            }
        }
        false
    }

    fn recompute_contiguous(&mut self) {
        let mut contiguous: u64 = 0;
        for (&offset, &length) in &self.ranges {
            if offset == contiguous {
                contiguous += length as u64;
            } else {
                break;
            }
        }
        self.contiguous = contiguous;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
    Complete,
}

/// Bounded book of concurrent proposal reassemblies.
#[derive(Debug)]
pub struct ReassemblyBook {
    entries: HashMap<[u8; 32], ProposalReassembly>,
    /// Tracks the newest reassembly per checkpoint for eviction ordering.
    insertion_order: Vec<[u8; 32]>,
    max_in_flight: usize,
    chunk_bytes: usize,
    expiry: Duration,
}

impl ReassemblyBook {
    pub fn new(max_in_flight: usize, chunk_bytes: usize, expiry: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: Vec::new(),
            max_in_flight,
            chunk_bytes,
            expiry,
        }
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    pub fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub fn expiry(&self) -> Duration {
        self.expiry
    }

    pub fn active_count(&self) -> usize {
        self.entries.len()
    }

    pub fn contains(&self, proposal_id: &[u8; 32]) -> bool {
        self.entries.contains_key(proposal_id)
    }

    pub fn get(&self, proposal_id: &[u8; 32]) -> Option<&ProposalReassembly> {
        self.entries.get(proposal_id)
    }

    pub fn get_mut(&mut self, proposal_id: &[u8; 32]) -> Option<&mut ProposalReassembly> {
        self.entries.get_mut(proposal_id)
    }

    pub fn proposal_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.insertion_order.iter().copied()
    }

    /// Begin a new reassembly. Returns `Duplicate` if one already exists for
    /// the proposal, or `Inserted` after evicting the oldest entry when the
    /// in-flight bound is reached.
    pub fn start(
        &mut self,
        proposal: Proposal,
        total_parts: u32,
        body_len: u64,
        now: Instant,
    ) -> Result<StartOutcome, NetworkError> {
        let proposal_id = proposal.proposal_id;
        if self.entries.contains_key(&proposal_id) {
            return Ok(StartOutcome::Duplicate);
        }
        if self.entries.len() >= self.max_in_flight {
            // Evict the oldest insertion. The driving loop is expected to
            // expire stale entries via `expire` before this point; reaching
            // the bound here means the book is genuinely full.
            if let Some(&oldest) = self.insertion_order.first() {
                self.entries.remove(&oldest);
                self.insertion_order.retain(|id| *id != oldest);
            }
        }
        let reassembly = ProposalReassembly::new(proposal, total_parts, body_len, now)?;
        self.entries.insert(proposal_id, reassembly);
        self.insertion_order.push(proposal_id);
        Ok(StartOutcome::Inserted)
    }

    /// Insert a chunk for an active reassembly. Returns `Complete` when the
    /// body becomes contiguous and verified-eligible.
    pub fn insert_chunk(
        &mut self,
        proposal_id: &[u8; 32],
        offset: u64,
        data: &[u8],
        now: Instant,
    ) -> Result<InsertOutcome, NetworkError> {
        if data.len() > self.chunk_bytes {
            return Err(NetworkError::Reassembly(format!(
                "chunk length {} exceeds reassembly chunk bound {}",
                data.len(),
                self.chunk_bytes
            )));
        }
        let reassembly = self
            .entries
            .get_mut(proposal_id)
            .ok_or_else(|| NetworkError::Reassembly("chunk for unknown proposal".into()))?;
        reassembly.insert_chunk(offset, data, now)
    }

    /// Finalize and verify a complete reassembly, removing it from the book.
    pub fn finalize(&mut self, proposal_id: &[u8; 32]) -> Result<CompleteProposalBody, NetworkError> {
        let reassembly = self
            .entries
            .remove(proposal_id)
            .ok_or_else(|| NetworkError::Reassembly("finalize for unknown proposal".into()))?;
        self.insertion_order.retain(|id| id != proposal_id);
        let proposal = reassembly.proposal.clone();
        let body = reassembly.into_verified_body()?;
        Ok(CompleteProposalBody { proposal, body })
    }

    /// Drop an in-flight reassembly without verifying.
    pub fn discard(&mut self, proposal_id: &[u8; 32]) {
        if self.entries.remove(proposal_id).is_some() {
            self.insertion_order.retain(|id| id != proposal_id);
        }
    }

    /// Expire stale reassemblies, returning their proposal IDs in
    /// insertion order.
    pub fn expire(&mut self, now: Instant) -> Vec<[u8; 32]> {
        let mut expired = Vec::new();
        for id in self.insertion_order.clone() {
            if let Some(reassembly) = self.entries.get(&id) {
                if reassembly.is_expired(now, self.expiry) {
                    expired.push(id);
                }
            }
        }
        for id in &expired {
            self.entries.remove(id);
        }
        self.insertion_order.retain(|id| !expired.contains(id));
        expired
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartOutcome {
    Inserted,
    Duplicate,
}

/// Validate a `ProposalPart::Start` declaration against protocol bounds.
pub fn validate_start(total_parts: u32, body_len: u64) -> Result<(), NetworkError> {
    if total_parts == 0 || total_parts > MAX_PROPOSAL_PARTS {
        return Err(NetworkError::Reassembly(format!(
            "total_parts {total_parts} outside 1..={MAX_PROPOSAL_PARTS}"
        )));
    }
    if body_len == 0 || body_len > MAX_PROPOSAL_BODY_BYTES as u64 {
        return Err(NetworkError::Reassembly(format!(
            "body_len {body_len} outside 1..={MAX_PROPOSAL_BODY_BYTES}"
        )));
    }
    Ok(())
}