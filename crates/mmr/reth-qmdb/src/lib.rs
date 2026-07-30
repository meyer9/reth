//! Minimal QMDB-style authenticated key-value store.
//!
//! Append-only operation log authenticated by an MMR ([`reth_mmr_db::PersistentMmr`]).
//! A RocksDB index maps keys to the latest active op location (Commonware `adb::any`
//! shape), with inactivity-floor compaction via [`Qmdb::compact`].

mod eth;
mod eip1186;

pub use eth::{account_key, apply_hashed_post_state, ops_from_hashed_post_state, storage_key};
pub use eip1186::{get_proof, try_get_proof, try_get_proof_at};

use reth_mmr::{
    digest_to_b256, mmr_append, mmr_root, Digest, Error as MmrError, MmrLocation, MmrProof,
};
use reth_mmr_db::{Error as MmrDbError, PersistentMmr};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use sha2::{Digest as Sha2Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, RwLock},
};
use thiserror::Error;
use alloy_primitives::B256;

static DEFAULT_QMDB_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

type HandleMap = HashMap<PathBuf, Arc<Mutex<Qmdb>>>;
static OPEN_HANDLES: OnceLock<Mutex<HandleMap>> = OnceLock::new();

fn open_handles() -> &'static Mutex<HandleMap> {
    OPEN_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Open (or reuse) the process-wide handle for `path`, then run `f`.
///
/// RocksDB only allows one open per directory; peeks and appends in the same
/// process must share a handle or they fail with lock errors.
pub fn with_qmdb<R>(
    path: impl AsRef<Path>,
    f: impl FnOnce(&mut Qmdb) -> Result<R, Error>,
) -> Result<R, Error> {
    let path = path.as_ref().to_path_buf();
    let handle = {
        let mut map = open_handles().lock().map_err(|_| {
            Error::Io(std::io::Error::other("qmdb handle map lock poisoned"))
        })?;
        if let Some(existing) = map.get(&path) {
            existing.clone()
        } else {
            let qmdb = Qmdb::open(&path)?;
            let handle = Arc::new(Mutex::new(qmdb));
            map.insert(path, handle.clone());
            handle
        }
    };
    let mut guard = handle.lock().map_err(|_| {
        Error::Io(std::io::Error::other("qmdb handle lock poisoned"))
    })?;
    f(&mut *guard)
}

/// Register the process-wide default QMDB path (used by RPC / speculative peeks).
pub fn register_default_path(path: impl Into<PathBuf>) {
    *DEFAULT_QMDB_PATH.write().expect("qmdb path lock") = Some(path.into());
}

/// Process-wide default QMDB path, if registered.
pub fn default_path() -> Option<PathBuf> {
    DEFAULT_QMDB_PATH.read().expect("qmdb path lock").clone()
}

const CF_INDEX: &str = "qmdb_index";
const CF_OPS: &str = "qmdb_ops";
const CF_META: &str = "qmdb_meta";
const META_FLOOR: &[u8] = b"inactivity_floor";

/// Operation kinds in the authenticated log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    /// Set key to value.
    Update = 1,
    /// Delete key (tombstone).
    Delete = 2,
}

/// A decoded log operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Upsert.
    Update {
        /// Key bytes.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Delete.
    Delete {
        /// Key bytes.
        key: Vec<u8>,
    },
}

impl Operation {
    /// Key this op applies to.
    pub fn key(&self) -> &[u8] {
        match self {
            Self::Update { key, .. } | Self::Delete { key } => key,
        }
    }

    /// Encode the operation for the MMR leaf / op log.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Update { key, value } => {
                let mut out = Vec::with_capacity(1 + 4 + key.len() + 4 + value.len());
                out.push(OpKind::Update as u8);
                out.extend_from_slice(&(key.len() as u32).to_be_bytes());
                out.extend_from_slice(key);
                out.extend_from_slice(&(value.len() as u32).to_be_bytes());
                out.extend_from_slice(value);
                out
            }
            Self::Delete { key } => {
                let mut out = Vec::with_capacity(1 + 4 + key.len());
                out.push(OpKind::Delete as u8);
                out.extend_from_slice(&(key.len() as u32).to_be_bytes());
                out.extend_from_slice(key);
                out
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Corrupt("empty op"));
        }
        let mut rest = &bytes[1..];
        match bytes[0] {
            x if x == OpKind::Update as u8 => {
                let key = read_len_pref(&mut rest)?;
                let value = read_len_pref(&mut rest)?;
                if !rest.is_empty() {
                    return Err(Error::Corrupt("trailing update bytes"));
                }
                Ok(Self::Update { key, value })
            }
            x if x == OpKind::Delete as u8 => {
                let key = read_len_pref(&mut rest)?;
                if !rest.is_empty() {
                    return Err(Error::Corrupt("trailing delete bytes"));
                }
                Ok(Self::Delete { key })
            }
            _ => Err(Error::Corrupt("unknown op kind")),
        }
    }
}

fn read_len_pref(buf: &mut &[u8]) -> Result<Vec<u8>, Error> {
    if buf.len() < 4 {
        return Err(Error::Corrupt("len prefix"));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err(Error::Corrupt("short payload"));
    }
    let out = buf[..len].to_vec();
    *buf = &buf[len..];
    Ok(out)
}

/// Authenticated inclusion of a key's current op.
#[derive(Debug, Clone)]
pub struct KeyProof {
    /// Leaf location of the active op.
    pub location: MmrLocation,
    /// Decoded op at that location.
    pub operation: Operation,
    /// MMR inclusion proof over the op encoding.
    pub proof: MmrProof,
    /// MMR root the proof commits to.
    pub root: Digest,
}

/// Errors from the QMDB store.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying MMR DB.
    #[error(transparent)]
    MmrDb(#[from] MmrDbError),
    /// Pure MMR logic.
    #[error(transparent)]
    Mmr(#[from] MmrError),
    /// RocksDB.
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    /// Corrupt data.
    #[error("corrupt qmdb: {0}")]
    Corrupt(&'static str),
    /// Key has no active value.
    #[error("key not found")]
    NotFound,
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// QMDB-style store: op log in MMR + key index in RocksDB.
pub struct Qmdb {
    path: PathBuf,
    mmr: PersistentMmr,
    index_db: DB,
    /// First location that may still be needed for current-state derivation.
    inactivity_floor: u64,
}

impl fmt::Debug for Qmdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Qmdb")
            .field("path", &self.path)
            .field("leaves", &self.mmr.leaves())
            .finish_non_exhaustive()
    }
}

impl Qmdb {
    /// Open or create under `path` (`mmr/` + `index/` subdirs).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;
        let mmr = PersistentMmr::open(path.join("mmr"))?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_OPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let index_db = DB::open_cf_descriptors(&opts, path.join("index"), cfs)?;
        let inactivity_floor = load_floor(&index_db)?;
        // Do not register a process-wide default here: in-process multi-node stacks
        // (e.g. base-devnet builder+client) each have their own datadir, and the last
        // open would steal peeks/RPC from the other node.

        Ok(Self { path, mmr, index_db, inactivity_floor })
    }

    /// Datadir for this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current inactivity floor (ops strictly before this may be compacted away).
    pub fn inactivity_floor(&self) -> MmrLocation {
        MmrLocation::new(self.inactivity_floor)
    }

    /// Oldest retained MMR leaf location (after prune).
    pub fn prune_loc(&self) -> MmrLocation {
        self.mmr.prune_loc()
    }

    /// Leaf / op count.
    pub fn len(&self) -> u64 {
        self.mmr.leaves()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current MMR root (no pyramid split).
    pub fn root(&self) -> Result<Digest, Error> {
        Ok(self.mmr.root(0)?)
    }

    /// Current root as [`B256`] (for `header.state_root`).
    pub fn root_b256(&self) -> Result<B256, Error> {
        Ok(digest_to_b256(&self.root()?))
    }

    /// Speculatively append `ops` onto a cloned MMR and return the resulting root (disk unchanged).
    pub fn peek_root_after_ops(
        &self,
        ops: impl IntoIterator<Item = Operation>,
    ) -> Result<Digest, Error> {
        let mut mmr = self.mmr.clone_mmr();
        let hasher = self.mmr.hasher().clone();
        for op in ops {
            let encoded = op.encode();
            mmr_append(&mut mmr, &hasher, &encoded)?;
        }
        Ok(mmr_root(&mmr, &hasher, 0)?)
    }

    /// [`peek_root_after_ops`] as [`B256`].
    pub fn peek_root_after_ops_b256(
        &self,
        ops: impl IntoIterator<Item = Operation>,
    ) -> Result<B256, Error> {
        Ok(digest_to_b256(&self.peek_root_after_ops(ops)?))
    }

    /// Speculative root after applying a hashed post-state (disk unchanged).
    pub fn peek_root_after_hashed_state(
        &self,
        state: &reth_trie_common::HashedPostState,
    ) -> Result<B256, Error> {
        let ops = eth::ops_from_hashed_post_state(state);
        Ok(digest_to_b256(&self.peek_root_after_ops(ops)?))
    }

    /// Speculative root after a sorted hashed post-state.
    pub fn peek_root_after_hashed_state_sorted(
        &self,
        sorted: &reth_trie_common::HashedPostStateSorted,
    ) -> Result<B256, Error> {
        let mut state = reth_trie_common::HashedPostState::default();
        state.extend_from_sorted(sorted);
        self.peek_root_after_hashed_state(&state)
    }

    /// Advance the inactivity floor by re-appending still-active ops in `[floor, floor+steps)`.
    ///
    /// Matches the Commonware `adb::any` compaction sketch: active ops are rewritten at the tip
    /// so older log prefixes become entirely inactive. Then prunes the MMR to the new floor and
    /// drops op payloads below the floor.
    pub fn compact(&mut self, steps: u64) -> Result<MmrLocation, Error> {
        if steps == 0 {
            return Ok(self.inactivity_floor());
        }
        let old_floor = self.inactivity_floor;
        let end = self.inactivity_floor.saturating_add(steps).min(self.len());
        let mut loc = self.inactivity_floor;
        while loc < end {
            let op = self.op_at(MmrLocation::new(loc))?;
            if self.latest_loc(op.key())? == Some(MmrLocation::new(loc)) {
                // Still active at this location — re-append so it moves to the tip.
                self.apply(op)?;
            }
            loc += 1;
        }
        self.inactivity_floor = end;
        self.persist_floor()?;
        self.prune_ops_below(old_floor, end)?;
        // MMR prune to the new inactivity floor (nodes below floor are inactive).
        self.mmr.prune(MmrLocation::new(end))?;
        Ok(self.inactivity_floor())
    }

    /// Drop authenticated op payloads in `[from, to)`.
    fn prune_ops_below(&self, from: u64, to: u64) -> Result<(), Error> {
        if from >= to {
            return Ok(());
        }
        let ops = self.index_db.cf_handle(CF_OPS).expect("ops");
        let mut batch = rocksdb::WriteBatch::default();
        for loc in from..to {
            batch.delete_cf(ops, loc.to_be_bytes());
        }
        self.index_db.write(batch)?;
        Ok(())
    }

    /// Apply an update; returns the new op location.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<MmrLocation, Error> {
        self.apply(Operation::Update { key: key.to_vec(), value: value.to_vec() })
    }

    /// Apply a delete; returns the new op location.
    pub fn delete(&mut self, key: &[u8]) -> Result<MmrLocation, Error> {
        self.apply(Operation::Delete { key: key.to_vec() })
    }

    /// Latest active value for `key`, if any.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.latest_op(key)? {
            Some(Operation::Update { value, .. }) => Ok(Some(value)),
            Some(Operation::Delete { .. }) | None => Ok(None),
        }
    }

    /// Prove the current active op for `key` (update or delete).
    pub fn prove_key(&self, key: &[u8]) -> Result<KeyProof, Error> {
        let loc = self.latest_loc(key)?.ok_or(Error::NotFound)?;
        let operation = self.op_at(loc)?;
        let encoded = operation.encode();
        let root = self.mmr.root(0)?;
        let proof = self.mmr.proof(loc, 0)?;
        if !self.mmr.verify(&proof, &encoded, loc, &root) {
            return Err(Error::Corrupt("proof self-check failed"));
        }
        Ok(KeyProof { location: loc, operation, proof, root })
    }

    /// Verify a [`KeyProof`] for `key` against an expected root.
    pub fn verify_key_proof(key: &[u8], proof: &KeyProof, expected_root: &Digest) -> bool {
        if proof.root != *expected_root {
            return false;
        }
        if proof.operation.key() != key {
            return false;
        }
        let encoded = proof.operation.encode();
        // Re-verify with a fresh forward hasher matching PersistentMmr default.
        let h = reth_mmr::hasher_forward();
        proof.proof.verify_element_inclusion(&h, &encoded, proof.location, expected_root)
    }

    pub(crate) fn apply(&mut self, op: Operation) -> Result<MmrLocation, Error> {
        let encoded = op.encode();
        // Leaf element = encoded op bytes (Commonware hashes the element bytes directly).
        let loc = self.mmr.append(&encoded)?;
        let ops = self.index_db.cf_handle(CF_OPS).expect("ops");
        let index = self.index_db.cf_handle(CF_INDEX).expect("index");
        self.index_db.put_cf(ops, (*loc).to_be_bytes(), &encoded)?;
        self.index_db.put_cf(index, op.key(), (*loc).to_be_bytes())?;
        Ok(loc)
    }

    fn latest_loc(&self, key: &[u8]) -> Result<Option<MmrLocation>, Error> {
        let index = self.index_db.cf_handle(CF_INDEX).expect("index");
        match self.index_db.get_cf(index, key)? {
            None => Ok(None),
            Some(bytes) if bytes.len() == 8 => {
                Ok(Some(MmrLocation::new(u64::from_be_bytes(bytes.try_into().unwrap()))))
            }
            Some(_) => Err(Error::Corrupt("index loc len")),
        }
    }

    fn latest_op(&self, key: &[u8]) -> Result<Option<Operation>, Error> {
        match self.latest_loc(key)? {
            None => Ok(None),
            Some(loc) => Ok(Some(self.op_at(loc)?)),
        }
    }

    fn op_at(&self, loc: MmrLocation) -> Result<Operation, Error> {
        let ops = self.index_db.cf_handle(CF_OPS).expect("ops");
        let bytes = self
            .index_db
            .get_cf(ops, (*loc).to_be_bytes())?
            .ok_or(Error::Corrupt("missing op"))?;
        Operation::decode(&bytes)
    }

    fn persist_floor(&self) -> Result<(), Error> {
        let meta = self.index_db.cf_handle(CF_META).expect("meta");
        self.index_db.put_cf(meta, META_FLOOR, self.inactivity_floor.to_be_bytes())?;
        Ok(())
    }
}

fn load_floor(db: &DB) -> Result<u64, Error> {
    let meta = db.cf_handle(CF_META).expect("meta");
    match db.get_cf(meta, META_FLOOR)? {
        None => Ok(0),
        Some(b) if b.len() == 8 => Ok(u64::from_be_bytes(b.try_into().unwrap())),
        Some(_) => Err(Error::Corrupt("floor len")),
    }
}

/// Hash helper kept for future key translation (Commonware translators).
pub fn hash_key(key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn update_get_prove_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("qmdb");

        let root = {
            let mut db = Qmdb::open(&path).unwrap();
            db.update(b"alice", b"1").unwrap();
            db.update(b"bob", b"2").unwrap();
            db.update(b"alice", b"3").unwrap();
            assert_eq!(db.get(b"alice").unwrap().as_deref(), Some(b"3".as_slice()));
            assert_eq!(db.get(b"bob").unwrap().as_deref(), Some(b"2".as_slice()));
            let proof = db.prove_key(b"alice").unwrap();
            assert!(matches!(
                &proof.operation,
                Operation::Update { value, .. } if value == b"3"
            ));
            assert!(Qmdb::verify_key_proof(b"alice", &proof, &proof.root));
            db.root().unwrap()
        };

        let db = Qmdb::open(&path).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.root().unwrap(), root);
        assert_eq!(db.get(b"alice").unwrap().as_deref(), Some(b"3".as_slice()));
        let proof = db.prove_key(b"alice").unwrap();
        assert!(Qmdb::verify_key_proof(b"alice", &proof, &root));
    }

    #[test]
    fn delete_clears_value_but_provable() {
        let dir = TempDir::new().unwrap();
        let mut db = Qmdb::open(dir.path().join("qmdb")).unwrap();
        db.update(b"k", b"v").unwrap();
        db.delete(b"k").unwrap();
        assert_eq!(db.get(b"k").unwrap(), None);
        let proof = db.prove_key(b"k").unwrap();
        assert!(matches!(proof.operation, Operation::Delete { .. }));
        assert!(Qmdb::verify_key_proof(b"k", &proof, &proof.root));
    }

    #[test]
    fn peek_root_matches_apply() {
        let dir = TempDir::new().unwrap();
        let mut db = Qmdb::open(dir.path().join("qmdb")).unwrap();
        db.update(b"a", b"1").unwrap();
        let ops = vec![
            Operation::Update { key: b"b".to_vec(), value: b"2".to_vec() },
            Operation::Update { key: b"a".to_vec(), value: b"3".to_vec() },
        ];
        let peeked = db.peek_root_after_ops(ops.clone()).unwrap();
        for op in ops {
            db.apply(op).unwrap();
        }
        assert_eq!(db.root().unwrap(), peeked);
    }

    #[test]
    fn compact_rewrites_active_keys() {
        let dir = TempDir::new().unwrap();
        let mut db = Qmdb::open(dir.path().join("qmdb")).unwrap();
        db.update(b"a", b"1").unwrap();
        db.update(b"b", b"2").unwrap();
        db.update(b"a", b"3").unwrap();
        assert_eq!(*db.inactivity_floor(), 0);
        db.compact(2).unwrap();
        assert_eq!(*db.inactivity_floor(), 2);
        // `a` was still active at loc 0? No — latest a is loc 2, so loc 0 inactive.
        // `b` at loc 1 still active → re-appended.
        assert_eq!(db.get(b"a").unwrap().as_deref(), Some(b"3".as_slice()));
        assert_eq!(db.get(b"b").unwrap().as_deref(), Some(b"2".as_slice()));
        let proof = db.prove_key(b"b").unwrap();
        assert!(*proof.location >= 2);
        assert!(Qmdb::verify_key_proof(b"b", &proof, &proof.root));

        // MMR pruned to floor; tip proofs still verify after restart.
        assert_eq!(db.prune_loc(), MmrLocation::new(2));
        let root = db.root().unwrap();
        drop(db);
        let db = Qmdb::open(dir.path().join("qmdb")).unwrap();
        assert_eq!(db.inactivity_floor(), MmrLocation::new(2));
        assert_eq!(db.root().unwrap(), root);
        let proof = db.prove_key(b"b").unwrap();
        assert!(Qmdb::verify_key_proof(b"b", &proof, &proof.root));
    }
}
