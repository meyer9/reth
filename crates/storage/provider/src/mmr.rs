//! Feature-gated QMDB / MMR integration (`feature = "mmr"`).
//!
//! Pending overlay: per-path FIFO of sealed-but-not-yet-saved hashed states.
//! Pop front on each append (under the QMDB lock). Better payloads that push
//! multiple times per height can still confuse FIFO; prefer Freeze or ensure
//! save happens before the next height's peek when possible.

use alloy_primitives::B256;
use reth_qmdb;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use reth_trie::{HashedPostState, HashedPostStateSorted};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use tracing::{debug, warn};

/// Directory name next to the DB path for the QMDB store.
pub const QMDB_DIR: &str = "qmdb";

type PendingMap = HashMap<PathBuf, Vec<(u64, HashedPostState)>>;
static PENDING: OnceLock<Mutex<PendingMap>> = OnceLock::new();

fn pending_map() -> &'static Mutex<PendingMap> {
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve QMDB path from the provider database path (`…/db` → `…/qmdb`).
pub fn qmdb_path_from_db_path(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .map(|p| p.join(QMDB_DIR))
        .unwrap_or_else(|| db_path.join(QMDB_DIR))
}

/// Remember the QMDB datadir for speculative header-root peeks (payload / validation).
pub fn register_qmdb_datadir(path: PathBuf) {
    reth_qmdb::register_default_path(path);
}

/// Currently registered QMDB datadir, if any.
pub fn qmdb_datadir() -> Option<PathBuf> {
    reth_qmdb::default_path()
}

/// Best-effort primary DB path (`…/db`) from a provider factory, for per-node peeks.
pub fn db_path_from_factory<F: reth_storage_api::DatabaseProviderFactory>(
    factory: &F,
) -> Option<PathBuf> {
    factory.db_path()
}

fn map_qmdb_err(ctx: &str, e: reth_qmdb::Error) -> ProviderError {
    ProviderError::other(std::io::Error::other(format!("{ctx}: {e}")))
}

/// Record a hashed post-state sealed into a payload but not yet persisted via `save_blocks`.
///
/// Same-height Better rebuilds **replace** the last pending entry when it has the same
/// block number; otherwise append (FIFO for consecutive heights).
pub fn push_pending_hashed_state(db_path: &Path, block_number: u64, state: &HashedPostState) {
    if state.is_empty() {
        return;
    }
    let path = qmdb_path_from_db_path(db_path);
    let mut map = pending_map().lock().expect("qmdb pending lock");
    let queue = map.entry(path).or_default();
    if let Some((num, slot)) = queue.last_mut() {
        if *num == block_number {
            *slot = state.clone();
            return;
        }
    }
    queue.push((block_number, state.clone()));
}

fn take_pending_matching(path: &Path, block_number: Option<u64>) {
    let mut map = pending_map().lock().expect("qmdb pending lock");
    let Some(queue) = map.get_mut(path) else {
        return;
    };
    match block_number {
        Some(n) => {
            if let Some(pos) = queue.iter().position(|(bn, _)| *bn == n) {
                queue.remove(pos);
            } else if !queue.is_empty() {
                // Fallback: pop front if heights drifted.
                queue.remove(0);
            }
        }
        None => {
            if !queue.is_empty() {
                queue.remove(0);
            }
        }
    }
    if queue.is_empty() {
        map.remove(path);
    }
}

fn pending_ops_before(path: &Path, before_block: Option<u64>) -> Vec<reth_qmdb::Operation> {
    let map = pending_map().lock().expect("qmdb pending lock");
    let Some(queue) = map.get(path) else {
        return Vec::new();
    };
    let mut ops = Vec::new();
    for (num, state) in queue {
        if before_block.is_some_and(|b| *num >= b) {
            continue;
        }
        ops.extend(reth_qmdb::ops_from_hashed_post_state(state));
    }
    ops
}

fn peek_with_pending(
    path: &Path,
    before_block: Option<u64>,
    state: &HashedPostState,
) -> Result<B256, reth_qmdb::Error> {
    reth_qmdb::with_qmdb(path, |qmdb| {
        let mut ops = pending_ops_before(path, before_block);
        if !state.is_empty() {
            ops.extend(reth_qmdb::ops_from_hashed_post_state(state));
        }
        if ops.is_empty() {
            return qmdb.root_b256();
        }
        qmdb.peek_root_after_ops_b256(ops)
    })
}

/// Apply a hashed post-state batch to the on-disk QMDB; return the new root as [`B256`].
pub fn append_hashed_state(
    db_path: &Path,
    state: &HashedPostStateSorted,
) -> ProviderResult<B256> {
    append_hashed_state_at_block(db_path, None, state)
}

/// Apply hashed state and drop the matching pending entry under the QMDB lock.
pub fn append_hashed_state_at_block(
    db_path: &Path,
    block_number: Option<u64>,
    state: &HashedPostStateSorted,
) -> ProviderResult<B256> {
    let path = qmdb_path_from_db_path(db_path);
    register_qmdb_datadir(path.clone());

    if state.is_empty() {
        if !path.exists() {
            take_pending_matching(&path, block_number);
            return Ok(B256::ZERO);
        }
        let root = reth_qmdb::with_qmdb(&path, |qmdb| {
            let root = qmdb.root_b256()?;
            take_pending_matching(&path, block_number);
            Ok(root)
        })
        .map_err(|e| map_qmdb_err("qmdb root", e))?;
        return Ok(root);
    }

    let root = reth_qmdb::with_qmdb(&path, |qmdb| {
        qmdb.apply_hashed_post_state_sorted(state)?;
        let b256 = qmdb.root_b256()?;
        take_pending_matching(&path, block_number);
        debug!(
            target: "providers::mmr",
            root = %b256,
            leaves = qmdb.len(),
            path = %path.display(),
            "updated QMDB after hashed state write"
        );
        Ok(b256)
    })
    .map_err(|e| map_qmdb_err(&format!("qmdb append at {path:?}"), e))?;
    Ok(root)
}

/// Speculative QMDB state root for a hashed post-state on top of the on-disk tip (no writes).
pub fn peek_state_root(
    db_path: &Path,
    state: &HashedPostStateSorted,
) -> ProviderResult<B256> {
    let path = qmdb_path_from_db_path(db_path);
    let mut unsorted = HashedPostState::default();
    unsorted.extend_from_sorted(state);
    peek_with_pending(&path, None, &unsorted).map_err(|e| map_qmdb_err("qmdb peek", e))
}

/// Speculative peek from an unsorted [`HashedPostState`] using an explicit DB path.
pub fn peek_state_root_from_post_state(
    db_path: &Path,
    state: &HashedPostState,
) -> ProviderResult<B256> {
    let path = qmdb_path_from_db_path(db_path);
    peek_with_pending(&path, None, state).map_err(|e| map_qmdb_err("qmdb peek", e))
}

/// Peek header `stateRoot` using the registered QMDB datadir (single-node / RPC fallback).
pub fn peek_registered_state_root(state: &HashedPostStateSorted) -> ProviderResult<Option<B256>> {
    let Some(path) = qmdb_datadir() else {
        return Ok(None)
    };
    let mut unsorted = HashedPostState::default();
    unsorted.extend_from_sorted(state);
    Ok(Some(
        peek_with_pending(&path, None, &unsorted).map_err(|e| map_qmdb_err("qmdb peek", e))?,
    ))
}

/// Convenience: peek from an unsorted [`HashedPostState`] via the process-wide registry.
pub fn peek_registered_state_root_from_post_state(
    state: &HashedPostState,
) -> ProviderResult<Option<B256>> {
    let sorted = state.clone_into_sorted();
    peek_registered_state_root(&sorted)
}

/// Prefer an explicit DB path; fall back to the process-wide registry.
pub fn peek_state_root_prefer_path(
    db_path: Option<&Path>,
    state: &HashedPostState,
) -> ProviderResult<Option<B256>> {
    if let Some(path) = db_path {
        return Ok(Some(peek_state_root_from_post_state(path, state)?))
    }
    peek_registered_state_root_from_post_state(state)
}

/// Prefer an explicit DB path. Overlay pending blocks with number `< block_number`.
pub fn peek_state_root_prefer_path_at_block(
    db_path: Option<&Path>,
    block_number: Option<u64>,
    state: &HashedPostState,
) -> ProviderResult<Option<B256>> {
    if let Some(path) = db_path {
        let qmdb = qmdb_path_from_db_path(path);
        return Ok(Some(
            peek_with_pending(&qmdb, block_number, state)
                .map_err(|e| map_qmdb_err("qmdb peek", e))?,
        ))
    }
    let Some(path) = qmdb_datadir() else {
        return Ok(None)
    };
    Ok(Some(
        peek_with_pending(&path, block_number, state).map_err(|e| map_qmdb_err("qmdb peek", e))?,
    ))
}

/// Best-effort append used from `save_blocks`.
pub fn append_hashed_state_best_effort(db_path: &Path, state: &HashedPostStateSorted) {
    append_hashed_state_best_effort_at_block(db_path, None, state)
}

/// Best-effort append that drops the matching pending entry.
pub fn append_hashed_state_best_effort_at_block(
    db_path: &Path,
    block_number: Option<u64>,
    state: &HashedPostStateSorted,
) {
    match append_hashed_state_at_block(db_path, block_number, state) {
        Ok(root) if root != B256::ZERO => {
            debug!(target: "providers::mmr", %root, "qmdb root (candidate stateRoot)");
        }
        Ok(_) => {}
        Err(err) => {
            warn!(target: "providers::mmr", %err, "failed to update qmdb");
        }
    }
}
