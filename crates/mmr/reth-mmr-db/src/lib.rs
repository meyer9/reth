//! RocksDB-backed durable MMR (own DB directory; not yet merged into primary CFs).
//!
//! Keeps a hot in-memory [`reth_mmr::Mmr`] and mirrors retained nodes + meta/pins to disk
//! so reopen restores an identical structure, including after prune.

use reth_mmr::{
    mmr_append, mmr_append_many, mmr_inactive_peaks, mmr_pin_digests, mmr_proof, mmr_prune,
    mmr_root, mmr_verify, Bagging, Digest, Error as MmrError, Hasher, Mmr, MmrConfig, MmrLocation,
    MmrPosition, MmrProof,
};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::{
    fmt,
    path::{Path, PathBuf},
};
use thiserror::Error;

const CF_NODES: &str = "mmr_nodes";
const CF_META: &str = "mmr_meta";

const META_LEAVES: &[u8] = b"leaves";
const META_PRUNE: &[u8] = b"prune_loc";
const META_BAGGING: &[u8] = b"bagging";
const META_PINS: &[u8] = b"pinned_nodes";

/// Errors from durable MMR storage.
#[derive(Debug, Error)]
pub enum Error {
    /// RocksDB error.
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    /// MMR logic error.
    #[error(transparent)]
    Mmr(#[from] MmrError),
    /// Corrupt or incomplete on-disk metadata.
    #[error("corrupt mmr db: {0}")]
    Corrupt(&'static str),
    /// I/O / path issues.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Durable MMR store under `path` (creates CFs as needed).
pub struct PersistentMmr {
    path: PathBuf,
    db: DB,
    mmr: Mmr,
    hasher: Hasher,
}

impl fmt::Debug for PersistentMmr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentMmr")
            .field("path", &self.path)
            .field("leaves", &self.leaves())
            .field("prune_loc", &self.prune_loc())
            .finish_non_exhaustive()
    }
}

impl PersistentMmr {
    /// Open or create an MMR database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_bagging(path, Bagging::ForwardFold)
    }

    /// Open with an explicit bagging policy (stored in meta on first create).
    pub fn open_with_bagging(path: impl AsRef<Path>, bagging: Bagging) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_NODES, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, &path, cfs)?;

        let hasher = match load_bagging(&db)? {
            Some(stored) => reth_mmr::hasher(stored),
            None => {
                put_bagging(&db, bagging)?;
                reth_mmr::hasher(bagging)
            }
        };

        let mmr = load_mmr(&db)?;
        Ok(Self { path, db, mmr, hasher })
    }

    /// Directory this store was opened on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the hot in-memory MMR.
    pub fn mmr(&self) -> &Mmr {
        &self.mmr
    }

    /// Hasher used for roots/proofs.
    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }

    /// Clone the hot MMR for speculative root computation (does not touch disk).
    pub fn clone_mmr(&self) -> Mmr {
        self.mmr.clone()
    }

    /// Number of leaves.
    pub fn leaves(&self) -> u64 {
        *self.mmr.leaves()
    }

    /// Oldest retained leaf location (pruning boundary).
    pub fn prune_loc(&self) -> MmrLocation {
        self.mmr.bounds().start
    }

    /// Append one element and persist new nodes + meta.
    pub fn append(&mut self, element: &[u8]) -> Result<MmrLocation, Error> {
        let old_size = *self.mmr.size();
        let loc = mmr_append(&mut self.mmr, &self.hasher, element)?;
        self.persist_suffix(old_size)?;
        Ok(loc)
    }

    /// Append many elements in one MMR batch and persist.
    pub fn append_many<'a>(
        &mut self,
        elements: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<MmrLocation, Error> {
        let old_size = *self.mmr.size();
        let start = mmr_append_many(&mut self.mmr, &self.hasher, elements)?;
        self.persist_suffix(old_size)?;
        Ok(start)
    }

    /// Prune leaves strictly before `loc`, pin required digests, and drop pruned nodes from disk.
    ///
    /// Root is unchanged. Proofs for locations `< loc` fail after prune.
    pub fn prune(&mut self, loc: MmrLocation) -> Result<(), Error> {
        if loc <= self.prune_loc() {
            return Ok(());
        }

        let pins = mmr_pin_digests(&self.mmr, loc)?;
        let old_prune_pos = *MmrPosition::try_from(self.prune_loc())
            .map_err(|_| Error::Corrupt("old prune pos"))?;
        let new_prune_pos =
            *MmrPosition::try_from(loc).map_err(|_| Error::Corrupt("new prune pos"))?;

        mmr_prune(&mut self.mmr, loc)?;

        let nodes_cf = self.db.cf_handle(CF_NODES).expect("mmr_nodes cf");
        let mut batch = WriteBatch::default();
        // Drop retained-node keys in [old_prune_pos, new_prune_pos).
        for pos in old_prune_pos..new_prune_pos {
            batch.delete_cf(nodes_cf, pos.to_be_bytes());
        }
        self.db.write(batch)?;
        self.write_meta_with_pins(&pins)?;
        Ok(())
    }

    /// Root with explicit inactive-peak count (0 = no pyramid split).
    pub fn root(&self, inactive_peaks: usize) -> Result<Digest, Error> {
        Ok(mmr_root(&self.mmr, &self.hasher, inactive_peaks)?)
    }

    /// Root using pyramid bagging for the given inactivity floor.
    pub fn root_at_floor(&self, inactivity_floor: MmrLocation) -> Result<(Digest, usize), Error> {
        let inactive = mmr_inactive_peaks(self.mmr.size(), inactivity_floor);
        Ok((self.root(inactive)?, inactive))
    }

    /// Inclusion proof for `loc`.
    pub fn proof(&self, loc: MmrLocation, inactive_peaks: usize) -> Result<MmrProof, Error> {
        Ok(mmr_proof(&self.mmr, &self.hasher, loc, inactive_peaks)?)
    }

    /// Verify a proof against a root.
    pub fn verify(
        &self,
        proof: &MmrProof,
        element: &[u8],
        loc: MmrLocation,
        root: &Digest,
    ) -> bool {
        mmr_verify(proof, &self.hasher, element, loc, root)
    }

    /// Flush WAL/memtables.
    pub fn flush(&self) -> Result<(), Error> {
        self.db.flush()?;
        Ok(())
    }

    fn persist_suffix(&mut self, old_size: u64) -> Result<(), Error> {
        let cf = self.db.cf_handle(CF_NODES).expect("mmr_nodes cf");
        let new_size = *self.mmr.size();
        for pos in old_size..new_size {
            let digest = self
                .mmr
                .get_node(MmrPosition::new(pos))
                .ok_or(Error::Corrupt("missing node after append"))?;
            self.db.put_cf(cf, pos.to_be_bytes(), digest.as_ref())?;
        }
        // Pins unchanged on append; rewrite leaves + prune_loc only.
        let pins = load_pins(&self.db)?;
        self.write_meta_with_pins(&pins)?;
        Ok(())
    }

    fn write_meta_with_pins(&self, pins: &[Digest]) -> Result<(), Error> {
        let cf = self.db.cf_handle(CF_META).expect("mmr_meta cf");
        self.db.put_cf(cf, META_LEAVES, (*self.mmr.leaves()).to_be_bytes())?;
        self.db.put_cf(cf, META_PRUNE, (*self.prune_loc()).to_be_bytes())?;
        let mut pin_bytes = Vec::with_capacity(pins.len() * 32);
        for d in pins {
            pin_bytes.extend_from_slice(d.as_ref());
        }
        self.db.put_cf(cf, META_PINS, pin_bytes)?;
        Ok(())
    }
}

fn load_bagging(db: &DB) -> Result<Option<Bagging>, Error> {
    let cf = db.cf_handle(CF_META).expect("mmr_meta cf");
    match db.get_cf(cf, META_BAGGING)? {
        None => Ok(None),
        Some(bytes) if bytes.as_slice() == [0] => Ok(Some(Bagging::ForwardFold)),
        Some(bytes) if bytes.as_slice() == [1] => Ok(Some(Bagging::BackwardFold)),
        Some(_) => Err(Error::Corrupt("unknown bagging")),
    }
}

fn put_bagging(db: &DB, bagging: Bagging) -> Result<(), Error> {
    let cf = db.cf_handle(CF_META).expect("mmr_meta cf");
    let tag = match bagging {
        Bagging::ForwardFold => [0u8],
        Bagging::BackwardFold => [1u8],
    };
    db.put_cf(cf, META_BAGGING, tag)?;
    Ok(())
}

fn load_pins(db: &DB) -> Result<Vec<Digest>, Error> {
    let meta = db.cf_handle(CF_META).expect("mmr_meta cf");
    match db.get_cf(meta, META_PINS)? {
        None => Ok(Vec::new()),
        Some(bytes) if bytes.is_empty() => Ok(Vec::new()),
        Some(bytes) if bytes.len() % 32 == 0 => {
            Ok(bytes
                .chunks_exact(32)
                .map(|c| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(c);
                    Digest::from(arr)
                })
                .collect())
        }
        Some(_) => Err(Error::Corrupt("pinned_nodes len")),
    }
}

fn load_mmr(db: &DB) -> Result<Mmr, Error> {
    let meta = db.cf_handle(CF_META).expect("mmr_meta cf");
    let nodes_cf = db.cf_handle(CF_NODES).expect("mmr_nodes cf");

    let Some(leaves_bytes) = db.get_cf(meta, META_LEAVES)? else {
        // Empty DB.
        return Ok(Mmr::new());
    };
    if leaves_bytes.len() != 8 {
        return Err(Error::Corrupt("leaves len"));
    }
    let leaves = u64::from_be_bytes(leaves_bytes.try_into().unwrap());
    if leaves == 0 {
        return Ok(Mmr::new());
    }

    let prune_loc = match db.get_cf(meta, META_PRUNE)? {
        Some(b) if b.len() == 8 => MmrLocation::new(u64::from_be_bytes(b.try_into().unwrap())),
        None => MmrLocation::new(0),
        Some(_) => return Err(Error::Corrupt("prune_loc len")),
    };

    let prune_pos =
        *MmrPosition::try_from(prune_loc).map_err(|_| Error::Corrupt("prune_loc→pos"))?;
    let expected_size = {
        *MmrPosition::try_from(MmrLocation::new(leaves)).map_err(|_| Error::Corrupt("leaf→size"))?
    };
    if prune_pos > expected_size {
        return Err(Error::Corrupt("prune beyond size"));
    }

    let pinned_nodes = load_pins(db)?;

    // Retained nodes: positions [prune_pos, expected_size), keys are u64 BE.
    let mut nodes = Vec::with_capacity((expected_size - prune_pos) as usize);
    let iter = db.iterator_cf(nodes_cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, val) = item?;
        if key.len() != 8 || val.len() != 32 {
            return Err(Error::Corrupt("node kv size"));
        }
        let pos = u64::from_be_bytes(key.as_ref().try_into().unwrap());
        if pos < prune_pos {
            // Stale node left behind — ignore (or could delete lazily).
            continue;
        }
        if pos != prune_pos + nodes.len() as u64 {
            return Err(Error::Corrupt("node position gap"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&val);
        nodes.push(Digest::from(arr));
    }
    if nodes.len() as u64 != expected_size - prune_pos {
        return Err(Error::Corrupt("retained node count"));
    }

    Mmr::init(MmrConfig {
        nodes,
        pruning_boundary: prune_loc,
        pinned_nodes,
    })
    .map_err(|e| Error::Mmr(e.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn persist_restart_prove() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("mmr");

        let root = {
            let mut store = PersistentMmr::open(&path).unwrap();
            for i in 0..20u64 {
                store.append(&i.to_be_bytes()).unwrap();
            }
            store.flush().unwrap();
            let root = store.root(0).unwrap();
            let proof = store.proof(MmrLocation::new(7), 0).unwrap();
            assert!(store.verify(&proof, &7u64.to_be_bytes(), MmrLocation::new(7), &root));
            root
        };

        let store = PersistentMmr::open(&path).unwrap();
        assert_eq!(store.leaves(), 20);
        assert_eq!(store.root(0).unwrap(), root);
        let proof = store.proof(MmrLocation::new(7), 0).unwrap();
        assert!(store.verify(&proof, &7u64.to_be_bytes(), MmrLocation::new(7), &root));
    }

    #[test]
    fn batch_append_many_persists() {
        let dir = TempDir::new().unwrap();
        let mut store = PersistentMmr::open(dir.path().join("mmr")).unwrap();
        let els: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        store.append_many(els.iter().copied()).unwrap();
        store.flush().unwrap();
        drop(store);

        let store = PersistentMmr::open(dir.path().join("mmr")).unwrap();
        assert_eq!(store.leaves(), 3);
        let root = store.root(0).unwrap();
        let proof = store.proof(MmrLocation::new(1), 0).unwrap();
        assert!(store.verify(&proof, b"two", MmrLocation::new(1), &root));
    }

    #[test]
    fn prune_preserves_root_and_reloads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("mmr");

        let (root, tip_proof_ok) = {
            let mut store = PersistentMmr::open(&path).unwrap();
            for i in 0..20u64 {
                store.append(&i.to_be_bytes()).unwrap();
            }
            let root = store.root(0).unwrap();
            store.prune(MmrLocation::new(8)).unwrap();
            assert_eq!(store.prune_loc(), MmrLocation::new(8));
            assert_eq!(store.root(0).unwrap(), root);
            assert!(store.proof(MmrLocation::new(3), 0).is_err());
            let proof = store.proof(MmrLocation::new(10), 0).unwrap();
            assert!(store.verify(&proof, &10u64.to_be_bytes(), MmrLocation::new(10), &root));
            store.flush().unwrap();
            (root, true)
        };
        assert!(tip_proof_ok);

        let store = PersistentMmr::open(&path).unwrap();
        assert_eq!(store.leaves(), 20);
        assert_eq!(store.prune_loc(), MmrLocation::new(8));
        assert_eq!(store.root(0).unwrap(), root);
        let proof = store.proof(MmrLocation::new(10), 0).unwrap();
        assert!(store.verify(&proof, &10u64.to_be_bytes(), MmrLocation::new(10), &root));
        assert!(store.proof(MmrLocation::new(3), 0).is_err());
    }
}
