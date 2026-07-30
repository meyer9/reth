//! MMR / MMB primitives for Reth, wrapping [`commonware_storage`].
//!
//! Phase 1–2: in-memory append, root, and inclusion proofs. Persistence and
//! QMDB layering live in sibling crates.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]

use alloy_primitives::B256;
use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher as _, Sha256};
use commonware_storage::merkle::{
    hasher::Standard,
    mmb, mmr,
    Bagging::{BackwardFold, ForwardFold},
    Family as _, Proof,
};
use thiserror::Error;

pub use commonware_storage::merkle::Bagging;
pub use mmb::{Location as MmbLocation, Position as MmbPosition};
pub use mmr::{Location as MmrLocation, Position as MmrPosition};

/// Digest type used by the default Sha256 hasher (Commonware).
pub type Digest = Sha256Digest;

/// Default Merkle hasher: Sha256 + configurable peak bagging.
pub type Hasher = Standard<Sha256>;

/// In-memory Merkle Mountain Range.
pub type Mmr = mmr::mem::Mmr<Digest>;

/// Config for initializing an MMR from retained nodes + pins.
pub type MmrConfig = mmr::mem::Config<Digest>;

/// In-memory Merkle Mountain Belt.
pub type Mmb = mmb::mem::Mmb<Digest>;

/// Config for initializing an MMB from retained nodes + pins.
pub type MmbConfig = mmb::mem::Config<Digest>;

/// Proof over an MMR.
pub type MmrProof = Proof<mmr::Family, Digest>;

/// Proof over an MMB.
pub type MmbProof = Proof<mmb::Family, Digest>;

/// Errors from MMR/MMB operations in this crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying Commonware MMR error.
    #[error(transparent)]
    Mmr(#[from] mmr::Error),
    /// Underlying Commonware MMB error.
    #[error(transparent)]
    Mmb(#[from] mmb::Error),
}

/// Build a Sha256 Merkle hasher with the given bagging policy.
#[inline]
pub fn hasher(bagging: Bagging) -> Hasher {
    Standard::new(bagging)
}

/// Forward-fold bagging hasher (Commonware default in many examples).
#[inline]
pub fn hasher_forward() -> Hasher {
    hasher(ForwardFold)
}

/// Backward-fold bagging hasher.
#[inline]
pub fn hasher_backward() -> Hasher {
    hasher(BackwardFold)
}

/// Hash arbitrary bytes into a leaf element digest (not positioned).
#[inline]
pub fn element_digest(bytes: &[u8]) -> Digest {
    Sha256::hash(bytes)
}

/// Append one element to an in-memory MMR and return its leaf location.
pub fn mmr_append(mmr: &mut Mmr, hasher: &Hasher, element: &[u8]) -> Result<MmrLocation, Error> {
    let loc = mmr.leaves();
    let batch = {
        let batch = mmr.new_batch().add(hasher, element);
        batch.merkleize(mmr, hasher)
    };
    mmr.apply_batch(&batch)?;
    Ok(loc)
}

/// Append many elements to an in-memory MMR in one batch.
pub fn mmr_append_many<'a>(
    mmr: &mut Mmr,
    hasher: &Hasher,
    elements: impl IntoIterator<Item = &'a [u8]>,
) -> Result<MmrLocation, Error> {
    let start = mmr.leaves();
    let batch = {
        let mut batch = mmr.new_batch();
        for element in elements {
            batch = batch.add(hasher, element);
        }
        batch.merkleize(mmr, hasher)
    };
    mmr.apply_batch(&batch)?;
    Ok(start)
}

/// Compute the MMR root with the given inactive-peak count (pyramid bagging).
#[inline]
pub fn mmr_root(mmr: &Mmr, hasher: &Hasher, inactive_peaks: usize) -> Result<Digest, Error> {
    Ok(mmr.root(hasher, inactive_peaks)?)
}

/// Single-leaf inclusion proof for an MMR.
#[inline]
pub fn mmr_proof(
    mmr: &Mmr,
    hasher: &Hasher,
    loc: MmrLocation,
    inactive_peaks: usize,
) -> Result<MmrProof, Error> {
    Ok(mmr.proof(hasher, loc, inactive_peaks)?)
}

/// Verify an MMR single-element inclusion proof against `root`.
pub fn mmr_verify(
    proof: &MmrProof,
    hasher: &Hasher,
    element: &[u8],
    loc: MmrLocation,
    root: &Digest,
) -> bool {
    proof.verify_element_inclusion(hasher, element, loc, root)
}

/// Append one element to an in-memory MMB and return its leaf location.
pub fn mmb_append(mmb: &mut Mmb, hasher: &Hasher, element: &[u8]) -> Result<MmbLocation, Error> {
    let loc = mmb.leaves();
    let batch = {
        let batch = mmb.new_batch().add(hasher, element);
        batch.merkleize(mmb, hasher)
    };
    mmb.apply_batch(&batch)?;
    Ok(loc)
}

/// Append many elements to an in-memory MMB in one batch.
pub fn mmb_append_many<'a>(
    mmb: &mut Mmb,
    hasher: &Hasher,
    elements: impl IntoIterator<Item = &'a [u8]>,
) -> Result<MmbLocation, Error> {
    let start = mmb.leaves();
    let batch = {
        let mut batch = mmb.new_batch();
        for element in elements {
            batch = batch.add(hasher, element);
        }
        batch.merkleize(mmb, hasher)
    };
    mmb.apply_batch(&batch)?;
    Ok(start)
}

/// Compute the MMB root with the given inactive-peak count (pyramid bagging).
#[inline]
pub fn mmb_root(mmb: &Mmb, hasher: &Hasher, inactive_peaks: usize) -> Result<Digest, Error> {
    Ok(mmb.root(hasher, inactive_peaks)?)
}

/// Single-leaf inclusion proof for an MMB.
#[inline]
pub fn mmb_proof(
    mmb: &Mmb,
    hasher: &Hasher,
    loc: MmbLocation,
    inactive_peaks: usize,
) -> Result<MmbProof, Error> {
    Ok(mmb.proof(hasher, loc, inactive_peaks)?)
}

/// Verify an MMB single-element inclusion proof against `root`.
pub fn mmb_verify(
    proof: &MmbProof,
    hasher: &Hasher,
    element: &[u8],
    loc: MmbLocation,
    root: &Digest,
) -> bool {
    proof.verify_element_inclusion(hasher, element, loc, root)
}

/// Convert a Commonware digest to an Ethereum [`B256`] (for `header.state_root`, etc.).
#[inline]
pub fn digest_to_b256(digest: &Digest) -> B256 {
    B256::from_slice(digest.as_ref())
}

/// Convert a [`B256`] to a Commonware digest.
#[inline]
pub fn b256_to_digest(hash: B256) -> Digest {
    Digest::from(<[u8; 32]>::from(hash))
}

/// Count oldest peaks that are entirely below `inactivity_floor` (pyramid bagging input).
#[inline]
pub fn mmr_inactive_peaks(size: MmrPosition, inactivity_floor: MmrLocation) -> usize {
    mmr::Family::inactive_peaks(size, inactivity_floor)
}

/// Count oldest MMB peaks entirely below `inactivity_floor`.
#[inline]
pub fn mmb_inactive_peaks(size: MmbPosition, inactivity_floor: MmbLocation) -> usize {
    mmb::Family::inactive_peaks(size, inactivity_floor)
}

/// Digests that must be pinned when pruning to `prune_loc` (Commonware `nodes_to_pin` order).
///
/// Call **before** [`mmr_prune`] while those nodes are still retained (or already pinned).
pub fn mmr_pin_digests(mmr: &Mmr, prune_loc: MmrLocation) -> Result<Vec<Digest>, Error> {
    let mut out = Vec::new();
    for pos in mmr::Family::nodes_to_pin(prune_loc) {
        let digest = mmr.get_node(pos).ok_or(Error::Mmr(mmr::Error::ElementPruned(pos)))?;
        out.push(digest);
    }
    Ok(out)
}

/// Prune all leaves strictly before `loc`, pinning nodes required for tip roots/proofs.
pub fn mmr_prune(mmr: &mut Mmr, loc: MmrLocation) -> Result<(), Error> {
    Ok(mmr.prune(loc)?)
}

// Re-export family markers for advanced callers.
pub use mmb::Family as MmbFamily;
pub use mmr::Family as MmrFamily;

#[cfg(test)]
mod tests {
    use super::*;

    /// Commonware docs example: 11 equal leaves → size 19, peaks (14,3), (17,1), (18,0).
    #[test]
    fn mmr_eleven_leaves_structure() {
        let h = hasher_forward();
        let mut mmr = Mmr::new();
        let element = b"01234567012345670123456701234567";
        for _ in 0..11 {
            mmr_append(&mut mmr, &h, element).unwrap();
        }
        assert_eq!(mmr.size(), MmrPosition::new(19));
        assert_eq!(*mmr.leaves(), 11);
        let peaks: Vec<_> = mmr.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![
                (MmrPosition::new(14), 3),
                (MmrPosition::new(17), 1),
                (MmrPosition::new(18), 0),
            ]
        );
    }

    #[test]
    fn mmr_append_prove_verify() {
        let h = hasher_forward();
        let mut mmr = Mmr::new();
        let elements: Vec<Vec<u8>> = (0..32u8).map(|i| vec![i; 32]).collect();
        for el in &elements {
            mmr_append(&mut mmr, &h, el).unwrap();
        }
        let root = mmr_root(&mmr, &h, 0).unwrap();
        for (i, el) in elements.iter().enumerate() {
            let loc = MmrLocation::new(i as u64);
            let proof = mmr_proof(&mmr, &h, loc, 0).unwrap();
            assert!(mmr_verify(&proof, &h, el, loc, &root), "proof failed at loc {i}");
        }
        // Wrong element must fail.
        let loc = MmrLocation::new(0);
        let proof = mmr_proof(&mmr, &h, loc, 0).unwrap();
        assert!(!mmr_verify(&proof, &h, b"nope", loc, &root));
    }

    #[test]
    fn mmr_batch_append_many() {
        let h = hasher_backward();
        let mut mmr = Mmr::new();
        let elements: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let start = mmr_append_many(&mut mmr, &h, elements.iter().copied()).unwrap();
        assert_eq!(*start, 0);
        assert_eq!(*mmr.leaves(), 4);
        let root = mmr_root(&mmr, &h, 0).unwrap();
        let proof = mmr_proof(&mmr, &h, MmrLocation::new(2), 0).unwrap();
        assert!(mmr_verify(&proof, &h, b"c", MmrLocation::new(2), &root));
    }

    #[test]
    fn mmr_pyramid_inactive_peaks() {
        let h = hasher_forward();
        let mut mmr = Mmr::new();
        for i in 0..16u64 {
            mmr_append(&mut mmr, &h, &i.to_be_bytes()).unwrap();
        }
        // Floor at 8 → some leading peaks may be inactive.
        let floor = MmrLocation::new(8);
        let inactive = mmr_inactive_peaks(mmr.size(), floor);
        let root0 = mmr_root(&mmr, &h, 0).unwrap();
        let root_p = mmr_root(&mmr, &h, inactive).unwrap();
        // Different inactive_peaks generally change the committed root.
        if inactive > 0 {
            assert_ne!(root0, root_p);
        }
        let loc = MmrLocation::new(15);
        let proof = mmr_proof(&mmr, &h, loc, inactive).unwrap();
        assert!(mmr_verify(&proof, &h, &15u64.to_be_bytes(), loc, &root_p));
    }

    #[test]
    fn mmb_append_prove_verify() {
        let h = hasher_forward();
        let mut mmb = Mmb::new();
        let elements: Vec<Vec<u8>> = (0..24u8).map(|i| vec![i ^ 0x5a; 32]).collect();
        for el in &elements {
            mmb_append(&mut mmb, &h, el).unwrap();
        }
        let floor = MmbLocation::new(8);
        let inactive = mmb_inactive_peaks(mmb.size(), floor);
        let root = mmb_root(&mmb, &h, inactive).unwrap();
        for i in 8..24 {
            let loc = MmbLocation::new(i);
            let proof = mmb_proof(&mmb, &h, loc, inactive).unwrap();
            assert!(
                mmb_verify(&proof, &h, &elements[i as usize], loc, &root),
                "mmb proof failed at {i}"
            );
        }
    }

    #[test]
    fn mmr_mmb_sizes_differ_for_same_leaves() {
        // Sanity: families are distinct topologies.
        let h = hasher_forward();
        let mut mmr = Mmr::new();
        let mut mmb = Mmb::new();
        for i in 0..8u64 {
            let b = i.to_be_bytes();
            mmr_append(&mut mmr, &h, &b).unwrap();
            mmb_append(&mut mmb, &h, &b).unwrap();
        }
        assert_ne!(*mmr.size(), *mmb.size());
        assert_eq!(*mmr.leaves(), *mmb.leaves());
    }
}
