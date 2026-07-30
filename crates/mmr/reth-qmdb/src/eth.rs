//! Apply Reth [`HashedPostState`] diffs as QMDB operations.

use alloy_primitives::{B256, U256};
use reth_mmr::MmrLocation;
use reth_primitives_traits::Account;
use reth_trie_common::HashedPostState;

use crate::{Error, Operation, Qmdb};

const ACCOUNT_TAG: u8 = b'a';
const STORAGE_TAG: u8 = b's';

/// QMDB key for a hashed account.
pub fn account_key(hashed_address: B256) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32);
    key.push(ACCOUNT_TAG);
    key.extend_from_slice(hashed_address.as_slice());
    key
}

/// QMDB key for a hashed storage slot.
pub fn storage_key(hashed_address: B256, hashed_slot: B256) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 64);
    key.push(STORAGE_TAG);
    key.extend_from_slice(hashed_address.as_slice());
    key.extend_from_slice(hashed_slot.as_slice());
    key
}

fn encode_account(account: &Account) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(&account.nonce.to_be_bytes());
    out.extend_from_slice(&account.balance.to_be_bytes::<32>());
    let code_hash = account.bytecode_hash.unwrap_or(alloy_primitives::KECCAK256_EMPTY);
    out.extend_from_slice(code_hash.as_slice());
    out
}

fn encode_storage_value(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

impl Qmdb {
    /// Apply a [`HashedPostState`] as update/delete ops. Returns locations written.
    pub fn apply_hashed_post_state(
        &mut self,
        state: &HashedPostState,
    ) -> Result<Vec<MmrLocation>, Error> {
        apply_hashed_post_state(self, state)
    }

    /// Apply a sorted hashed post-state (as produced by executed blocks).
    pub fn apply_hashed_post_state_sorted(
        &mut self,
        sorted: &reth_trie_common::HashedPostStateSorted,
    ) -> Result<Vec<MmrLocation>, Error> {
        let mut state = HashedPostState::default();
        state.extend_from_sorted(sorted);
        self.apply_hashed_post_state(&state)
    }
}

/// Apply hashed post-state into `db`.
pub fn apply_hashed_post_state(
    db: &mut Qmdb,
    state: &HashedPostState,
) -> Result<Vec<MmrLocation>, Error> {
    let mut locs = Vec::new();
    for op in ops_from_hashed_post_state(state) {
        locs.push(db.apply(op)?);
    }
    Ok(locs)
}

/// Convert a [`HashedPostState`] into QMDB operations (deterministic order).
pub fn ops_from_hashed_post_state(state: &HashedPostState) -> Vec<Operation> {
    let mut ops = Vec::new();

    let mut accounts: Vec<_> = state.accounts.iter().collect();
    accounts.sort_by_key(|(addr, _)| *addr);
    for (hashed_address, account) in accounts {
        let key = account_key(*hashed_address);
        ops.push(match account {
            Some(acc) => Operation::Update { key, value: encode_account(acc) },
            None => Operation::Delete { key },
        });
    }

    let mut storages: Vec<_> = state.storages.iter().collect();
    storages.sort_by_key(|(addr, _)| *addr);
    for (hashed_address, storage) in storages {
        if storage.wiped {
            let wipe_key = {
                let mut k = account_key(*hashed_address);
                k[0] = b'w';
                k
            };
            ops.push(Operation::Update { key: wipe_key, value: vec![1] });
        }

        let mut slots: Vec<_> = storage.storage.iter().collect();
        slots.sort_by_key(|(slot, _)| *slot);
        for (hashed_slot, value) in slots {
            let key = storage_key(*hashed_address, *hashed_slot);
            ops.push(if value.is_zero() {
                Operation::Delete { key }
            } else {
                Operation::Update { key, value: encode_storage_value(*value).to_vec() }
            });
        }
    }

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{map::HashMap, U256};
    use reth_mmr::digest_to_b256;
    use reth_trie_common::HashedStorage;
    use tempfile::TempDir;

    #[test]
    fn hashed_state_to_header_root() {
        let dir = TempDir::new().unwrap();
        let mut db = Qmdb::open(dir.path().join("qmdb")).unwrap();

        let addr = B256::repeat_byte(0x11);
        let mut accounts = alloy_primitives::map::B256Map::default();
        accounts.insert(
            addr,
            Some(Account {
                nonce: 1,
                balance: U256::from(100),
                bytecode_hash: None,
            }),
        );
        let mut slot_map = HashMap::default();
        slot_map.insert(B256::repeat_byte(0x22), U256::from(7));
        let mut storages = alloy_primitives::map::B256Map::default();
        storages.insert(addr, HashedStorage { wiped: false, storage: slot_map });

        let state = HashedPostState { accounts, storages };
        db.apply_hashed_post_state(&state).unwrap();

        let root = db.root().unwrap();
        let header_state_root = digest_to_b256(&root);
        assert_ne!(header_state_root, B256::ZERO);

        let proof = db.prove_key(&account_key(addr)).unwrap();
        assert!(Qmdb::verify_key_proof(&account_key(addr), &proof, &root));
        assert_eq!(digest_to_b256(&proof.root), header_state_root);
    }
}
