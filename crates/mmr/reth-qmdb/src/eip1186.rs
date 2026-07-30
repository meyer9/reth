//! `eth_getProof` cutover: build EIP-1186-shaped responses from QMDB keyed proofs.
//!
//! This is **not** an MPT proof. Digests in `accountProof` / `storageProof` are MMR
//! inclusion digests (32-byte nodes). `storageHash` is the QMDB MMR root (`stateRoot`).
//! Verifiers must use Commonware/MMR verification against that root, not trie verification.

use alloy_primitives::{keccak256, Address, Bytes, B256, KECCAK256_EMPTY, U256};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, EIP1186StorageProof};
use alloy_serde::JsonStorageKey;

use crate::{account_key, storage_key, Error, Operation, Qmdb};
use reth_mmr::digest_to_b256;

/// Attempt QMDB-backed `eth_getProof` when a default path is registered.
///
/// Returns `Ok(None)` if no QMDB path is registered (caller should fall back to MPT).
pub fn try_get_proof(
    address: Address,
    keys: &[JsonStorageKey],
) -> Result<Option<EIP1186AccountProofResponse>, Error> {
    let Some(path) = crate::default_path() else {
        return Ok(None);
    };
    try_get_proof_at(path, address, keys)
}

/// QMDB-backed `eth_getProof` for an explicit QMDB directory.
pub fn try_get_proof_at(
    path: impl AsRef<std::path::Path>,
    address: Address,
    keys: &[JsonStorageKey],
) -> Result<Option<EIP1186AccountProofResponse>, Error> {
    crate::with_qmdb(path, |db| Ok(Some(get_proof(db, address, keys)?)))
}

/// Build an EIP-1186-shaped account proof from the QMDB tip.
pub fn get_proof(
    db: &Qmdb,
    address: Address,
    keys: &[JsonStorageKey],
) -> Result<EIP1186AccountProofResponse, Error> {
    let root = digest_to_b256(&db.root()?);
    let hashed_addr = keccak256(address);

    let (balance, nonce, code_hash, account_proof) = match db.prove_key(&account_key(hashed_addr)) {
        Ok(proof) => {
            let digests = proof_digests(&proof.proof);
            match &proof.operation {
                Operation::Update { value, .. } => {
                    let (nonce, balance, code_hash) = decode_account_value(value)?;
                    (balance, nonce, code_hash, digests)
                }
                Operation::Delete { .. } => {
                    (U256::ZERO, 0, KECCAK256_EMPTY, digests)
                }
            }
        }
        Err(Error::NotFound) => (U256::ZERO, 0, KECCAK256_EMPTY, Vec::new()),
        Err(e) => return Err(e),
    };

    let mut storage_proof = Vec::with_capacity(keys.len());
    for key in keys {
        let slot = key.as_b256();
        let hashed_slot = keccak256(slot);
        let (value, proof_nodes) =
            match db.prove_key(&storage_key(hashed_addr, hashed_slot)) {
                Ok(proof) => {
                    let digests = proof_digests(&proof.proof);
                    let value = match &proof.operation {
                        Operation::Update { value, .. } => decode_storage_value(value)?,
                        Operation::Delete { .. } => U256::ZERO,
                    };
                    (value, digests)
                }
                Err(Error::NotFound) => (U256::ZERO, Vec::new()),
                Err(e) => return Err(e),
            };
        storage_proof.push(EIP1186StorageProof {
            key: key.clone(),
            value,
            proof: proof_nodes,
        });
    }

    Ok(EIP1186AccountProofResponse {
        address,
        balance,
        code_hash,
        nonce,
        // QMDB root committed as header `stateRoot` — reuse the field as the authenticated tip.
        storage_hash: root,
        account_proof,
        storage_proof,
    })
}

fn proof_digests(proof: &reth_mmr::MmrProof) -> Vec<Bytes> {
    proof
        .digests
        .iter()
        .map(|d| Bytes::copy_from_slice(d.as_ref()))
        .collect()
}

fn decode_account_value(value: &[u8]) -> Result<(u64, U256, B256), Error> {
    if value.len() != 8 + 32 + 32 {
        return Err(Error::Corrupt("account value len"));
    }
    let nonce = u64::from_be_bytes(value[0..8].try_into().unwrap());
    let balance = U256::from_be_slice(&value[8..40]);
    let code_hash = B256::from_slice(&value[40..72]);
    Ok((nonce, balance, code_hash))
}

fn decode_storage_value(value: &[u8]) -> Result<U256, Error> {
    if value.len() != 32 {
        return Err(Error::Corrupt("storage value len"));
    }
    Ok(U256::from_be_slice(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::map::HashMap;
    use reth_primitives_traits::Account;
    use reth_trie_common::{HashedPostState, HashedStorage};
    use tempfile::TempDir;

    #[test]
    fn eip1186_from_qmdb() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("qmdb");
        let mut db = Qmdb::open(&path).unwrap();
        crate::register_default_path(path);

        let address = Address::repeat_byte(0xAB);
        let hashed = keccak256(address);
        let slot = B256::repeat_byte(0x01);

        let mut accounts = alloy_primitives::map::B256Map::default();
        accounts.insert(
            hashed,
            Some(Account {
                nonce: 3,
                balance: U256::from(42),
                bytecode_hash: None,
            }),
        );
        let mut slot_map = HashMap::default();
        slot_map.insert(keccak256(slot), U256::from(9));
        let mut storages = alloy_primitives::map::B256Map::default();
        storages.insert(hashed, HashedStorage { wiped: false, storage: slot_map });
        db.apply_hashed_post_state(&HashedPostState { accounts, storages }).unwrap();

        let resp = get_proof(&db, address, &[JsonStorageKey::from(slot)]).unwrap();
        assert_eq!(resp.address, address);
        assert_eq!(resp.nonce, 3);
        assert_eq!(resp.balance, U256::from(42));
        assert_eq!(resp.code_hash, KECCAK256_EMPTY);
        assert_eq!(resp.storage_hash, digest_to_b256(&db.root().unwrap()));
        assert!(!resp.account_proof.is_empty());
        assert_eq!(resp.storage_proof.len(), 1);
        assert_eq!(resp.storage_proof[0].value, U256::from(9));
        assert!(!resp.storage_proof[0].proof.is_empty());

        // try_get_proof needs exclusive open — drop first handle.
        let root = digest_to_b256(&db.root().unwrap());
        drop(db);
        let resp2 = try_get_proof(address, &[]).unwrap().expect("registered");
        assert_eq!(resp2.storage_hash, root);
    }
}
