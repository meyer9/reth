#![allow(missing_docs)]

use core::hash;
use std::alloc::GlobalAlloc;

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_primitives::{
    keccak256,
    map::{HashMap, HashSet},
    Address, Bytes, B256, U256,
};
use alloy_rlp::{BufMut, EMPTY_STRING_CODE};
use reth_db::{cursor::DbCursorRW, tables};
use reth_db_api::transaction::DbTxMut;
use reth_primitives::{Account, StorageEntry};
use reth_provider::{test_utils::create_test_provider_factory, HashingWriter};
use reth_trie::{proof::Proof, witness::TrieWitness, HashedPostState, HashedStorage, Nibbles, StateRoot};
use reth_trie_db::{DatabaseProof, DatabaseStateRoot, DatabaseTrieWitness};

#[test]
fn includes_empty_node_preimage() {
    let factory = create_test_provider_factory();
    let provider = factory.provider_rw().unwrap();

    let address = Address::random();
    let hashed_address = keccak256(address);
    let hashed_slot = B256::random();

    // witness includes empty state trie root node
    assert_eq!(
        TrieWitness::from_tx(provider.tx_ref())
            .compute(HashedPostState {
                accounts: HashMap::from([(hashed_address, Some(Account::default()))]),
                storages: HashMap::default(),
            })
            .unwrap(),
        HashMap::from_iter([(EMPTY_ROOT_HASH, Bytes::from([EMPTY_STRING_CODE]))])
    );

    // Insert account into database
    provider.insert_account_for_hashing([(address, Some(Account::default()))]).unwrap();

    let state_root = StateRoot::from_tx(provider.tx_ref()).root().unwrap();
    let multiproof = Proof::from_tx(provider.tx_ref())
        .multiproof(HashMap::from_iter([(hashed_address, HashSet::from_iter([hashed_slot]))]))
        .unwrap();

    let witness = TrieWitness::from_tx(provider.tx_ref())
        .compute(HashedPostState {
            accounts: HashMap::from([(hashed_address, Some(Account::default()))]),
            storages: HashMap::from([(
                hashed_address,
                HashedStorage::from_iter(false, [(hashed_slot, U256::from(1))]),
            )]),
        })
        .unwrap();
    assert!(witness.contains_key(&state_root));
    for node in multiproof.account_subtree.values() {
        assert_eq!(witness.get(&keccak256(node)), Some(node));
    }
    // witness includes empty state trie root node
    assert_eq!(witness.get(&EMPTY_ROOT_HASH), Some(&Bytes::from([EMPTY_STRING_CODE])));
}

#[test]
fn includes_nodes_for_destroyed_storage_nodes() {
    let factory = create_test_provider_factory();
    let provider = factory.provider_rw().unwrap();

    let address = Address::random();
    let hashed_address = keccak256(address);
    let slot = B256::random();
    let hashed_slot = keccak256(slot);

    // Insert account and slot into database
    provider.insert_account_for_hashing([(address, Some(Account::default()))]).unwrap();
    provider
        .insert_storage_for_hashing([(address, [StorageEntry { key: slot, value: U256::from(1) }])])
        .unwrap();

    let state_root = StateRoot::from_tx(provider.tx_ref()).root().unwrap();
    let multiproof = Proof::from_tx(provider.tx_ref())
        .multiproof(HashMap::from_iter([(hashed_address, HashSet::from_iter([hashed_slot]))]))
        .unwrap();

    let witness = TrieWitness::from_tx(provider.tx_ref())
        .compute(HashedPostState {
            accounts: HashMap::from([(hashed_address, Some(Account::default()))]),
            storages: HashMap::from([(hashed_address, HashedStorage::from_iter(true, []))]), // destroyed
        })
        .unwrap();
    assert!(witness.contains_key(&state_root));
    for node in multiproof.account_subtree.values() {
        assert_eq!(witness.get(&keccak256(node)), Some(node));
    }
    for node in multiproof.storages.iter().flat_map(|(_, storage)| storage.subtree.values()) {
        assert_eq!(witness.get(&keccak256(node)), Some(node));
    }
}

#[test]
fn includes_nodes_for_destroyed_storage_nodes_2() {
    let factory = create_test_provider_factory();
    let provider = factory.provider_rw().unwrap();

    let address = Address::random();
    let hashed_address = keccak256(address);

    let slot = B256::random();
    let hashed_slot = keccak256(slot);

    // find two slots that have the same first byte when hashed (in the MPT trie)
    let (slot_2, hashed_slot_2) = {
        loop {
            let maybe_slot_2 = B256::random();
            let hashed_slot_2 = keccak256(maybe_slot_2);
            if Nibbles::unpack(hashed_slot).common_prefix_length(&Nibbles::unpack(hashed_slot_2)) == 0 // 0 always fails, 1 always passes
            {
                break (maybe_slot_2, hashed_slot_2)
            }
        }
    };

    // Insert account and slots into database
    provider.insert_account_for_hashing([(address, Some(Account::default()))]).unwrap();
    provider
        .insert_storage_for_hashing([(address, [StorageEntry { key: slot, value: U256::from(1) }, StorageEntry { key: slot_2, value: U256::from(2) }])])
        .unwrap();

    let witness = TrieWitness::from_tx(provider.tx_ref())
        .compute(HashedPostState {
            accounts: HashMap::from([(hashed_address, Some(Account::default()))]),
            storages: HashMap::from([(hashed_address, HashedStorage::from_iter(false, [(hashed_slot_2, U256::from(0))]))]), // destroyed
        })
        .unwrap();

    // rlp encode: [tagged_hashed_slot_2, 2] so we can check if the witness contains the correct value
    let tagged_hashed_slot: Vec<_> = Bytes::from(vec!(0x20u8)).into_iter().chain(hashed_slot.into_iter().skip(1)).collect();
    let mut rlp = Vec::new();
    alloy_rlp::encode_list::<Bytes, Bytes>(&[Bytes::from(tagged_hashed_slot), Bytes::from(vec!(1u8))], &mut rlp);

    // hash the result to find the MPT node hash
    let hash_storage_slot: alloy_primitives::FixedBytes<32> = keccak256(rlp.clone());

    // println!("hash_storage_slot: {:?}", hash_storage_slot);
    // println!("address: {:?}", address);
    // println!("rlp: {:?}", rlp.clone().into_iter().map(|b| format!("{:02x}", b)).collect::<String>());
    // println!("hashed_address: {:?}", hashed_address);
    // println!("hashed_slot_1: {:?}", hashed_slot);
    // println!("hashed_slot_2: {:?}", hashed_slot_2);
    // println!("witness: {:?}", witness);

    // ensure the witness contains the MPT node of the sibling of the node that was deleted
    assert_eq!(witness.get(&hash_storage_slot), Some(&rlp.into()));
}

#[test]
fn correctly_decodes_branch_node_values() {
    let factory = create_test_provider_factory();
    let provider = factory.provider_rw().unwrap();

    let address = Address::random();
    let hashed_address = keccak256(address);
    let hashed_slot1 = B256::with_last_byte(1);
    let hashed_slot2 = B256::with_last_byte(2);

    // Insert account and slots into database
    provider.insert_account_for_hashing([(address, Some(Account::default()))]).unwrap();
    let mut hashed_storage_cursor =
        provider.tx_ref().cursor_dup_write::<tables::HashedStorages>().unwrap();
    hashed_storage_cursor
        .upsert(hashed_address, StorageEntry { key: hashed_slot1, value: U256::from(1) })
        .unwrap();
    hashed_storage_cursor
        .upsert(hashed_address, StorageEntry { key: hashed_slot2, value: U256::from(1) })
        .unwrap();

    let state_root = StateRoot::from_tx(provider.tx_ref()).root().unwrap();
    let multiproof = Proof::from_tx(provider.tx_ref())
        .multiproof(HashMap::from_iter([(
            hashed_address,
            HashSet::from_iter([hashed_slot1, hashed_slot2]),
        )]))
        .unwrap();

    let witness = TrieWitness::from_tx(provider.tx_ref())
        .compute(HashedPostState {
            accounts: HashMap::from([(hashed_address, Some(Account::default()))]),
            storages: HashMap::from([(
                hashed_address,
                HashedStorage::from_iter(
                    false,
                    [hashed_slot1, hashed_slot2].map(|hashed_slot| (hashed_slot, U256::from(2))),
                ),
            )]),
        })
        .unwrap();
    assert!(witness.contains_key(&state_root));
    for node in multiproof.account_subtree.values() {
        assert_eq!(witness.get(&keccak256(node)), Some(node));
    }
    for node in multiproof.storages.iter().flat_map(|(_, storage)| storage.subtree.values()) {
        assert_eq!(witness.get(&keccak256(node)), Some(node));
    }
}
