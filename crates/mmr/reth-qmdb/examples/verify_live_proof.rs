//! Verify live QMDB keyed proofs as MMR inclusion proofs.
//!
//! Usage:
//!   cargo run -p reth-qmdb --example verify_live_proof -- <qmdb-path> <address> [rpc-url]

use alloy_primitives::{keccak256, Address, B256};
use reth_mmr::{b256_to_digest, digest_to_b256, Digest};
use reth_qmdb::{account_key, Operation, Qmdb};
use std::{env, process::Command, str::FromStr, thread, time::Duration};

fn main() {
    let mut args = env::args().skip(1);
    let path = args.next().expect("usage: verify_live_proof <qmdb-path> <address> [rpc-url]");
    let addr = Address::from_str(&args.next().expect("address")).expect("bad address");
    let rpc = args.next();

    let db = Qmdb::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let root = db.root().expect("root");
    let root_b256 = digest_to_b256(&root);
    let key = account_key(keccak256(addr));
    let proof = db.prove_key(&key).unwrap_or_else(|e| panic!("prove_key: {e}"));

    assert_eq!(proof.root, root, "proof root != db root");
    assert!(
        Qmdb::verify_key_proof(&key, &proof, &root),
        "MMR verify_key_proof FAILED for {addr}"
    );

    // Negative check: corrupt one digest → verify must fail.
    let mut bad = proof.clone();
    if let Some(d) = bad.proof.digests.first_mut() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(d.as_ref());
        bytes[0] ^= 0xff;
        *d = Digest::from(bytes);
        assert!(
            !Qmdb::verify_key_proof(&key, &bad, &root),
            "corrupted proof unexpectedly verified"
        );
    }

    let digest_b256s: Vec<B256> =
        proof.proof.digests.iter().map(|d| B256::from_slice(d.as_ref())).collect();

    println!("qmdb_path={path}");
    println!("address={addr}");
    println!("leaves={}", db.len());
    println!("location={}", *proof.location);
    println!("root={root_b256}");
    println!("account_proof_len={}", digest_b256s.len());
    print!("digests=");
    for (i, d) in digest_b256s.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{d}");
    }
    println!();
    println!("MMR_VERIFY=ok");
    println!("MMR_VERIFY_NEGATIVE=ok");

    match &proof.operation {
        Operation::Update { value, .. } => {
            assert_eq!(value.len(), 72, "account value encoding");
            let nonce = u64::from_be_bytes(value[0..8].try_into().unwrap());
            let balance = alloy_primitives::U256::from_be_slice(&value[8..40]);
            let code_hash = B256::from_slice(&value[40..72]);
            println!("leaf_nonce={nonce}");
            println!("leaf_balance={balance}");
            println!("leaf_code_hash={code_hash}");
        }
        other => panic!("expected Update op, got {other:?}"),
    }

    assert!(Qmdb::verify_key_proof(&key, &proof, &b256_to_digest(root_b256)));
    println!("VERIFY_AGAINST_B256_ROOT=ok");

    let Some(rpc) = rpc else {
        return;
    };

    // eth_getProof only carries digests (no location/leaves). Cross-check digests when the
    // RPC tip root still equals this frozen on-disk root.
    for attempt in 0..40 {
        let out = Command::new("cast")
            .args(["proof", "--rpc-url", &rpc, &format!("{addr}"), "--json"])
            .output()
            .expect("cast proof");
        assert!(out.status.success(), "cast proof failed: {}", String::from_utf8_lossy(&out.stderr));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        let storage_hash = B256::from_str(v["storageHash"].as_str().unwrap()).unwrap();
        if storage_hash != root_b256 {
            eprintln!("rpc attempt {attempt}: tip moved storageHash={storage_hash}");
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        let rpc_digests: Vec<B256> = v["accountProof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| B256::from_str(x.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(rpc_digests, digest_b256s, "eth_getProof digests != prove_key digests");

        let nonce = parse_u64_hexish(&v["nonce"]);
        let balance = alloy_primitives::U256::from_str(v["balance"].as_str().unwrap()).unwrap();
        let code_hash = B256::from_str(v["codeHash"].as_str().unwrap()).unwrap();
        match &proof.operation {
            Operation::Update { value, .. } => {
                let n = u64::from_be_bytes(value[0..8].try_into().unwrap());
                let bal = alloy_primitives::U256::from_be_slice(&value[8..40]);
                let ch = B256::from_slice(&value[40..72]);
                assert_eq!(n, nonce);
                assert_eq!(bal, balance);
                assert_eq!(ch, code_hash);
            }
            _ => unreachable!(),
        }
        println!("eth_getProof.storageHash={storage_hash}");
        println!("ETH_GETPROOF_DIGESTS_MATCH=ok");
        println!("ETH_GETPROOF_ACCOUNT_FIELDS_MATCH=ok");
        return;
    }
    panic!("could not match eth_getProof storageHash to frozen disk root (sequencer too fast)");
}

fn parse_u64_hexish(v: &serde_json::Value) -> u64 {
    if let Some(s) = v.as_str() {
        let s = s.strip_prefix("0x").unwrap_or(s);
        return u64::from_str_radix(s, 16).expect("nonce hex");
    }
    v.as_u64().expect("nonce")
}
