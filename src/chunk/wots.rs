use std::collections::HashMap;

use bitcoin_script::script;

use crate::chunk::primitves::{fq_from_nibbles, pack_nibbles_to_limbs};
use crate::treepp::Script;

// use crate::signatures::{winternitz, winternitz_compact, winternitz_compact_hash, winternitz_hash};
use crate::signatures::wots::{wots160, wots256};

use super::config::assign_link_ids;

pub(crate) fn wots_hash_sign_digits(secret_key: &str, message_digits: [u8; 40]) -> Vec<bitcoin_script::Script> {
    //winternitz_hash::sign_digits(secret_key, message_digits)
    //wots160::sign2(secret_key, &message_digits)
    vec![wots160::sign(secret_key, &message_digits)]
}

pub(crate) fn wots_sign_digits(secret_key: &str, message_digits: [u8; 64]) -> Vec<bitcoin_script::Script> {
    //winternitz::sign_digits(secret_key, message_digits)
    //wots256::sign2(secret_key, &message_digits)
    vec![wots256::sign(secret_key, &message_digits)]
}

pub(crate) fn wots_compact_get_pub_key(secret_key: &str) -> WOTSPubKey {
    //winternitz_compact::get_pub_key(secret_key)
    WOTSPubKey::P256(wots256::generate_public_key(secret_key))
}

pub(crate) fn wots_compact_hash_get_pub_key(secret_key: &str) -> WOTSPubKey {
    //winternitz_compact_hash::get_pub_key(secret_key)
    WOTSPubKey::P160(wots160::generate_public_key(secret_key))
}

pub(crate) fn wots_compact_hash_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    if let WOTSPubKey::P160(pb) = pub_key {
        let sc_nib = wots160::compact::checksig_verify(*pb);
        const N0: usize = 40;
        return script!{
            {sc_nib}
            for _ in 0..(64-N0) {
                {0}
            }
            // field element reconstruction
            for i in 1..64 {
                {i} OP_ROLL
            }
    
            {fq_from_nibbles()}
        }
    }
    panic!()
}

pub(crate) fn wots_compact_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    if let WOTSPubKey::P256(pb) = pub_key {
        let sc_nib = wots256::compact::checksig_verify(*pb);
        return script!{
            {sc_nib}
            // field element reconstruction
            for i in 1..64 {
                {i} OP_ROLL
            }
            {fq_from_nibbles()}
        }
    }
    panic!()
}

fn wots_hash_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    if let WOTSPubKey::P160(pb) = pub_key {
        let sc_nib = wots160::compact::checksig_verify(*pb);
        const N0: usize = 40;
        return script!{
            {sc_nib}
            for _ in 0..(64-N0) {
                {0}
            }
            // field element reconstruction
            for i in 1..64 {
                {i} OP_ROLL
            }
    
            {fq_from_nibbles()}
        }
    }
    panic!()
}

fn wots_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    if let WOTSPubKey::P256(pb) = pub_key {
        let sc_nib = wots256::compact::checksig_verify(*pb);
        return script!{
            {sc_nib}
            // field element reconstruction
            for i in 1..64 {
                {i} OP_ROLL
            }
            {fq_from_nibbles()}
        }
    }
    panic!()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WOTSPubKey {
    P160(wots160::PublicKey),
    P256(wots256::PublicKey)
}

impl WOTSPubKey {
    pub(crate) fn serialize(&self) -> Vec<Vec<u8>> {
        match self {
            WOTSPubKey::P160(p) => {
                let mut v = Vec::new();
                for i in p {
                    v.push(i.to_vec());
                }
                v
            },
            WOTSPubKey::P256(p) => {
                let mut v = Vec::new();
                for i in p {
                    v.push(i.to_vec());
                }
                v
            }
        }
    }

    pub(crate) fn deserialize(ser: Vec<Vec<u8>>) -> Option<Self> {
        if ser.len() == 67 {
            let mut ps: [[u8;20]; 67] = [[0u8;20];67];
            for pi in 0..ser.len() {
                let en:[u8;20] = ser[pi].clone().try_into().unwrap();
                ps[pi] = en;
            }
        } else if ser.len() == 43 {
            let mut ps: [[u8;20]; 43] = [[0u8;20];43];
            for pi in 0..ser.len() {
                let en:[u8;20] = ser[pi].clone().try_into().unwrap();
                ps[pi] = en;
            }
        }
        None
    }
}

pub struct AssertPublicKeys {
    pub p160: HashMap<u32, wots160::PublicKey>,
    pub p256: HashMap<u32, wots256::PublicKey>,
}

pub fn generate_verifier_public_keys(msk: &str) -> AssertPublicKeys {
    let (links, _, _) = assign_link_ids();
    let mut p160 = HashMap::new();
    let mut p256 = HashMap::new();

    for i in 0..links.len() as u32 {
        if i < 32 {
            let public_key = wots256::generate_public_key(&format!("{msk}{i:04X}"));
            p256.insert(i, public_key);
        } else {
            let public_key = wots160::generate_public_key(&format!("{msk}{i:04X}"));
            p160.insert(i, public_key);
        }
    }
    AssertPublicKeys { p160, p256 }
}

pub fn generate_disprover_script_public_keys(apk: &AssertPublicKeys) -> Vec<Script> {
    let mut spks = Vec::new();
    for (_, &public_key) in &apk.p256 {
        spks.push(wots256::compact::checksig_verify(public_key));
    }
    for (_, &public_key) in &apk.p160 {
        spks.push(wots160::compact::checksig_verify(public_key));
    }
    spks
}

pub fn generate_assertion_script_public_keys(apk: &AssertPublicKeys) -> Vec<Script> {
    let mut spks = Vec::new();
    for (_, &public_key) in &apk.p256 {
        spks.push(wots256::checksig_verify(public_key));
    }
    for (_, &public_key) in &apk.p160 {
        spks.push(wots160::checksig_verify(public_key));
    }
    spks
}

pub fn generate_assertion_spending_key_lengths(apk: &AssertPublicKeys) -> Vec<usize> {
    let mut spks = Vec::new();
    for (_, &public_key) in &apk.p256 {
        spks.push(
            wots256::sign(
                "00",
                &vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )
            .len(),
        );
    }
    for (_, &public_key) in &apk.p160 {
        spks.push(
            wots160::sign(
                "00",
                &vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )
            .len(),
        );
    }
    spks
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{execute_script, signatures::{self, wots::{wots256, wots32}}};

    #[test]
    fn test_wots256() {
        let secret = "a01b23c45d67e89f";
        let public_key = wots256::generate_public_key(&secret);

        const MESSAGE: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4,
        ];
        let msg_bytes = MESSAGE.to_vec();

        let script = script! {
            { wots256::compact::sign(&secret, &msg_bytes) }
            { wots256::compact::checksig_verify(public_key) }

            for i in (0..8).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }

            { wots256::sign(&secret, &msg_bytes) }
            { wots256::checksig_verify(public_key) }

            for _ in 0..8 {
                OP_FROMALTSTACK OP_EQUALVERIFY
            }

            OP_TRUE
        };

        println!(
            "wots32: sig={}, csv={}",
            wots256::sign(&secret, &msg_bytes).len(),
            wots256::checksig_verify(public_key).len()
        );

        println!(
            "wots32:compact: sig={}, csv={}",
            wots256::compact::sign(&secret, &msg_bytes).len(),
            wots256::compact::checksig_verify(public_key).len()
        );

        let res = execute_script(script);
        assert!(res.success);
    }

    
    #[test]
    fn test_winternitz_old() {
        const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        const MESSAGE: [u8; 64 as usize] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4,
        ];


        let public_key = signatures::winternitz::generate_public_key(MY_SECKEY);
    
        let wots_pub_key = wots256::generate_public_key(MY_SECKEY);

        let signed_digits = signatures::winternitz::sign_digits(MY_SECKEY, MESSAGE);
        let wots_signed_digits = wots256::sign(MY_SECKEY, &MESSAGE);

        let script = script!{
            {signed_digits}
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }


        let script = script!{
            {wots_signed_digits}
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }

    }
}