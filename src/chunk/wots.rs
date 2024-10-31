use std::collections::HashMap;

use bitcoin_script::script;

use crate::chunk::primitves::{fq_from_nibbles, pack_nibbles_to_limbs};
use crate::treepp::Script;

// use crate::signatures::{winternitz, winternitz_compact, winternitz_compact_hash, winternitz_hash};
use crate::signatures::wots::{wots160, wots256};

use super::config::assign_link_ids;

pub(crate) fn wots_hash_sign_digits(secret_key: &str, message_digits: [u8; 40]) -> Vec<bitcoin_script::Script> {
    //winternitz_hash::sign_digits(secret_key, message_digits)
    wots160::sign2(secret_key, message_digits)
}

pub(crate) fn wots_sign_digits(secret_key: &str, message_digits: [u8; 64]) -> Vec<bitcoin_script::Script> {
    //winternitz::sign_digits(secret_key, message_digits)
    wots256::sign2(secret_key, message_digits)
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
        let sc_nib = wots160::checksig_verify(*pb);
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
        let sc_nib = wots256::checksig_verify(*pb);
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

    use ark_ff::{Field, UniformRand};
    use bitcoin::opcodes::{all::OP_ROLL, OP_TRUE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, utils::fq_push_not_montgomery}, chunk::primitves::{emulate_extern_hash_fps, emulate_extern_hash_nibbles, emulate_fq_to_nibbles, unpack_limbs_to_nibbles}, execute_script, signatures::{self, wots::{wots256, wots32}}};


    #[test]
    fn test_wots_fq() {
            // runtime
            let mut prng = ChaCha20Rng::seed_from_u64(0);
            let f = ark_bn254::Fq::rand(&mut prng);
            let secret = "a01b23c45d67e89f";
            let public_key = wots256::generate_public_key(&secret);

            let fnib = emulate_fq_to_nibbles(f);

            let sigs = {wots_sign_digits(&secret, fnib)};
            let mut compact_sig = script! {};
            for i in 0..sigs.len() {
                if i % 2 == 0 {
                    compact_sig = compact_sig.push_script(sigs[i].clone().compile());
                }
            }
            let script = script!{
                {compact_sig}
                {wots_compact_checksig_verify_with_pubkey(&WOTSPubKey::P256(public_key))}
                {fq_push_not_montgomery(f)}
                {Fq::equalverify(1,0)}
                OP_TRUE
            };
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
            assert!(res.success);

            let script = script!{
                for sig in sigs {
                    {sig}
                }
                {wots_checksig_verify_with_pubkey(&WOTSPubKey::P256(public_key))}
                {fq_push_not_montgomery(f)}
                {Fq::equalverify(1,0)}
                OP_TRUE
            };
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
            assert!(res.success);
    }

}