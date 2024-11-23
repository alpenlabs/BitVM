use std::collections::HashMap;

use bitcoin_script::script;

use crate::chunk::primitves::{pack_nibbles_to_limbs};
use crate::treepp::Script;

// use crate::signatures::{winternitz, winternitz_compact, winternitz_compact_hash, winternitz_hash};
use crate::signatures::wots::{wots160, wots256};

use super::config::{assign_link_ids, NUM_PUBS, NUM_U160, NUM_U256};

// pub(crate) fn wots_p160_sign_digits(secret_key: &str, message_digits: [u8; 40]) -> Vec<bitcoin_script::Script> {
//     //winternitz_hash::sign_digits(secret_key, message_digits)
//     wots160::sign2(secret_key, message_digits)
// }

// pub(crate) fn wots_p256_sign_digits(secret_key: &str, message_digits: [u8; 64]) -> Vec<bitcoin_script::Script> {
//     //winternitz::sign_digits(secret_key, message_digits)
//     wots256::sign2(secret_key, message_digits)
// }

pub(crate) fn wots_p256_get_pub_key(secret_key: &str) -> WOTSPubKey {
    //winternitz_compact::get_pub_key(secret_key)
    WOTSPubKey::P256(wots256::generate_public_key(secret_key))
}

pub(crate) fn wots_p160_get_pub_key(secret_key: &str) -> WOTSPubKey {
    //winternitz_compact_hash::get_pub_key(secret_key)
    WOTSPubKey::P160(wots160::generate_public_key(secret_key))
}

pub(crate) fn wots_compact_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::P160(pb) => {
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
        
                {pack_nibbles_to_limbs()}
            }
        },
        WOTSPubKey::P256(pb) => {
            let sc_nib = wots256::compact::checksig_verify(*pb);
            return script!{
                {sc_nib}
                // field element reconstruction
                for i in 1..64 {
                    {i} OP_ROLL
                }
                {pack_nibbles_to_limbs()}
            }
        },
    }
}



fn wots_checksig_verify_with_pubkey(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::P160(pb) => {
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
        
                {pack_nibbles_to_limbs()}
            }
        },
        WOTSPubKey::P256(pb) => {
            let sc_nib = wots256::checksig_verify(*pb);
            return script!{
                {sc_nib}
                // field element reconstruction
                for i in 1..64 {
                    {i} OP_ROLL
                }
                {pack_nibbles_to_limbs()}
            }
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WOTSPubKey {
    P160(wots160::PublicKey),
    P256(wots256::PublicKey)
}
pub struct AssertPublicKeys {
    pub p160: HashMap<u32, wots160::PublicKey>,
    pub p256: HashMap<u32, wots256::PublicKey>,
}

pub fn generate_verifier_public_keys(msk: &str) -> AssertPublicKeys {
    let (links, _, _) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
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

    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_std::test_rng;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::{chunk::primitves::extern_fq_to_nibbles, signatures::wots::wots256};

// 0110 0100
// 0011 1100 0000
    #[test]
    fn test_nib() {
        let secret = "a01b23c45d67e89f";
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq::from(100);
        let mut fb = extern_fq_to_nibbles(f);
        println!("fb {:?}", fb);
        let sig = wots256::get_signature(secret, &fb);  
        let mut bs = vec![]; 
        for (a, b) in sig {
            bs.push(b);
        }
        println!("bs {:?}", bs);
        // let r = from_wots_signature(sig);
        // println!("f {:?}", f);
        // println!("r {:?}", r);
    }

    fn from_wots_signature<F: ark_ff::PrimeField>(
        signature: wots256::Signature,
        public_key: wots256::PublicKey,
    ) -> F {
        let nibbles = &signature.map(|(sig, digit)| digit)[0..wots256::M_DIGITS as usize];
        let bytes = nibbles
            .chunks(2)
            .rev()
            .map(|bn| (bn[0] << 4) + bn[1])
            .collect::<Vec<u8>>();
        F::from_le_bytes_mod_order(&bytes)
    }

    #[test]
    fn test_fq_from_wots_signature() {
        // let secret = "0011";

        // let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // let fq = ark_bn254::Fq::ONE;
        // let fqnib = emulate_fq_to_nibbles(fq);
        // let fqr = nib_to_byte_array(&fqnib);
        // let public_key = wots256::generate_public_key(secret);
        // let signature = wots256::get_signature(secret, &fqr);
        // let nibbles = &signature.map(|(sig, digit)| digit)[0..wots256::M_DIGITS as usize];
        // println!("{:?}", fqr);
        // println!("{:?}", nibbles);
        // let fq_s = from_wots_signature::<ark_bn254::Fq>(signature, public_key);
        // println!("{:?}", fq_s);
        // assert_eq!(fq, fq_s);

        // let fr = ark_bn254::Fr::ONE;
        // let public_key = wots256::generate_public_key(secret);
        // let signature = wots256::get_signature(secret, &fr.into_bigint().to_bytes_le());
        // let fr_s = from_wots_signature::<ark_bn254::Fr>(signature, public_key);
        // assert_eq!(fr, fr_s);
    }


    #[test]
    fn test_em1() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let fq = ark_bn254::Fq::from(280);
        let fq2 = fq.into_bigint().to_bytes_le();
        let fqs = extern_fq_to_nibbles(fq);
        println!("fqs {:?}", fqs);
        println!("fqs {:?}", fq2);
    }
    

    #[test]
    fn test_emq() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let fq = ark_bn254::Fq::rand(&mut rng);
        // let mut fqb = fq.into_bigint().to_bytes_le();
        // fqb.reverse();
        // println!("fqb {:?}", fqb);

        // let nibs = emulate_fq_to_nibbles(fq);
        // println!("nibs {:?}", nibs);

        let fq = ark_bn254::Fq::rand(&mut rng);
        let fqb = fq.into_bigint().to_bytes_le();
        let secret = "0011";
        let signature = wots256::get_signature(secret, &fq.into_bigint().to_bytes_le());
        let nibbles = &signature.map(|(sig, digit)| digit)[0..wots256::M_DIGITS as usize];
        println!("fqb {:?}", nibbles);

        let nibs = extern_fq_to_nibbles(fq);
        println!("nibs {:?}", nibs);
    }
}