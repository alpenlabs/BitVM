use std::collections::HashMap;

use ark_bn254::fq;
use ark_ff::{AdditiveGroup, BigInt, BigInteger, Field};

use crate::bigint::{BigIntImpl, U254, U256};
use crate::bn254;
use crate::bn254::fq2::Fq2;
use crate::chunk::blake3compiled::{hash_128b, hash_128b_compact, hash_192b, hash_192b_compact, hash_64b, hash_64b_compact};
use crate::pseudo::NMUL;
use crate::signatures::wots::{wots160, wots256};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

use super::wots::{wots_compact_checksig_verify_with_pubkey, WOTSPubKey};

pub(crate) type HashBytes = [u8; 64];

pub type Link = (u32, bool);

#[derive(Debug, Clone)]
pub enum SigData {
    Sig256(wots256::Signature),
    Sig160(wots160::Signature),
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub(crate) cache: HashMap<u32, SigData>,
}

pub(crate) fn tup_to_scr(sig: &mut Sig, tup: Vec<Link>) -> Script {
    let mut compact_bc_scripts = script!();
    if !sig.cache.is_empty() {
        for skey in tup {
            let bcelem = sig.cache.get(&skey.0).unwrap();
            let scr = match bcelem {
                SigData::Sig160(signature) => {
                    let s = script! {
                        for (sig, _) in signature {
                            { sig.to_vec() }
                        }
                    };
                    s
                }
                SigData::Sig256(signature) => {
                    let s = script! {
                        for (sig, _) in signature {
                            { sig.to_vec() }
                        }
                    };
                    s
                }
            };
            compact_bc_scripts = compact_bc_scripts.push_script(scr.compile());
        }        
    }
    compact_bc_scripts
}

pub(crate) fn wots_locking_script(link: Link, link_ids: &HashMap<u32, WOTSPubKey>) -> Script {
    wots_compact_checksig_verify_with_pubkey(link_ids.get(&link.0).unwrap())
}

pub(crate) fn gen_bitcom(
    link_ids: &HashMap<u32, WOTSPubKey>,
    // sec_out: Option<Link>,
    sec: Vec<Link>,
) -> Script {
    let mut tot_script = script!();
    // if sec_out.is_some() {
    //     tot_script = tot_script.push_script(wots_locking_script(sec_out.unwrap(), link_ids).compile());  // hash_in
    //     tot_script = tot_script.push_script({Fq::toaltstack()}.compile());
    // }
    // [px, py, qx0, qx1, qy0, qy1, in, out]
    for sec_in in sec {
        tot_script = tot_script.push_script(wots_locking_script(sec_in, link_ids).compile());  // hash_in
        tot_script = tot_script.push_script({Fq::toaltstack()}.compile());
    }
    tot_script
}

pub fn unpack_limbs_to_nibbles() -> Script {
    U256::transform_limbsize(29,4)
}

pub fn pack_nibbles_to_limbs() -> Script {
    U256::transform_limbsize(4,29)
}

// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb


pub(crate) fn hash_fp2() -> Script {
    script! {
        { hash_64b_compact() }
        { pack_nibbles_to_limbs() }
    }
}

pub(crate) fn hash_fp4() -> Script {
    script! {
        // [a0b0, a0b1, a1b0, a1b1]
        {Fq2::roll(2)}
        { hash_128b_compact() }
        { pack_nibbles_to_limbs() }
    }
}


pub(crate) fn extern_fq_to_nibbles(msg: ark_bn254::Fq) -> [u8; 64] {
    let v = fq_to_chunked_bits(msg.into(), 4);
    let vu8: Vec<u8> = v.iter().map(|x| (*x) as u8).collect();
    vu8.try_into().unwrap()
}

fn fq_to_chunked_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).collect();
    assert!(bits.len() == 256);
    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
                let res = chunk.iter().rev().fold(0, |acc, &x| {
                    let r = acc + if x { factor } else { 0 };
                    factor *= 2;
                    r
                });
                res
        })
        .collect()
}


pub(crate) fn extern_fr_to_nibbles(msg: ark_bn254::Fr) -> [u8; 64] {
    let v = fq_to_chunked_bits(msg.into(), 4);
    let vu8: Vec<u8> = v.iter().map(|x| (*x) as u8).collect();
    vu8.try_into().unwrap()
}

pub(crate) fn hash_fp12() -> Script {
    script! {
        for _ in 0..6 {
            {Fq::toaltstack()}
        }
        {hash_fp6()}

        // second part: Stack: [hash_first], Alt: [6 fps]
        for _ in 0..6 {
            {Fq::fromaltstack()}
        }
        {Fq::roll(6)} {Fq::toaltstack()}
        {hash_fp6()}

        // wrap up
        {Fq::fromaltstack()}
        {hash_64b_compact()}
        {pack_nibbles_to_limbs()}
    }
}


pub(crate) fn extern_nibbles_to_limbs(nibble_array: [u8; 64]) -> [u32; 9] {
    let bit_array: Vec<bool> = nibble_array
    .iter()
    .flat_map(|&nibble| (0..4).rev().map(move |i| (nibble >> i) & 1 != 0)) // Extract each bit
    .collect();

    let r: ark_ff::BigInt<4> = BigInt::from_bits_be(&bit_array);
    fn bigint_to_limbs(n: num_bigint::BigInt, n_bits: u32) -> Vec<u32> {
        const LIMB_SIZE: u64 = 29;
        let mut limbs = vec![];
        let mut limb: u32 = 0;
        for i in 0..n_bits as u64 {
            if i > 0 && i % LIMB_SIZE == 0 {
                limbs.push(limb);
                limb = 0;
            }
            if n.bit(i) {
                limb += 1 << (i % LIMB_SIZE);
            }
        }
        limbs.push(limb);
        limbs
    }

    let mut limbs = bigint_to_limbs(r.into(), 256);
    limbs.reverse();
    limbs.try_into().unwrap()
}

fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
    let mut msg_bytes = Vec::with_capacity(digits.len() / 2);

    for nibble_pair in digits.chunks(2) {
        let byte = (nibble_pair[0] << 4) | (nibble_pair[1] & 0b00001111);
        msg_bytes.push(byte);
    }

    fn le_to_be_byte_array(byte_array: Vec<u8>) -> Vec<u8> {
        assert!(byte_array.len() % 4 == 0, "Byte array length must be a multiple of 4");
        byte_array
            .chunks(4) // Process each group of 4 bytes (one u32)
            .flat_map(|chunk| chunk.iter().rev().cloned()) // Reverse each chunk
            .collect()
    }
    le_to_be_byte_array(msg_bytes)
}

fn replace_first_n_with_zero(hex_string: &str, n: usize) -> String {
    let mut result = String::new();

    if hex_string.len() <= n {
        result.push_str(&"0".repeat(hex_string.len())); // If n >= string length, replace all
    } else {
        result.push_str(&"0".repeat(n)); // Replace first n characters
        result.push_str(&hex_string[0..(hex_string.len()-n)]); // Keep the rest of the string
    }
    result
}

pub(crate) fn extern_hash_fps(fqs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
    let mut msgs: Vec<[u8; 64]> = Vec::new();
    for fq in fqs {
        let v = fq_to_chunked_bits(fq.into(), 4);
        let nib_arr: Vec<u8> = v.into_iter().map(|x| x as u8).collect();
        msgs.push(nib_arr.try_into().unwrap());
    }
    extern_hash_nibbles(msgs, mode)
}

pub(crate) fn extern_hash_nibbles(msgs: Vec<[u8; 64]>, mode: bool) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 6);

    fn hex_string_to_nibble_array(hex_string: &str) -> Vec<u8> {
        hex_string
            .chars()
            .map(|c| c.to_digit(16).expect("Invalid hex character") as u8) // Convert each char to a nibble
            .collect()
    }

    fn extern_hash_fp_var(fqs: Vec<[u8; 64]>) -> [u8;64] {
        let mut vs = Vec::new();
        for fq in fqs {
            let v = fq.to_vec();
            vs.extend_from_slice(&v);
        }
        let nib_arr: Vec<u8> = vs.clone().into_iter().map(|x| x as u8).collect();
        let p_bytes:Vec<u8> = nib_to_byte_array(&nib_arr);

        let hash_out = blake3::hash(&p_bytes).to_string();

        let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);
        let res = hex_string_to_nibble_array(&hash_out);
        res.try_into().unwrap()
    }



    fn extern_hash_fp12(fqs: Vec<[u8; 64]>) -> [u8;64] {
        let hash_out_first = extern_hash_fp6(fqs[0..6].to_vec());
        let mut hash_out_second = extern_hash_fp6(fqs[6..12].to_vec()).to_vec();
        hash_out_second.extend_from_slice(&hash_out_first);
        let p_bytes:Vec<u8> = nib_to_byte_array(&hash_out_second);
        let hash_out = blake3::hash(&p_bytes).to_string();
        let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);
        let hash_out = hex_string_to_nibble_array(&hash_out);
        hash_out.try_into().unwrap()
    }

    fn extern_hash_fp12_v2(fqs: Vec<[u8; 64]>) -> [u8;64] {
        let hash_out_first = extern_hash_fp_var(fqs[0..6].to_vec());
        let mut hash_out_second = extern_hash_fp_var(fqs[6..12].to_vec()).to_vec();
        hash_out_second.extend_from_slice(&hash_out_first);
        let p_bytes:Vec<u8> = nib_to_byte_array(&hash_out_second);
        let hash_out = blake3::hash(&p_bytes).to_string();
        let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);
        let hash_out = hex_string_to_nibble_array(&hash_out);
        hash_out.try_into().unwrap()
    }

    fn extern_hash_fp6(fqs: Vec<[u8; 64]>) -> [u8;64] {
        let hash_out_first = extern_hash_fp_var(fqs[0..2].to_vec());
        let mut hash_out_second = extern_hash_fp_var(fqs[2..6].to_vec()).to_vec();
        hash_out_second.extend_from_slice(&hash_out_first);
        let p_bytes:Vec<u8> = nib_to_byte_array(&hash_out_second);
        let hash_out = blake3::hash(&p_bytes).to_string();
        let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);
        let hash_out = hex_string_to_nibble_array(&hash_out);
        hash_out.try_into().unwrap()
    }


    if msgs.len() == 4 {
        extern_hash_fp_var(msgs)
    } else if msgs.len() == 12 {
        if mode {
            extern_hash_fp12(msgs)
        } else {
            extern_hash_fp12_v2(msgs)
        }
    } else if msgs.len() == 2 {
        extern_hash_fp_var(msgs)
    } else if msgs.len() == 6 {
        extern_hash_fp6(msgs)
    } else {
        panic!()
    }
}

pub(crate) fn new_hash_g2acc_with_hashed_le() -> Script {
    script! {
        //Stack: [tx, ty, hash_inaux]
        //T
        {Fq::toaltstack()} 
        {hash_fp4()} // HT

        {Fq::fromaltstack()}
        {hash_fp2()}
    }
}

pub(crate) fn new_hash_g2acc_with_both_raw_le() -> Script {
    script!(
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {hash_fp4()} 
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} // [HT, dbl_le]
        {Fq::roll(4)} {Fq::toaltstack()} // [dbl_le]
        {hash_fp4()} // [Hdbl_le]
        {Fq::fromaltstack()} // [Hdbl_le, HT]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} // [Hdbl_le, HT, add_le]
        {Fq2::roll(4)} {Fq2::toaltstack()} // [add_le]
        {hash_fp4()} // [Hadd_le]
        {Fq::fromaltstack()} // [Hadd_le, Hdbl_le]
        {Fq::roll(1)}
        {hash_fp2()} // [Hle]
        {Fq::fromaltstack()} // [Hle, HT]
        {Fq::roll(1)}
        {hash_fp2()} // [HTcacl]
    )
}

pub(crate) fn new_hash_g2acc_with_hashed_t(is_dbl: bool) -> Script {
    script!(

        //Stack: [cur_le, H_ale, H_at]
        {Fq2::toaltstack()}
        // [cur_le] [.., H_at, H_ale]
        {hash_fp4()} 
    
        {Fq::fromaltstack()}
        // [H_le, H_le]
        if !is_dbl {
            {Fq::roll(1)}
        }
        {hash_fp2()}
        // [Hle]
        {Fq::fromaltstack()}
        // [Hle, HT]
        {Fq::roll(1)}
        {hash_fp2()}
    )

}

pub(crate) fn hash_fp6() -> Script {
    script! {
        // [a, b, c]
        for _ in 0..4 {
            {Fq::toaltstack()}
        }

        // first part
        {hash_64b_compact()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        { Fq2::roll(2) }

        {Fq::roll(4)}
        {Fq::toaltstack()}
        { hash_128b_compact() }
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        {hash_64b_compact()}
        {pack_nibbles_to_limbs()}

    }
}

pub(crate) fn hash_fp12_192() -> Script {

    script! {
        for _ in 0..6 {
            {Fq::toaltstack()}
        }
        {Fq2::roll(2)} {Fq2::roll(4)}
        {hash_192b_compact()}
        {pack_nibbles_to_limbs()}

        for _ in 0..6 {
            { Fq::fromaltstack()}
        }
        {Fq::roll(6)}
        {Fq::toaltstack()}

        {Fq2::roll(2)} {Fq2::roll(4)}
        {hash_192b_compact()}
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        {hash_64b_compact()}
        {pack_nibbles_to_limbs()}
    }
}



// 6Fp_hash
// fp6
pub fn hash_fp12_with_hints() -> Script {
    script! {
        {Fq::toaltstack()} //Hc0
        {hash_fp6()}

        // wrap up
        {Fq::fromaltstack()}
        {hash_64b_compact()}
        {pack_nibbles_to_limbs()}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::{Field, UniformRand};
    use ark_std::iterable::Iterable;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::{
        bn254::utils::fq_push_not_montgomery, execute_script, u4::u4_std::u4_hex_to_nibbles
    };
    

    #[test]
    fn test_fq_from_nibbles() {
        // pack_nibbles_to_fq
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::Fq::rand(&mut prng);

        let nib32 = [15u8; 64];
        let script = script! {
             {fq_push_not_montgomery(ark_bn254::Fq::ONE)}
             {unpack_limbs_to_nibbles()}
             //{Fq::add(1, 0)}
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
    }

    #[test]
    fn test_emulator() {
        let repeat = 16;
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let mut nu32_arr: Vec<u32> = (0..repeat).into_iter().map(|_| prng.gen()).collect();
        nu32_arr.pop();
        nu32_arr.push(1);
        let blake3_in = nu32_arr.iter().flat_map(|i| (i).to_le_bytes()).collect::<Vec<_>>();
        let hash_out = blake3::hash(&blake3_in).to_string();

        fn replace_first_n_with_zero(hex_string: &str, n: usize) -> String {
            let mut result = String::new();
        
            if hex_string.len() <= n {
                result.push_str(&"0".repeat(hex_string.len())); // If n >= string length, replace all
            } else {
                result.push_str(&"0".repeat(n)); // Replace first n characters
                result.push_str(&hex_string[n..]); // Keep the rest of the string
            }
            result
        }
        let expected_hex_out = replace_first_n_with_zero(&hash_out, (32-20)*2);

        let bytes: Vec<u8> = nu32_arr
        .iter()
        .flat_map(|&word| word.to_be_bytes())
        .collect::<Vec<u8>>();

        fn bytes_to_nibbles(byte_array: Vec<u8>) -> Vec<u8> {
            byte_array
                .iter()
                .flat_map(|&byte| vec![(byte >> 4) & 0x0F, byte & 0x0F]) // Extract high and low nibbles
                .collect()
        }
        let hex_in = bytes_to_nibbles(bytes);
        println!("input msg {:?}", blake3_in);
        println!("hex msg {:?}", hex_in);

        let script = script! {
            for i in hex_in {
                {i}
            }
            { hash_64b() }
            { pack_nibbles_to_limbs() }
            { u4_hex_to_nibbles(&expected_hex_out)}
            {pack_nibbles_to_limbs()}
            {Fq::equalverify(1, 0)}
        };
        println!("expected hex_out {:?}", expected_hex_out);
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }

    }


    #[test]
    fn test_emulator2() {
        let mut prng = ChaCha20Rng::seed_from_u64(10);
        let p = ark_bn254::Fq::rand(&mut prng);
        let q = ark_bn254::Fq::rand(&mut prng);
        let mut p_nibs = fq_to_chunked_bits(p.into(), 4);
        let q_nibs = fq_to_chunked_bits(q.into(), 4);
        p_nibs.extend_from_slice(&q_nibs);
        
        let nib_arr: Vec<u8> = p_nibs.clone().into_iter().map(|x| x as u8).collect();
        let p_bytes:Vec<u8> = nib_to_byte_array(&nib_arr);

        let hash_out = blake3::hash(&p_bytes);

        fn replace_first_n_with_zero(hex_string: &str, n: usize) -> String {
            let mut result = String::new();
        
            if hex_string.len() <= n {
                result.push_str(&"0".repeat(hex_string.len())); // If n >= string length, replace all
            } else {
                result.push_str(&"0".repeat(n)); // Replace first n characters
                result.push_str(&hex_string[n..]); // Keep the rest of the string
            }
            result
        }
        let expected_hex_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);

        let script = script! {
            for i in p_nibs {
                {i}
            }
            { hash_64b() }
            { pack_nibbles_to_limbs() }
            { u4_hex_to_nibbles(&expected_hex_out)}
            {pack_nibbles_to_limbs()}
            {Fq::equalverify(1, 0)}
        };
        println!("expected hex_out {:?}", expected_hex_out);
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }

    }


    #[test]
    fn test_emulate_fq_to_nibbles() {
        let mut prng = ChaCha20Rng::seed_from_u64(1777);
        let p = ark_bn254::Fq::rand(&mut prng);
        pub(crate) fn emulate_fq_to_nibbles_scripted(msg: ark_bn254::Fq) -> [u8; 64] {
            let scr = script! {
                {fq_push_not_montgomery(msg)}
                {unpack_limbs_to_nibbles()}
            };
            let exec_result = execute_script(scr);
            let mut arr = [0u8; 64];
            for i in 0..exec_result.final_stack.len() {
                let v = exec_result.final_stack.get(i);
                if v.is_empty() {
                    arr[i] = 0;
                } else {
                    arr[i] = v[0];
                }
            }
            arr
        }
        let pb1 = extern_fq_to_nibbles(p);
        let pb2 = emulate_fq_to_nibbles_scripted(p);
        assert_eq!(pb1, pb2);
    }

    #[test]
    fn test_emulate_external_hash() {
        fn emulate_extern_hash_fps_scripted(msgs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
            assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 6);
            let scr = script! {
                for i in 0..msgs.len() {
                    {fq_push_not_montgomery(msgs[i])}
                }
                if msgs.len() == 4 {
                    {hash_fp4()}
                } else if msgs.len() == 12 {
                    if mode {
                        {hash_fp12()}
                    } else {
                        {hash_fp12_192()}
                    }
                } else if msgs.len() == 2 {
                    {hash_fp2()}
                } else if msgs.len() == 6 {
                    {hash_fp6()}
                }
                {unpack_limbs_to_nibbles()}
            };
            let exec_result = execute_script(scr);
            let mut arr = [0u8; 64];
            for i in 0..exec_result.final_stack.len() {
                let v = exec_result.final_stack.get(i);
                if v.is_empty() {
                    arr[i] = 0;
                } else {
                    arr[i] = v[0];
                }
            }
            arr
        }
    
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let _f = ark_bn254::Fq12::rand(&mut prng);
        let g = ark_bn254::Fq12::rand(&mut prng);

        let ps = g.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
        let res = emulate_extern_hash_fps_scripted(ps.clone(), false);
        let res2 = extern_hash_fps(ps, false);
        assert_eq!(res, res2);
    }

}


