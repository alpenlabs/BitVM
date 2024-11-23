use ark_ff::{BigInt, BigInteger};

use crate::bigint::U254;
use crate::bn254::fq::bigint_to_u32_limbs;
use crate::chunk::blake3compiled;
use crate::pseudo::NMUL;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use std::cmp::min;

use super::taps::HashBytes;

fn split_digit(window: u32, index: u32) -> Script {
    script! {
        // {v}
        0                           // {v} {A}
        OP_SWAP
        for i in 0..index {
            OP_TUCK                 // {v} {A} {v}
            { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
            OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
            OP_TUCK                 // {v} {1/0} {A} {1/0}
            OP_ADD                  // {v} {1/0} {A+1/0}
            if i < index - 1 { { NMUL(2) } }
            OP_ROT OP_ROT
            OP_IF
                { 1 << (window - i - 1) }
                OP_SUB
            OP_ENDIF
        }
        // OP_SWAP
    }
}

pub fn unpack_limbs_to_nibbles() -> Script {
    script! {
        {8}
        OP_ROLL
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-1 + 6}
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}

        {NMUL(8)}
        {8-2 + 6+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-3 + 6+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-4 + 6+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-5 + 6+8+7+7+7} //
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}

        {NMUL(8)}
        {8-6 + 6+8+7+7+7+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-7 + 6+8+7+7+7+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-8 + 6+8+7+7+7+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

    }
}

pub fn pack_nibbles_to_limbs() -> Script {
    fn split_digit(window: u32, index: u32) -> Script {
        script! {
            // {v}
            0                           // {v} {A}
            OP_SWAP
            for i in 0..index {
                OP_TUCK                 // {v} {A} {v}
                { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
                OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
                OP_TUCK                 // {v} {1/0} {A} {1/0}
                OP_ADD                  // {v} {1/0} {A+1/0}
                if i < index - 1 { { NMUL(2) } }
                OP_ROT OP_ROT
                OP_IF
                    { 1 << (window - i - 1) }
                    OP_SUB
                OP_ENDIF
            }
            OP_SWAP
        }
    }

    const WINDOW: u32 = 4;
    const LIMB_SIZE: u32 = 29;
    const N_BITS: u32 = U254::N_BITS;
    const N_DIGITS: u32 = (N_BITS + WINDOW - 1) / WINDOW;

    script! {
        for i in 1..64 { { i } OP_ROLL }
        for i in (1..=N_DIGITS).rev() {
            if (i * WINDOW) % LIMB_SIZE == 0 {
                OP_TOALTSTACK
            } else if (i * WINDOW) % LIMB_SIZE > 0 &&
                        (i * WINDOW) % LIMB_SIZE < WINDOW {
                OP_SWAP
                { split_digit(WINDOW, (i * WINDOW) % LIMB_SIZE) }
                OP_ROT
                { NMUL(1 << ((i * WINDOW) % LIMB_SIZE)) }
                OP_ADD
                OP_TOALTSTACK
            } else if i != N_DIGITS {
                { NMUL(1 << WINDOW) }
                OP_ADD
            }
        }
        for _ in 1..U254::N_LIMBS { OP_FROMALTSTACK }
        for i in 1..U254::N_LIMBS { { i } OP_ROLL }
    }
}

// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb

pub(crate) fn hash_fp2() -> Script {
    script! {
        { Fq::toaltstack() }
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { blake3compiled::hash_64b_75k() }
        { pack_nibbles_to_limbs() }
    }
}

pub(crate) fn hash_fp4() -> Script {
    script! {
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }

        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { blake3compiled::hash_128b_168k() }
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
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        // second part

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }


        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }

        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
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
        result.push_str(&hex_string[n..]); // Keep the rest of the string
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


pub(crate) fn hash_fp6() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        for _ in 0..5 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

    }
}

pub(crate) fn hash_fp12_192() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_192b_252k = blake3compiled::hash_192b_252k();

    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }
        {unpack_limbs_to_nibbles() }
        for _ in 0..5 {
            { Fq::fromaltstack()}
            {unpack_limbs_to_nibbles()}
        }
        {hash_192b_252k.clone()}
        {pack_nibbles_to_limbs()}

        for _ in 0..6 {
            { Fq::fromaltstack()}
            {unpack_limbs_to_nibbles()}
        }
        {hash_192b_252k}
        for _ in 0..9 {
            {64+8} OP_ROLL
        }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k}
        {pack_nibbles_to_limbs()}
    }
}

// 6Fp_hash
// fp6
pub fn hash_fp12_with_hints() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        {Fq::toaltstack()} //Hc0
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }

        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}

        // wrap up
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::{AdditiveGroup, BigInt, Field, UniformRand};
    use ark_std::iterable::Iterable;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::{
        bn254::utils::{fq_push_not_montgomery, fq_to_bits}, chunk, execute_script, u4::u4_std::u4_hex_to_nibbles
    };

    #[test]
    fn test_fq_from_nibbles() {
        // pack_nibbles_to_fq
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::Fq::rand(&mut prng);

        let mut nib32 = [15u8; 64];
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
            { blake3compiled::hash_64b_75k() }
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
            { blake3compiled::hash_64b_75k() }
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
    
        let mut prng = ChaCha20Rng::seed_from_u64(1777);
        let mut ps = vec![];
        for _ in 0..12 {
            let p = ark_bn254::Fq::rand(&mut prng);
            ps.push(p);
        }

        let res = emulate_extern_hash_fps_scripted(ps.clone(), false);
        let res2 = extern_hash_fps(ps, false);
       assert_eq!(res, res2);
    }


    #[test]
    fn test_this() {
        let mut prng = ChaCha20Rng::seed_from_u64(1777);
        let p = ark_bn254::Fq::rand(&mut prng);
        let pnib = extern_fq_to_nibbles(p);
        

        fn emulate_nibbles_to_limbs_scripted(msg: [u8; 64]) -> [u32; 9] {
            let scr = script! {
                for i in 0..msg.len() {
                    {msg[i]}
                }
                {pack_nibbles_to_limbs()}
            };
            let exec_result = execute_script(scr);
            let mut arr = [0u32; 9];
            for i in 0..exec_result.final_stack.len() {
                let v = exec_result.final_stack.get(i);
                let mut w: [u8; 4] = [0u8; 4];
                for j in 0..min(v.len(), 4) {
                    w[j] = v[j];
                }
                arr[i] = u32::from_le_bytes(w);
            }
            arr
        }



        let pu32 = extern_nibbles_to_limbs(pnib);
        let exp = emulate_nibbles_to_limbs_scripted(pnib);
        assert_eq!(pu32, exp);
    }
}
