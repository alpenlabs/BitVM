
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{ fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine, new_hinted_from_eval_point};
use crate::pseudo::NMUL;
use crate::signatures::winternitz_compact::checksig_verify_fq;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::bn::{G1Prepared, G2Prepared};
use ark_ec::pairing::Pairing;
use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use bitcoin::opcodes::all::{OP_ENDIF, OP_NUMEQUAL};
use bitcoin::ScriptBuf;
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::min;
use std::fs::File;
use std::io::{self, Read};
use std::ops::Neg;
use std::str::FromStr;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use num_traits::One;

use super::utils::Hint;


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

    script!{
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
    let n_limbs = 9;
    script!{
        {58} OP_ROLL
        {59} OP_ROLL
        {60} OP_ROLL
        {61} OP_ROLL
        {62} OP_ROLL
        {63} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        OP_TOALTSTACK

        {50} OP_ROLL
        {51} OP_ROLL
        {52} OP_ROLL
        {53} OP_ROLL
        {54} OP_ROLL
        {55} OP_ROLL
        {56} OP_ROLL
        {57} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(2)}
        OP_SWAP
        {split_digit(4, 1)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {43} OP_ROLL
        {44} OP_ROLL
        {45} OP_ROLL
        {46} OP_ROLL
        {47} OP_ROLL
        {48} OP_ROLL
        {49} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(4)}
        OP_SWAP
        {split_digit(4, 2)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {36} OP_ROLL
        {37} OP_ROLL
        {38} OP_ROLL
        {39} OP_ROLL
        {40} OP_ROLL
        {41} OP_ROLL
        {42} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(8)}
        OP_SWAP
        {split_digit(4, 3)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {29} OP_ROLL
        {30} OP_ROLL
        {31} OP_ROLL
        {32} OP_ROLL
        {33} OP_ROLL
        {34} OP_ROLL
        {35} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        OP_TOALTSTACK

        {21} OP_ROLL
        {22} OP_ROLL
        {23} OP_ROLL
        {24} OP_ROLL
        {25} OP_ROLL
        {26} OP_ROLL
        {27} OP_ROLL
        {28} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(2)}
        OP_SWAP
        {split_digit(4, 1)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {14} OP_ROLL
        {15} OP_ROLL
        {16} OP_ROLL
        {17} OP_ROLL
        {18} OP_ROLL
        {19} OP_ROLL
        {20} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(4)}
        OP_SWAP
        {split_digit(4, 2)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {7} OP_ROLL
        {8} OP_ROLL
        {9} OP_ROLL
        {10} OP_ROLL
        {11} OP_ROLL
        {12} OP_ROLL
        {13} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(8)}
        OP_SWAP
        {split_digit(4, 3)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {1} OP_ROLL
        {2} OP_ROLL
        {3} OP_ROLL
        {4} OP_ROLL
        {5} OP_ROLL
        {6} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD

        for i in 1..n_limbs {
            OP_FROMALTSTACK
        }
        for i in 1..n_limbs {
            {i} OP_ROLL
        }
    }

}

pub fn read_script_from_file(file_path: &str) -> Script {
    fn read_file_to_bytes(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut all_script_bytes = Vec::new();
        file.read_to_end(&mut all_script_bytes)?;
        Ok(all_script_bytes)
    }
    //let file_path = "blake3_bin/blake3_192b_252k.bin"; // Replace with your file path
    let all_script_bytes = read_file_to_bytes(file_path).unwrap();
    let scb = ScriptBuf::from_bytes(all_script_bytes);
    let sc = script!();
    let sc = sc.push_script(scb);
    sc
}

// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb

pub(crate) fn hash_fp2() -> Script {
    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    script!{
        { Fq::toaltstack() }
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { hash_64b_75k }
        { pack_nibbles_to_limbs() }
    }   
}

pub(crate) fn hash_fp4() -> Script {
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");
    script!{
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
        { hash_128b_168k }
        { pack_nibbles_to_limbs() }
    }   
}

// msg to nibbles
pub(crate) fn emulate_extern_hash_fps(msgs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 6);
    let scr = script!{
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

pub(crate) fn emulate_extern_hash_nibbles(msgs: Vec<[u8;64]>) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12);
    let scr = script!{
        for i in 0..msgs.len() {
            for j in 0..msgs[i].len() {
                {msgs[i][j]}
            }
            {pack_nibbles_to_limbs()} // pack only to unpack later, inefficient but ok for being emulated
        }
        if msgs.len() == 4 {
            {hash_fp4()}
        } else if msgs.len() == 12 {
            {hash_fp12()}
        } else if msgs.len() == 2 {
            {hash_fp2()}
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



pub(crate) fn emulate_fq_to_nibbles(msg: ark_bn254::Fq) -> [u8;64] {
    let scr = script!{
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

pub(crate) fn emulate_nibbles_to_limbs(msg: [u8;64]) -> [u32;9] {
    let scr = script!{
        for i in 0..msg.len() {
            {msg[i]}
        }
        {pack_nibbles_to_limbs()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u32; 9];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        let mut w: [u8;4] = [0u8;4];
        for j in 0..min(v.len(), 4) {
            w[j] = v[j];
        }
        arr[i] = u32::from_le_bytes(w);
    }
    arr
}

pub(crate) fn hash_fp12() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
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


pub(crate) fn hash_fp6() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
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
    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_192b_252k = read_script_from_file("blake3_bin/blake3_192b_252k.bin");
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

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
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

