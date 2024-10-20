
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{ fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine, new_hinted_from_eval_point};
use crate::pseudo::NMUL;
use crate::signatures::winternitz_compact::checksig_verify_fq;
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use bitcoin::ScriptBuf;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::min;
use std::fs::File;
use std::io::{self, Read};
use std::ops::Neg;
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

fn hash_fp2() -> Script {
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

fn hash_fp4() -> Script {
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
fn emulate_extern_hash_fps(msgs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
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

fn emulate_extern_hash_nibbles(msgs: Vec<[u8;64]>) -> [u8; 64] {
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



fn emulate_fq_to_nibbles(msg: ark_bn254::Fq) -> [u8;64] {
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

fn emulate_nibbles_to_limbs(msg: [u8;64]) -> [u32;9] {
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

pub fn hash_fp12() -> Script {

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


pub fn hash_fp6() -> Script {

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

pub fn hash_fp12_192() -> Script {
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



// SQUARING
fn hints_squaring(a: ark_bn254::Fq12)-> Vec<Hint> {
    let (_, hints) = Fq12::hinted_square(a);
    hints
}

pub(crate) fn tap_squaring(sec_key: &str, sec_out: u32, sec_in: Vec<u32>)-> Script {
    assert_eq!(sec_in.len(), 1);
    let (sq_script, _) = Fq12::hinted_square(ark_bn254::Fq12::ONE);
    let bitcomms_sc = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
    };
    let hash_sc  = script!{
        { hash_fp12() } // Hash(b)
        { Fq::fromaltstack() } // hash_b
        { Fq::equalverify(1, 0)} // NOTE: WE SHOULD BE SHOWING INEQUALITY, WILL DO LATER
        { hash_fp12() } // Hash(a)
        { Fq::fromaltstack() } // hash_a
        { Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_sc}
        {sq_script}
        {hash_sc}
        OP_TRUE
    };
    sc
}


// POINT DBL
pub(crate) fn tap_point_dbl(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    
    assert_eq!(sec_in.len(), 3);
    let (hinted_double_line, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_tangent, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let ops_script = script! {
        // { fq2_push_not_montgomery(alpha_tangent)}
        // { fq2_push_not_montgomery(bias_minus_tangent)}
        // { fq2_push_not_montgomery(t.x) }
        // { fq2_push_not_montgomery(t.y) }
        // { fq_push_not_montgomery(aux_hash) } 

        // {hash_aux}

        // { fq_push_not_montgomery(p_dash_x) }
        // { fq_push_not_montgomery(p_dash_y) }

        // { hash_in } // hash
        // { hash_out_claim } // hash
       
        // move aux hash to MOVE_AUX_HASH_HERE
        {Fq::toaltstack()} // hash out
        {Fq::toaltstack()} // hash in
        {Fq::roll(2)}
        {Fq::toaltstack()} // hash aux in

        //[a, b, tx, ty, px, py]
        { Fq2::copy(8)} // alpha
        { Fq2::copy(8)} // bias
        { Fq2::copy(8)} // t.x
        { Fq2::copy(8)} // t.y
        { hinted_check_tangent }

        //[a, b, tx, ty, px, py]
        { Fq2::copy(8) } // alpha
        { Fq2::copy(8) } // bias
        { Fq2::roll(4) } // p_dash
        { hinted_ell_tangent }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1

        //[a, b, tx, ty]
        { Fq2::roll(4)} // bias
        //[a, tx, ty, b]
        { Fq2::roll(6)} // alpha
        //[tx, ty, b, a]
        { Fq2::copy(6)} // t.x
        //[tx, ty, b, a, tx]
        { hinted_double_line } // R
        // [t, R]

        { Fq2::fromaltstack() } // le.0
        { Fq2::fromaltstack() } // le.1
        // [t, R, le]

        // Altstack: [hash_out, hash_in, hash_inaux]
        // Stack: [t, R, le]
    };

    let hash_script = script!{
        //Altstack: [hash_out, hash_in, hash_inaux]
        //Stack: [tx, ty, Rx, Ry, le0, le1]
        //T
        {Fq2::roll(10)}
        {Fq2::roll(10)}

        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        //{pack_nibbles_to_limbs()}
        //[T, R, le]

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}

        // // [HashOut]
        // // [Rx, Ry, le0, le1]

        {Fq2::roll(6)}
        {Fq2::roll(6)}
        // // [HashOut]
        // // [le, R]
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // // [HashOut, HashR]
        // // [le]
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        // // [HashOut, HashR]
        // // [Hashle]
        for _ in 0..64 {
            {0}
        }
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        // // [HashOut]
        // // [Hashle, HashR]
        {unpack_limbs_to_nibbles()}
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
    };

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // pdash_x

        {Fq::fromaltstack()} // py
        {Fq::fromaltstack()} // in
        {Fq::fromaltstack()} // out
        // [x, y, in, out]
    };


    let sc = script!{
        {bitcomms_script.clone()}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

fn hint_point_dbl(t: ark_bn254::G2Affine, p:ark_bn254::G1Affine) -> (Vec<Hint>, [ark_bn254::Fq2; 2],[ark_bn254::Fq2; 4]) {
    // let mut prng = ChaCha20Rng::seed_from_u64(0);
    // let t = ark_bn254::G2Affine::rand(&mut prng);
    // let q = ark_bn254::G2Affine::rand(&mut prng);
    // let p = ark_bn254::g1::G1Affine::rand(&mut prng);

    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_tangent = t.x.square();
    alpha_tangent /= t.y;
    alpha_tangent.mul_assign_by_fp(&three_div_two);
    // -bias
    let bias_minus_tangent = alpha_tangent * t.x - t.y;

    let x = alpha_tangent.square() - t.x.double();
    let y = bias_minus_tangent - alpha_tangent * x;
    let (_, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();


    // affine mode as well
    let mut c1new = alpha_tangent;
    c1new.mul_assign_by_fp(&(-p.x / p.y));

    let mut c2new = bias_minus_tangent;
    c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);

    let mut all_qs = vec![];
    for hint in hints_check_tangent { 
        all_qs.push(hint)
    }
    for hint in hints_ell_tangent { 
        all_qs.push(hint)
    }
    for hint in hints_double_line { 
        all_qs.push(hint)
    }


    let aux = [alpha_tangent, bias_minus_tangent];
    let out = [x, y, c1new, c2new];
    (all_qs, aux, out)
}

// POINT ADD
pub(crate) fn tap_point_add(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, ate: i8) -> Script {
    assert!(ate == 1 || ate == -1);
    assert_eq!(sec_in.len(), 7);
    let mut ate_unsigned_bit = 1;
    if ate == -1 {
        ate_unsigned_bit = 0;
    }

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, _) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let ops_script = script! {
        // [a,b,tx,ty, aux_in]
        // [px, py, qx, qy, in, out]

        {Fq::toaltstack()} // hash out
        {Fq::toaltstack()} // hash in
        {Fq::roll(6)}
        {Fq::toaltstack()} // hash aux in

        //[a, b, tx, ty, p, qx, qy]
        // hinted check chord // t.x, t.y
        { Fq2::copy(12)} // alpha
        { Fq2::copy(12)} // bias
        { Fq2::copy(6) } // q.x
        { Fq2::copy(6) } // q.y
        { hinted_check_chord_q }
        { Fq2::copy(12)} // alpha
        { Fq2::copy(12)} // bias
        { Fq2::copy(12)} // tx
        { Fq2::copy(12)} // ty
        { hinted_check_chord_t }


         //[a, b, tx, ty, p, qx, qy]
        { Fq2::copy(12) } // alpha
        { Fq2::copy(12) } // bias
        { Fq2::roll(8) } // p_dash
        { hinted_ell_chord }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1

        //[a, b, tx, ty, qx, qy]
        { Fq2::roll(8) } // bias
        //[a, tx, ty, qx, qy, b]
        { Fq2::roll(10) } // alpha
        //[tx, ty, qx, qy, b, a]
        { Fq2::roll(6) } //q.x
        //[tx, ty, qy, b, a, qx]
        { Fq2::copy(10) } // t.x from altstack
        //[tx, ty, qy, b, a, qx, tx]
        { hinted_add_line } // alpha, bias chord consumed
         //[tx, ty, qy, R]

        { Fq2::fromaltstack() } // le
        { Fq2::fromaltstack() } // le
        // [tx, ty, qy, Rx, Ry, le0, le1]
        {Fq2::roll(8)}
        {Fq2::drop()}
        // Altstack: [hash_out, hash_in, hash_inaux]
        // Stack: [tx, ty, Rx, Ry, le0, le1]
    };

    let hash_script = script!{
        //Altstack: [hash_out, hash_in, hash_inaux]
        //Stack: [tx, ty, Rx, Ry, le0, le1]
        //T
        {Fq2::roll(10)}
        {Fq2::roll(10)}

        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        //{pack_nibbles_to_limbs()}
        //[T, R, le]

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}

        // // [HashOut]
        // // [Rx, Ry, le0, le1]

        {Fq2::roll(6)}
        {Fq2::roll(6)}
        // [HashOut]
        // [le, R]
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // // // [HashOut, HashR]
        // // // [le]
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        // // [HashOut, HashR]
        // // [Hashle]
        for _ in 0..64 {
            {0}
        }
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        // // [HashOut]
        // // [Hashle, HashR]
        {unpack_limbs_to_nibbles()}
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
    };

    let ate_mul_y_toaltstack = script!{
        {ate_unsigned_bit}
        1 OP_NUMEQUAL
        OP_IF
            {Fq::toaltstack()}
        OP_ELSE // -1
            {Fq::neg(0)}
            {Fq::toaltstack()}
        OP_ENDIF
    };
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_root_claim
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // qdash_y1
        {ate_mul_y_toaltstack.clone()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // qdash_y0
        {ate_mul_y_toaltstack}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // qdash_x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} // qdash_x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} // pdash_x

        // bring back from altstack
        for _ in 0..7 {
            {Fq::fromaltstack()}
        }
        // [px, py, qx0, qx1, qy0, qy1, in, out]
    };


    let sc = script!{
        {bitcomms_script.clone()}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

fn hint_point_add(tt: ark_bn254::G2Affine, q: ark_bn254::G2Affine, p:ark_bn254::G1Affine, ate: i8) -> (Vec<Hint>, [ark_bn254::Fq2; 2],[ark_bn254::Fq2; 4]) {

    let mut qq = q.clone();
    if ate == -1 {
        qq = q.neg();
    }

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    let x = alpha_chord.square() - tt.x - qq.x;
    let y = bias_minus_chord - alpha_chord * x;
    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();

    let (_, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) = new_hinted_check_line_through_point( qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    let mut c1new_2 = alpha_chord;
    c1new_2.mul_assign_by_fp(&(-p.x / p.y));

    let mut c2new_2 = bias_minus_chord;
    c2new_2.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

    let mut all_qs = vec![];
    for hint in hints_check_chord_q { 
        all_qs.push(hint)
    }
    for hint in hints_check_chord_t { 
        all_qs.push(hint)
    }
    for hint in hints_ell_chord { 
        all_qs.push(hint)
    }
    for hint in hints_add_line { 
        all_qs.push(hint)
    }

    let aux = [alpha_chord, bias_minus_chord];
    let out = [x, y, c1new_2, c2new_2];
    (all_qs, aux, out)
}


// POINT DBL AND ADD
pub(crate) fn tap_point_ops(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, ate: i8) -> Script {
    assert!(ate == 1 || ate == -1);
    assert_eq!(sec_in.len(), 7);
    let mut ate_unsigned_bit = 1;
    if ate == -1 {
        ate_unsigned_bit = 0;
    }
    let (hinted_double_line, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_tangent, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, _) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let bcsize = 6+3;
    let ops_script = script! {
        // Altstack is empty
        // View of stack:
        // aux
        // { fq2_push_not_montgomery(alpha_chord)}
        // { fq2_push_not_montgomery(bias_minus_chord)}
        // { fq2_push_not_montgomery(alpha_tangent)}
        // { fq2_push_not_montgomery(bias_minus_tangent)}
        // { fq2_push_not_montgomery(t.x) }
        // { fq2_push_not_montgomery(t.y) }
        // { fq_push_not_montgomery(aux_hash) } // AUX_HASH- not bc

        // bit commits
        // { fq_push_not_montgomery(p_dash_x) }
        // { fq_push_not_montgomery(p_dash_y) }
        // { fq2_push_not_montgomery(q.x) }
        // { fq2_push_not_montgomery(q.y) }
        // { hash_in } // hash
        // MOVE_AUX_HASH_HERE
        // { hash_out_claim } // hash
       
        // move aux hash to MOVE_AUX_HASH_HERE
        {Fq::toaltstack()}
        {Fq::toaltstack()}
        {Fq::roll(6)}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}

        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::copy(bcsize+6)} // t.x
        { Fq2::copy(bcsize+6)} // t.y
        { hinted_check_tangent }

        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(4 + 7) } // p_dash
        { hinted_ell_tangent }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1


        { Fq2::copy(bcsize+4)} // bias
        { Fq2::copy(bcsize+8)} // alpha
        { Fq2::copy(bcsize+6)} // t.x
        { hinted_double_line }
        { Fq2::toaltstack() } 
        { Fq2::toaltstack()}

        { Fq2::roll(bcsize+6) } // alpha tangent drop
        { Fq2::drop() }
        { Fq2::roll(bcsize+4) } // bias tangent drop
        { Fq2::drop() }

        // hinted check chord // t.x, t.y
        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::copy(8+1) } // q.x
        { Fq2::copy(8+1) } // q.y
        { hinted_check_chord_q }
        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::fromaltstack() } // TT
        { Fq2::fromaltstack() }
        { Fq2::copy(2)} // t.x
        { Fq2::toaltstack() } // t.x to altstack
        { hinted_check_chord_t }


        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(10+1) } // p_dash
        { hinted_ell_chord }

        { Fq2::roll(4+bcsize+4) } // bias
        { Fq2::roll(6+bcsize+4) } // alpha
        { Fq2::copy(4+4+4+1) } //q.x
        { Fq2::fromaltstack() } // t.x from altstack
        { hinted_add_line } // alpha, bias chord consumed

        { Fq2::toaltstack() }//R
        { Fq2::toaltstack() }
        
        { Fq2::toaltstack() } //le_add
        { Fq2::toaltstack() } 


        { Fq::toaltstack() } //hashes
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq2::drop() } // drop Qy
        { Fq2::drop() } // drop Qx
        { Fq::drop() } // drop Py
        { Fq::drop() } // drop Px

        // Altstack: [dbl_le, R, add_le, hash_out, hash_in, hash_inaux]
        // Stack: [t]
    };


    let hash_script = script!{

        //T
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}


        // Altstack: [dbl_le, R, add_le, hash_out]
        // Stack: [t]
        for i in 0..13 {
            {Fq::fromaltstack()}
        }

        // Altstack: []
        // Stack: [hash_out, add_le, R, dbl_le]

        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // Altstack: [HD, HR, HA]
        // Stack: [hash_out]
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // Altstack: []
        // Stack: [hash_out, HA, HR, HD]
        {Fq::roll(2)}
        // Stack: [hash_out, HR, HD, HA]
        {Fq::toaltstack()}
        {unpack_limbs_to_nibbles()}
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        // Altstack: []
        // Stack: [hash_out, HR, Hle]
        {Fq::toaltstack()}
        {unpack_limbs_to_nibbles()}
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::equalverify(1, 0)}
    };

    let ate_mul_y_toaltstack = script!{
        {ate_unsigned_bit}
        1 OP_NUMEQUAL
        OP_IF
            {Fq::toaltstack()}
        OP_ELSE // -1
            {Fq::neg(0)}
            {Fq::toaltstack()}
        OP_ENDIF
    };
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_root_claim
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // qdash_y1
        {ate_mul_y_toaltstack.clone()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // qdash_y0
        {ate_mul_y_toaltstack}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // qdash_x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} // qdash_x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} // pdash_x

        // bring back from altstack
        for _ in 0..7 {
            {Fq::fromaltstack()}
        }
    };



    let sc = script!{
        {bitcomms_script.clone()}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

fn hint_point_ops(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine, p:ark_bn254::G1Affine, ate: i8) -> (Vec<Hint>, [ark_bn254::Fq2; 4],[ark_bn254::Fq2; 6]) {
    // let mut prng = ChaCha20Rng::seed_from_u64(0);
    // let t = ark_bn254::G2Affine::rand(&mut prng);
    // let q = ark_bn254::G2Affine::rand(&mut prng);
    // let p = ark_bn254::g1::G1Affine::rand(&mut prng);

    let mut qq = q.clone();
    if ate == -1 {
        qq = q.neg();
    }

    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_tangent = t.x.square();
    alpha_tangent /= t.y;
    alpha_tangent.mul_assign_by_fp(&three_div_two);
    // -bias
    let bias_minus_tangent = alpha_tangent * t.x - t.y;

    let x = alpha_tangent.square() - t.x.double();
    let y = bias_minus_tangent - alpha_tangent * x;
    let (_, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

    let tt = G2Affine::new(x, y);

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    let x = alpha_chord.square() - tt.x - qq.x;
    let y = bias_minus_chord - alpha_chord * x;
    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();

    let (_, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) = new_hinted_check_line_through_point( qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    // affine mode as well
    let mut c1new = alpha_tangent;
    c1new.mul_assign_by_fp(&(-p.x / p.y));

    let mut c2new = bias_minus_tangent;
    c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

    let mut c1new_2 = alpha_chord;
    c1new_2.mul_assign_by_fp(&(-p.x / p.y));

    let mut c2new_2 = bias_minus_chord;
    c2new_2.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
    let (_, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

    let mut all_qs = vec![];
    for hint in hints_check_tangent { 
        all_qs.push(hint)
    }
    for hint in hints_ell_tangent { 
        all_qs.push(hint)
    }
    for hint in hints_double_line { 
        all_qs.push(hint)
    }
    for hint in hints_check_chord_q { 
        all_qs.push(hint)
    }
    for hint in hints_check_chord_t { 
        all_qs.push(hint)
    }
    for hint in hints_ell_chord { 
        all_qs.push(hint)
    }
    for hint in hints_add_line { 
        all_qs.push(hint)
    }


    let aux = [alpha_tangent, bias_minus_tangent, alpha_chord, bias_minus_chord];
    let out = [x, y, c1new, c2new, c1new_2, c2new_2];
    (all_qs, aux, out)
}

// DOUBLE EVAL
fn hint_double_eval_mul_for_fixed_Qs(t2: G2Affine, t3: G2Affine, p2: G1Affine, p3: G1Affine) -> (Vec<Hint>, (G2Affine, G2Affine), ark_bn254::Fq12) {
    // First
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t2 = t2.x.square();
    alpha_t2 /= t2.y;
    alpha_t2.mul_assign_by_fp(&three_div_two);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x.double();
    let y2 = bias_t2 - alpha_t2 * x2;
    let mut c2x = alpha_t2;
    c2x.mul_assign_by_fp(&p2.x);
    let mut c2y = bias_t2;
    c2y.mul_assign_by_fp(&p2.y);
    let mut f = ark_bn254::Fq12::zero();
    f.c0.c0 = ark_bn254::Fq2::one(); // 0
    f.c1.c0 = c2x; // 3
    f.c1.c1 = c2y; // 4
    
    // Second
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t3 = t3.x.square();
    alpha_t3 /= t3.y;
    alpha_t3.mul_assign_by_fp(&three_div_two);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x.double();
    let y3 = bias_t3 - alpha_t3 * x3;
    let mut c3x = alpha_t3;
    c3x.mul_assign_by_fp(&p3.x);
    let mut c3y = bias_t3;
    c3y.mul_assign_by_fp(&p3.y);

    let mut f1 = f;
    f1.mul_by_034(&ark_bn254::Fq2::ONE, &c3x, &c3y);

    let mut hints = vec![];
    let (_, hint_ell_t2) = new_hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = new_hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
    let (_, hint_sparse_dense_mul) = Fq12::hinted_mul_by_34(f, c3x, c3y);

    for hint in hint_ell_t3 {
        hints.push(hint);
    }
    for hint in hint_ell_t2 {
        hints.push(hint);
    }
    for hint in hint_sparse_dense_mul {
        hints.push(hint);
    }
    (hints, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)), f1)
}

pub(crate) fn tap_double_eval_mul_for_fixed_Qs(sec_key: &str,sec_out: u32, sec_in: Vec<u32>, t2: G2Affine, t3: G2Affine) -> Script {
    // First
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t2 = t2.x.square();
    alpha_t2 /= t2.y;
    alpha_t2.mul_assign_by_fp(&three_div_two);
    let bias_t2 = alpha_t2 * t2.x - t2.y;

    // Second
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t3 = t3.x.square();
    alpha_t3 /= t3.y;
    alpha_t3.mul_assign_by_fp(&three_div_two);
    let bias_t3 = alpha_t3 * t3.x - t3.y;

    let (hinted_ell_t2,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_ell_t3,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_sparse_dense_mul,_) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let ops_scr = script!{
        // tmul hints
        // Bitcommits:
        // claimed_fp12_output
        // P2 
        // P3
        {fq2_push_not_montgomery(alpha_t2)} // baked
        {fq2_push_not_montgomery(bias_t2)}
        {fq2_push_not_montgomery(alpha_t3)}
        {fq2_push_not_montgomery(bias_t3)}
        
        { Fq2::roll(8) } // P3
        { hinted_ell_t3 }
        {Fq2::toaltstack()} // c4
        {Fq2::toaltstack()} // c3

        { Fq2::roll(4) } // P2
        { hinted_ell_t2 }
        {Fq2::toaltstack()} // c4
        {Fq2::toaltstack()} // c3

        //insert fp12
        {fq2_push_not_montgomery(ark_bn254::Fq2::one())} // f0
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f1
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f2
        {Fq2::fromaltstack()} // f3
        {Fq2::fromaltstack()} // f4
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f5

        {Fq2::fromaltstack()} // c3
        {Fq2::fromaltstack()} // c4

        {hinted_sparse_dense_mul}
    };

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // P3y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // P3x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // P2y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // P2x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // bhash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack: [bhash, P2x, P2y, P3x, P3y]
    };
    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_script} 
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    sc
}

// ADD EVAL
fn hint_add_eval_mul_for_fixed_Qs(t2: G2Affine, t3: G2Affine, p2: G1Affine, p3: G1Affine, q2: G2Affine, q3: G2Affine) -> (Vec<Hint>, (G2Affine, G2Affine), ark_bn254::Fq12) {
    // First
    let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - q2.x;
    let y2 = bias_t2 - alpha_t2 * x2;
    let mut c2x = alpha_t2;
    c2x.mul_assign_by_fp(&p2.x);
    let mut c2y = bias_t2;
    c2y.mul_assign_by_fp(&p2.y);
    let mut f = ark_bn254::Fq12::zero();
    f.c0.c0 = ark_bn254::Fq2::one(); // 0
    f.c1.c0 = c2x; // 3
    f.c1.c1 = c2y; // 4
    
    // Second
    let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - q3.x;
    let y3 = bias_t3 - alpha_t3 * x3;
    let mut c3x = alpha_t3;
    c3x.mul_assign_by_fp(&p3.x);
    let mut c3y = bias_t3;
    c3y.mul_assign_by_fp(&p3.y);

    let mut f1 = f;
    f1.mul_by_034(&ark_bn254::Fq2::ONE, &c3x, &c3y);

    let mut hints = vec![];
    let (_, hint_ell_t2) = new_hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = new_hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
    let (_, hint_sparse_dense_mul) = Fq12::hinted_mul_by_34(f, c3x, c3y);

    for hint in hint_ell_t3 {
        hints.push(hint);
    }
    for hint in hint_ell_t2 {
        hints.push(hint);
    }
    for hint in hint_sparse_dense_mul {
        hints.push(hint);
    }
    (hints, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)), f1)
}

pub(crate) fn tap_add_eval_mul_for_fixed_Qs(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, t2: G2Affine, t3: G2Affine, q2: G2Affine, q3: G2Affine) -> Script {
    // First
    let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    // Second
    let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;

    let (hinted_ell_t2,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_ell_t3,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t3, bias_t3);
    let (hinted_sparse_dense_mul,_) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let ops_scr = script!{
        // tmul hints
        // P2 
        // P3
        {fq2_push_not_montgomery(alpha_t2)} // baked
        {fq2_push_not_montgomery(bias_t2)}
        {fq2_push_not_montgomery(alpha_t3)}
        {fq2_push_not_montgomery(bias_t3)}
        
        { Fq2::roll(8) } // P3
        { hinted_ell_t3 }
        {Fq2::toaltstack()} // c4
        {Fq2::toaltstack()} // c3

        { Fq2::roll(4) } // P2
        { hinted_ell_t2 }
        {Fq2::toaltstack()} // c4
        {Fq2::toaltstack()} // c3

        // insert fp12
        {fq2_push_not_montgomery(ark_bn254::Fq2::one())} // f0
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f1
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f2
        {Fq2::fromaltstack()} // f3
        {Fq2::fromaltstack()} // f4
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f5

        {Fq2::fromaltstack()} // c3
        {Fq2::fromaltstack()} // c4

        {hinted_sparse_dense_mul}
    };

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // P3y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // P3x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // P2y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // P2x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // bhash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack: [bhash, P2x, P2y, P3x, P3y]
    };
    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_script}
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    sc
}


// SPARSE DENSE

pub(crate) fn tap_sparse_dense_mul(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, dbl_blk: bool) -> Script {
    assert_eq!(sec_in.len(), 2);
    let (hinted_script, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let mut add = 0;
    if dbl_blk == false {
        add = 1;
    }

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_dense_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // hash_sparse_in
        {Fq::toaltstack()}
        // Stack: [...,hash_out, hash_in1, hash_in2]
    };

    let ops_script = script! {
        // Stack: [...,hash_out, hash_in1, hash_in2]
        // Move aux hashes to alt stack
        {Fq::toaltstack()}
        {Fq::toaltstack()}

        // Stack [f, dbl_le0, dbl_le1]
        {Fq12::copy(4)}
        {Fq2::copy(14)}
        {Fq2::copy(14)}

        // Stack [f, dbl_le0, dbl_le1, f, dbl_le0, dbl_le]
        { hinted_script }
        // Stack [f, dbl_le0, dbl_le1, f1]
        // Fq_equal verify
    };
    let hash_script = script!{
        {hash_fp12()}
        // Stack [f, dbl_le0, dbl_le1, Hf1]

        {Fq2::roll(3)}
        {Fq2::roll(3)}
        {hash_fp4()} // hash_le
        {Fq::fromaltstack()} // addle
        // {Fq::fromaltstack()}
        {add} 1 OP_NUMEQUAL
        OP_IF
            {Fq::roll(1)}
        OP_ENDIF
 
        {hash_fp2()}
        {Fq::fromaltstack()} // T_le
        {Fq::roll(1)}
        {hash_fp2()}

        {Fq::fromaltstack()} // hash_in_sparse
        {Fq::equalverify(1, 0)}

        {Fq::toaltstack()} // Hf1 to altstack
        {hash_fp12()} // Hash_calcin
        {Fq::fromaltstack()} // Hash_calcout
        {Fq::fromaltstack()} // Hash_claimin
        {Fq::fromaltstack()} // Hash_claimout
        {Fq::equalverify(3, 1)}
        {Fq::equalverify(1,0)}
    };
    let scr = script!{
        {bitcomms_script}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    scr
}


fn hints_sparse_dense_mul(p: ark_bn254::Fq12, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Vec<Hint> {
    let (_, hints) = Fq12::hinted_mul_by_34(p, c3, c4);
    hints
}

// DENSE DENSE MUL ZERO

pub(crate) fn tap_dense_dense_mul0(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, check_is_identity: bool) -> Script {
    assert_eq!(sec_in.len(), 2);
    let (hinted_mul, _) = Fq12::hinted_mul_first(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // g
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f // SD or DD output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // c // SS or c' output
        {Fq::toaltstack()}
    };

    let hash_scr = script!{
        {hash_fp6()} // c
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} // 
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c

        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g

        {Fq::equalverify(0, 5)}
        {Fq::equalverify(0, 3)}
        {Fq::equalverify(0, 1)}

    };


    let ops_scr = script! {
        { hinted_mul }
        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            {fq_push_not_montgomery(ark_bn254::Fq::one())}
            for _ in 0..5 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script!{
        {bitcom_scr}
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}


fn hints_dense_dense_mul0(a: ark_bn254::Fq12, b: ark_bn254::Fq12) -> Vec<Hint> {
    let (_, mul_hints) = Fq12::hinted_mul_first(12, a, 0, b);
    mul_hints
}


// DENSE DENSE MUL ONE


pub(crate) fn tap_dense_dense_mul1(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, check_is_identity: bool) -> Script {
    assert_eq!(sec_in.len(), 3);
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let (hinted_mul, _) = Fq12::hinted_mul_second(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // g
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f // SD or DD output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // c // SS or c' output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // c // SS or c' output
        {Fq::toaltstack()}
    };

    let hash_scr = script!{
        {Fq::fromaltstack()} // Hc0
        {hash_fp12_with_hints()} // Hc
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} // 
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c

        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g

        {Fq::equalverify(0, 5)}
        {Fq::equalverify(0, 3)}
        {Fq::equalverify(0, 1)}
        

    };


    let ops_scr = script! {
        { hinted_mul }
        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            for _ in 0..6 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script!{
        {bitcom_scr}
        {ops_scr}
        {hash_scr}
        // OP_TRUE
    };
    scr
}


fn hints_dense_dense_mul1(a: ark_bn254::Fq12, b: ark_bn254::Fq12) -> Vec<Hint> {
    let (_, mul_hints) = Fq12::hinted_mul_second(12, a, 0, b);
    mul_hints
}

// PREMILLER

// HASH_C
pub(crate) fn tap_hash_c(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    assert_eq!(sec_in.len(), 12);
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f11 MSB
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[7]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[8]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[9]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[10]))}  // f1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[11]))} // f0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // f_hash
        for _ in 0..12 {
            {Fq::fromaltstack()}
        }
        // Stack:[f_hash_claim, f0, ..,f11]
    };

    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {hash_scr}
        OP_TRUE
    };
    sc
}

// precompute P
pub(crate) fn tap_precompute_P(sec_key: &str, sec_out: Vec<u32>, sec_in: Vec<u32>) -> Script {
    let mut prng = ChaCha20Rng::seed_from_u64(0); // todo: remove prng use later, pt can be any valid mock data
    let pt = ark_bn254::G1Affine::rand(&mut prng);
    let (ops_scr, _) =  {new_hinted_from_eval_point(pt)};
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // py
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // px
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out[0]))} // pyd
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out[1]))} // pxd

        {Fq::fromaltstack()} // pyd
        {Fq::fromaltstack()} // px
        {Fq::fromaltstack()} // py

        // Stack: [hints, pxd, pyd, px, py]
    };

    script!{
        {bitcomms_script}
        {ops_scr}
        OP_TRUE
    }
}

fn hints_precompute_P(p: G1Affine) -> Vec<Hint> {
    let (_, hints) =  {new_hinted_from_eval_point(p)};
    hints
}

// hash T4
pub(crate) fn tap_initT4(sec_key: &str, sec_out: u32, sec_in: Vec<u32>)-> Script {
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // y1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // y0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // f_hash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack:[f_hash_claim, x0,x1,y0,y1]
    };
    let hash_scr = script!{
        { hash_fp4() }
        for _ in 0..64 {
            {0}
        }
        {pack_nibbles_to_limbs()}
        {hash_fp2()}
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {hash_scr}
        OP_TRUE
    };

    sc
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::bn254::utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq6_push_not_montgomery};
    use crate::signatures::winternitz_compact;
    use ark_ff::Field;

    #[test]
    fn test_tap_hash_c() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1,2,3,4,5,6,7,8,9,10,11,12];
        let hash_c_scr = tap_hash_c(&sec_key_for_bitcomms, 0, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f = vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1];
        let fhash = emulate_extern_hash_fps(f.clone(), false);
        let simulate_stack_input = script!{
            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), fhash)}
            for i in 0..12 {
                {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[11-i]), emulate_fq_to_nibbles(f[i]))}
            }
        };

        let tap_len = hash_c_scr.len();
        let script = script!{
            {simulate_stack_input}
            {hash_c_scr}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }


    #[test]
    fn test_tap_hash_T4() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1,2,3,4];
        let hash_c_scr = tap_initT4(&sec_key_for_bitcomms, 0, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let t4hash = emulate_extern_hash_fps(vec![t4.x.c0, t4.x.c1, t4.y.c0, t4.y.c1], false);
        let t4hash = emulate_extern_hash_nibbles(vec![t4hash, [0u8;64]]);  
        let simulate_stack_input = script!{
            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), t4hash)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[3]), emulate_fq_to_nibbles(t4.x.c0))}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[2]), emulate_fq_to_nibbles(t4.x.c1))}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[1]), emulate_fq_to_nibbles(t4.y.c0))}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[0]), emulate_fq_to_nibbles(t4.y.c1))}
        };

        let tap_len = hash_c_scr.len();
        let script = script!{
            {simulate_stack_input}
            {hash_c_scr}
        };

        let res = execute_script(script);
       // assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }


    #[test]
    fn test_precompute_P() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let precompute_p = tap_precompute_P(&sec_key_for_bitcomms, vec![0,1], vec![2,3]);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
        let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());
        let p_x = emulate_fq_to_nibbles(p.x);
        let p_y = emulate_fq_to_nibbles(p.y);
        let tmul_hints = hints_precompute_P(p);

        let simulate_stack_input = script!{
            for hint in tmul_hints { 
                { hint.push() }
            }
            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), pdash_x)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), pdash_y)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), p_x)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), p_y)}
        };

        let tap_len = precompute_p.len();
        let script = script!{
            {simulate_stack_input}
            {precompute_p}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }

    #[test]
    fn test_hinited_sparse_dense_mul() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sparse_dense_mul_script = tap_sparse_dense_mul(&sec_key_for_bitcomms, 0, vec![1,2], true);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let mut f1 = f;
        let dbl_le0 = ark_bn254::Fq2::rand(&mut prng);
        let dbl_le1 = ark_bn254::Fq2::rand(&mut prng);
        f1.mul_by_034(&ark_bn254::Fq2::ONE, &dbl_le0, &dbl_le1);

        let tmul_hints = hints_sparse_dense_mul(f, dbl_le0, dbl_le1);

        // assumes sparse-dense after doubling block, hashing arrangement changes otherwise
        let hash_new_t = [3u8; 64];
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = [4u8; 64]; // mock
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        let hash_sparse_input = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

        let hash_dense_input = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
        let hash_dense_output = emulate_extern_hash_fps(vec![f1.c0.c0.c0,f1.c0.c0.c1, f1.c0.c1.c0, f1.c0.c1.c1, f1.c0.c2.c0,f1.c0.c2.c1, f1.c1.c0.c0,f1.c1.c0.c1, f1.c1.c1.c0, f1.c1.c1.c1, f1.c1.c2.c0,f1.c1.c2.c1], true);
        let hash_add_le_limbs = emulate_nibbles_to_limbs(hash_add_le);
        let hash_t_limbs = emulate_nibbles_to_limbs(hash_new_t);

        println!("hints len {:?}", tmul_hints.len());
        // data passed to stack in runtime 
        let simulate_stack_input = script!{
            // quotients for tmul
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux_a
            {fq12_push_not_montgomery(f)}
            {fq2_push_not_montgomery(dbl_le0)}
            {fq2_push_not_montgomery(dbl_le1)}
 
            for i in 0..hash_add_le_limbs.len() {
                {hash_add_le_limbs[i]}
            }
            for i in 0..hash_t_limbs.len() {
                {hash_t_limbs[i]}
            }
            // aux_hashes
            // bit commit hashes
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), hash_sparse_input)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_dense_input)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_dense_output)}
        };


        let tap_len = sparse_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:3} {:?}", exec_result.final_stack.get(i));
        }
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }


    #[test]
    fn test_hinited_dense_dense_mul0() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul0(&sec_key_for_bitcomms, 0, vec![1,2], true);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap(); //ark_bn254::Fq12::rand(&mut prng); // check_is_identity true
        let h = f * g; 

        let tmul_hints = hints_dense_dense_mul0(f, g);

        let hash_f = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
        let hash_g = emulate_extern_hash_fps(vec![g.c0.c0.c0,g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0,g.c0.c2.c1, g.c1.c0.c0,g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0,g.c1.c2.c1], false);
        let hash_c = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1], true);

        // data passed to stack in runtime 
        let simulate_stack_input = script!{
            // quotients for tmul
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux_a
            {fq12_push_not_montgomery(f)}
            {fq12_push_not_montgomery(g)}
 
            // aux_hashes
            // bit commit hashes
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), hash_c)} // in2: SS or c' link
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_f)} // in1: SD or DD1 link
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_g)} // out
        };


        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }


    #[test]
    fn test_hinited_dense_dense_mul1() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul1(&sec_key_for_bitcomms,0, vec![1,2,3], false);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = ark_bn254::Fq12::rand(&mut prng);
        let h = f * g; 

        let tmul_hints = hints_dense_dense_mul1(f, g);

        let hash_f = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
        let hash_g = emulate_extern_hash_fps(vec![g.c0.c0.c0,g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0,g.c0.c2.c1, g.c1.c0.c0,g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0,g.c1.c2.c1], false);

        let hash_c0 = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1], true);
        let hash_c = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1, h.c1.c0.c0,h.c1.c0.c1, h.c1.c1.c0, h.c1.c1.c1, h.c1.c2.c0,h.c1.c2.c1], true);

        // data passed to stack in runtime 
        let simulate_stack_input = script!{
            // quotients for tmul
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux_a
            {fq12_push_not_montgomery(f)}
            {fq12_push_not_montgomery(g)}
 
            // aux_hashes
            // bit commit hashes

            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), hash_c0)} // in3: links to DD0
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), hash_c)} // in2: SS or c' link
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_f)} // in1: SD or DD1 link
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_g)} // out
        };


        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { dense_dense_mul_script }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }


    #[test]
    fn test_tap_fq12_hinted_square() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let squaring_tapscript = tap_squaring(&sec_key_for_bitcomms, 0, vec![1]);

        // run time
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = a.square();
        let hints_square = hints_squaring(a);
        let a_hash = emulate_extern_hash_fps(vec![a.c0.c0.c0,a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0,a.c0.c2.c1, a.c1.c0.c0,a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0,a.c1.c2.c1], true);
        let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], true);

        // data passed to stack in runtime 
        let simulate_stack_input = script!{
            // quotients for tmul
            for hint in hints_square { 
                { hint.push() }
            }
            // aux_a
            {fq12_push_not_montgomery(a)}
            // aux_a
            {fq12_push_not_montgomery(a)}
            // hash_a
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), b_hash)}
            // hash_b
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), a_hash)}
        };

        let tap_len = squaring_tapscript.len();
        let script = script! {
            { simulate_stack_input }
            { squaring_tapscript }
        };

        let exec_result = execute_script(script);

        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);
    }

    #[test]
    fn test_tap_affine_double_add_eval() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_ops(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6,7], -1);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let (tmul_hints, aux, out) = hint_point_ops(t, q, p, -1);
        let [alpha_tangent, bias_minus_tangent, alpha_chord, bias_minus_chord] = aux;
        let [new_tx, new_ty, dbl_le0, dbl_le1, add_le0, add_le1] = out;

        let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
        let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());
        let qdash_x0 = emulate_fq_to_nibbles(q.x.c0);
        let qdash_x1 = emulate_fq_to_nibbles(q.x.c1);
        let qdash_y0 = emulate_fq_to_nibbles(q.y.c0);
        let qdash_y1 = emulate_fq_to_nibbles(q.y.c1);

        let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true); 
        let aux_hash_le = emulate_nibbles_to_limbs([2u8;64]); // mock     
        let hash_input = emulate_extern_hash_nibbles(vec![hash_t, [2u8;64]]);  

        let simulate_stack_input = script!{
            // tmul_hints
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux
            { fq2_push_not_montgomery(alpha_chord)}
            { fq2_push_not_montgomery(bias_minus_chord)}
            { fq2_push_not_montgomery(alpha_tangent)}
            { fq2_push_not_montgomery(bias_minus_tangent)}
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }

            for i in 0..aux_hash_le.len() {
                {aux_hash_le[i]}
            }

            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 7), pdash_x)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 6), pdash_y)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 5), qdash_x0)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 4), qdash_x1)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), qdash_y0)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), qdash_y1)}

            // bit commits hashes
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_input)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_root_claim)}
        };
        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_affine_double_eval() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_dbl(sec_key_for_bitcomms, 0, vec![1,2,3]);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let (tmul_hints, aux, out) = hint_point_dbl(t, p);
        let [alpha_tangent, bias_minus_tangent] = aux;
        let [new_tx, new_ty, dbl_le0, dbl_le1] = out;

        let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
        let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());


        let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = [0u8; 64];
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true); 
        let aux_hash_le = emulate_nibbles_to_limbs([2u8;64]); // mock     
        let hash_input = emulate_extern_hash_nibbles(vec![hash_t, [2u8;64]]);  

        let simulate_stack_input = script!{
            // tmul_hints
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux
            { fq2_push_not_montgomery(alpha_tangent)}
            { fq2_push_not_montgomery(bias_minus_tangent)}
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }

            for i in 0..aux_hash_le.len() {
                {aux_hash_le[i]}
            }
            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), pdash_x)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), pdash_y)}
            // bit commits hashes
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_input)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_root_claim)}
        };
        
        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_affine_add_eval() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_add(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6, 7], -1);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let (tmul_hints, aux, out) = hint_point_add(t, q, p, -1);
        let [ alpha_chord, bias_minus_chord] = aux;
        let [new_tx, new_ty, add_le0, add_le1] = out;

        let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
        let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());
        let qdash_x0 = emulate_fq_to_nibbles(q.x.c0);
        let qdash_x1 = emulate_fq_to_nibbles(q.x.c1);
        let qdash_y0 = emulate_fq_to_nibbles(q.y.c0);
        let qdash_y1 = emulate_fq_to_nibbles(q.y.c1);

        let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
        let hash_dbl_le = [0u8; 64];
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true); 
        let aux_hash_le = emulate_nibbles_to_limbs([2u8;64]); // mock     
        let hash_input = emulate_extern_hash_nibbles(vec![hash_t, [2u8;64]]);  

        let simulate_stack_input = script!{
            // tmul_hints
            for hint in tmul_hints { 
                { hint.push() }
            }
            // aux
            { fq2_push_not_montgomery(alpha_chord)}
            { fq2_push_not_montgomery(bias_minus_chord)}
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }

            for i in 0..aux_hash_le.len() {
                {aux_hash_le[i]}
            }

            // bit commits raw
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 7), pdash_x)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 6), pdash_y)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 5), qdash_x0)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 4), qdash_x1)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), qdash_y0)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), qdash_y1)}

            // bit commits hashes
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), hash_input)}
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), hash_root_claim)}
        };
        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_dbl_sparse_muls() {

        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
    
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sparse_dbl_tapscript = tap_double_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], t2, t3);
        
        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hints = hint_double_eval_mul_for_fixed_Qs( t2, t3, p2dash, p3dash);
        let (tmul_hints, (_new_t2, _new_t3), b) = hints;
    
        let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], false);
        let p2dash_x = emulate_fq_to_nibbles(p2dash.x);
        let p2dash_y = emulate_fq_to_nibbles(p2dash.y);
        let p3dash_x = emulate_fq_to_nibbles(p3dash.x);
        let p3dash_y = emulate_fq_to_nibbles(p3dash.y);

        println!("hints len {:?}", tmul_hints.len());
        let simulate_stack_input = script!{
            for hint in tmul_hints { 
                { hint.push() }
            }
            // bit commits
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), b_hash)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 4), p2dash_x)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), p2dash_y)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), p3dash_x)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), p3dash_y)}
        };
        let tap_len = sparse_dbl_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_dbl_tapscript }
        };

        let exec_result = execute_script(script);

        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }    


    #[test]
    fn test_tap_add_sparse_muls() {

        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
    
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sparse_add_tapscript = tap_add_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], t2, t3, q2, q3);
        
        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hints = hint_add_eval_mul_for_fixed_Qs( t2, t3, p2dash, p3dash, q2, q3);
        let (tmul_hints, (_new_t2, _new_t3), b) = hints;
    
        let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], false);
        let p2dash_x = emulate_fq_to_nibbles(p2dash.x);
        let p2dash_y = emulate_fq_to_nibbles(p2dash.y);
        let p3dash_x = emulate_fq_to_nibbles(p3dash.x);
        let p3dash_y = emulate_fq_to_nibbles(p3dash.y);

        let simulate_stack_input = script!{
            for hint in tmul_hints { 
                { hint.push() }
            }
            // bit commits
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 0), b_hash)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 4), p2dash_x)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 3), p2dash_y)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 2), p3dash_x)}
            { winternitz_compact::sign(&format!("{}{:04X}", sec_key_for_bitcomms, 1), p3dash_y)}
        };
        let tap_len = sparse_add_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_add_tapscript }
        };

        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }    


 }