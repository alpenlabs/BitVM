use std::collections::HashMap;

use crate::bn254::chunk_primitves::{emulate_extern_hash_fps, emulate_fq_to_nibbles, emulate_fr_to_nibbles, unpack_limbs_to_nibbles};
use crate::bn254::chunk_taps::tup_to_scr;
use crate::bn254::utils::{fq_push_not_montgomery, hinted_affine_add_line};
use crate::signatures::winternitz_compact::{checksig_verify_fq, WOTSPubKey};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use bitcoin::opcodes::all::{ OP_1ADD, OP_2DROP, OP_ADD, OP_DEPTH, OP_DROP, OP_DUP, OP_ENDIF, OP_FROMALTSTACK, OP_NUMEQUAL, OP_PICK, OP_ROLL, OP_TOALTSTACK};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use num_traits::One;

use super::chunk_taps::{Sig};
use super::fq2::Fq2;
use super::utils::{Hint};

fn tap_msm(window: u8, pub_ins: u8, msm_tap_index: u8) {

    let (hinted_check_tangent, _) = hinted_check_line_through_point_g1(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one());
    let (hinted_double_line, _) = hinted_affine_double_line_g1(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one());

    let (hinted_check_chord_t, _) = hinted_check_line_through_point_g1(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one());
    let (hinted_check_chord_q, _) = hinted_check_line_through_point_g1(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one());
    let (hinted_add_line, _) = hinted_affine_add_line_g1(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq::one());

    // alpha, bias
    let ops_script = script!{

        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // [a, b, tx, ty]
        for _ in 0..window {
            {Fq::copy(3)}
            {Fq::copy(3)}
            {hinted_check_tangent.clone()}
            {Fq::drop()}
            {hinted_double_line.clone()}
        }

        for _ in 0..pub_ins {
            {Fq::copy(3)}
            {Fq::copy(3)}
            { hinted_check_chord_t.clone() }
            {Fq::copy(3)}
            {Fq::copy(3)}
            {msm_tap_index}
            { hinted_check_chord_q.clone() }
        }
    };
}

fn tap_bake_precompute(q: ark_bn254::G1Affine, window: u8) -> Script {
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << window) {
        p_mul.push((p_mul.last().unwrap().clone() + q.clone()).into_affine());
    }
    script!{
        for i in 0..(1 << window) {
            OP_DUP {i} OP_NUMEQUAL
            OP_IF 
                {fq_push_not_montgomery(p_mul[i].x)}
                {fq_push_not_montgomery(p_mul[i].y)}
            OP_ENDIF
        }
        OP_DEPTH OP_1SUB OP_ROLL OP_DROP
    }

}

fn tap_extract_window_segment_from_scalar(index: usize) -> Script {
    const N: usize = 32;
    script!{
        {unpack_limbs_to_nibbles()}
        {N-1-index} OP_DUP OP_ADD // double
        OP_1ADD // +1
        OP_DUP OP_TOALTSTACK
        OP_ROLL
        OP_FROMALTSTACK OP_ROLL
        OP_TOALTSTACK OP_TOALTSTACK
        for _ in 0..N-1 {
            OP_2DROP
        }
        OP_FROMALTSTACK 
        OP_DUP OP_ADD
        OP_DUP OP_ADD 
        OP_DUP OP_ADD
        OP_DUP OP_ADD 
        OP_FROMALTSTACK
        OP_ADD
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintInMSM {
    t: ark_bn254::G1Affine,
    scalars: Vec<ark_bn254::Fr>,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutMSM {
    t: ark_bn254::G1Affine,
}

fn hinted_affine_add_line_g1(tx: ark_bn254::Fq, qx: ark_bn254::Fq, c3: ark_bn254::Fq, c4: ark_bn254::Fq) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hsc, hts) = Fq::hinted_square(c3);
    let (hinted_script1, hint1) = Fq::hinted_mul(4, c3, 0, c3.square()-tx-qx);

    let script_lines = vec! [
        // [T.x, Q.x]
        Fq::neg(0),
        // [T.x, -Q.x]
        Fq::roll(2),
        // [-Q.x, T.x]
        Fq::neg(0),
        // [-T.x - Q.x]
        Fq::add(2, 0),
        // [-T.x - Q.x]
        Fq::roll(2),
        Fq::copy(0),
        hsc,
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        Fq::add(4, 0),
        // [alpha, x']
        Fq::copy(0),
        // [alpha, x', x']
        hinted_script1,
        // [x', alpha * x']
        Fq::neg(0),
        // [x', -alpha * x']
        // fq2_push_not_montgomery(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        Fq::add(4, 0),
        // [x', y']
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hts);
    hints.extend(hint1);

    (script, hints)
}


fn hinted_affine_double_line_g1(tx: ark_bn254::Fq, c3: ark_bn254::Fq, c4: ark_bn254::Fq) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hsc, hts) = Fq::hinted_square(c3);
    let (hinted_script1, hint1) = Fq::hinted_mul(4, c3, 0, c3.square()-tx-tx);

    let script_lines = vec! [
        Fq::double(0),
        Fq::neg(0),
        // [alpha, - 2 * T.x]
        Fq::roll(2),
        Fq::copy(0),
        hsc,
        // fq2_push_not_montgomery(c3.square()),
        // [- 2 * T.x, alpha, alpha^2]
        Fq::add(4, 0),
        Fq::copy(0),
        // [alpha, x', x']
        hinted_script1,
        Fq::neg(0),
        // [x', -alpha * x']

        Fq::add(4, 0),
        // [x', y']
    ];

    let mut script = script!{};

    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hts);
    hints.extend(hint1);

    (script, hints)
}


fn hinted_check_line_through_point_g1(x: ark_bn254::Fq, c3: ark_bn254::Fq, c4: ark_bn254::Fq) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();
    
    let (hinted_script1, hint1) = Fq::hinted_mul(2, x,0, c3);

    let script_lines = vec![
        // [alpha, bias, y, x ]
        Fq::roll(2),
        // [alpha, bias, x, y ]
        Fq::roll(6),
        hinted_script1,
        // [bias, y, alpha * x]
        Fq::neg(0),
        // [bias, y, -alpha * x]
        Fq::add(2, 0),
        // [bias, y - alpha * x]
        Fq::add(2, 0),
        // [y - alpha * x - bias]

        Fq::push_zero(),
        // [y - alpha * x - bias, 0]
        Fq::equalverify(1,0),
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}

fn get_byte_mul_g1(scalar: ark_bn254::Fr, window: u8, index: usize, base: ark_bn254::G1Affine) -> ark_bn254::G1Affine {
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << window) {
        p_mul.push((p_mul.last().unwrap().clone() + base.clone()).into_affine());
    }

    let chunks = scalar
    .into_bigint()
    .to_bits_be()
    .iter()
    .map(|b| if *b { 1_u8 } else { 0_u8 })
    .collect::<Vec<_>>()
    .chunks(window as usize)
    .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
    .collect::<Vec<u32>>();
    
    let item = chunks[index];
    let precomputed_q = p_mul[item as usize];
    return precomputed_q;
}

fn hint_msm(sig: &mut Sig, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInMSM, index: usize, qs: Vec<ark_bn254::G1Affine>,) -> (HintOutMSM, Script) {
    const window: u8 = 8;
    const num_pubs: usize = 4;

    // hint_in
    let mut t = hint_in.t.clone();
    assert!(qs.len() <= num_pubs);
    assert_eq!(qs.len(), hint_in.scalars.len());
    assert_eq!(sec_in.len(), hint_in.scalars.len());

    // constants
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;

    let mut aux_tangent = vec![];

    let mut hints_tangent: Vec<Hint> = Vec::new();

    if t.y != ark_bn254::Fq::ZERO {
        for _ in 0..window {
            let mut alpha = t.x.square();
            alpha /= t.y;
            alpha *= three_div_two;
            let bias_minus = alpha * t.x - t.y;
            let new_tx = alpha.square() - t.x.double();
            let new_ty = bias_minus - alpha * new_tx;
        
            t.x = new_tx;
            t.y = new_ty;     

            let (_, hints_double_line) = hinted_affine_double_line_g1(t.x, alpha, bias_minus);
            let (_, hints_check_tangent) = hinted_check_line_through_point_g1(t.x, alpha, bias_minus);

            for hint in hints_check_tangent {
                hints_tangent.push(hint);
            }
            for hint in hints_double_line {
                hints_tangent.push(hint);
            }
            
            aux_tangent.push(bias_minus);
            aux_tangent.push(alpha);
        }
    }
    let mut hints_chord: Vec<Hint> = Vec::new();
    let mut aux_chord = vec![];
    for (qi, qq) in qs.iter().enumerate() {
        let q = get_byte_mul_g1(hint_in.scalars[qi], window, index, *qq);
        if  t.y == ark_bn254::Fq::ZERO {
            t = q.clone();
            continue;
        } else {
            let alpha = (t.y - q.y) / (t.x - q.x);
            let bias_minus = alpha * t.x - t.y;
            
            let new_tx = alpha.square() - t.x - q.x;
            let new_ty = bias_minus - alpha * new_tx;
            
            t.x = new_tx;
            t.y = new_ty;
     
            let (_, hints_check_chord_t) = hinted_affine_double_line_g1( t.x, alpha, bias_minus);
            let (_, hints_check_chord_q) = hinted_affine_double_line_g1( q.x, alpha, bias_minus);
            let (_, hints_add_line) = hinted_affine_add_line_g1(t.x, q.x, alpha, bias_minus);
    
            for hint in hints_check_chord_q {
                hints_chord.push(hint)
            }
            for hint in hints_check_chord_t {
                hints_chord.push(hint)
            }
            for hint in hints_add_line {
                hints_chord.push(hint)
            }
            aux_chord.push(bias_minus);
            aux_chord.push(alpha);  
        }
    }

    let mut tup = vec![
        (sec_out, emulate_extern_hash_fps(vec![t.x, t.y], true)),
    ];

    let mut hash_scalars = vec![];
    for i in 0..hint_in.scalars.len() {
        let idx = hint_in.scalars.len()-1-i;
        let tup = (sec_in[idx], emulate_fr_to_nibbles(hint_in.scalars[idx]));
        hash_scalars.push(tup);
    }
 
    tup.extend_from_slice(&hash_scalars);
   
    let bc_elems = tup_to_scr(sig, tup);


    let simulate_stack_input = script! {
        // tmul hints
        for hint in hints_tangent { // check_tangent then double line
            {hint.push()}
        }
        for hint in hints_chord { // check chord q, t, add line
            {hint.push()}
        }
        for i in 0..aux_chord.len() { // 
            {fq_push_not_montgomery(aux_chord[aux_chord.len()-1-i])}
        }
        for i in 0..aux_tangent.len() {
            {fq_push_not_montgomery(aux_tangent[aux_tangent.len()-i-i])}
        }

        for bc in bc_elems {
            {bc}
        }
    };

    let hint_out = HintOutMSM {t};

    (hint_out, simulate_stack_input)
}

pub(crate) fn bitcom_msm(link_ids: &HashMap<u32, WOTSPubKey>, sec_out: u32, sec_in: Vec<u32>) -> Script {
    script!{
        for sec in sec_in {
            {checksig_verify_fq(link_ids.get(&sec).unwrap().clone())}
            {Fq::toaltstack()}
        }
        {checksig_verify_fq(link_ids.get(&sec_out).unwrap().clone())}
        {Fq::toaltstack()}
    }
    // altstack: [k2, k1, k0, acc]
    // stack: []
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::bn254::{fq2::Fq2, utils::fr_push_not_montgomery};

    use super::*;
    use ark_bn254::G1Affine;
    use ark_ff::{UniformRand};
    use bitcoin::opcodes::{all::OP_EQUALVERIFY, OP_TRUE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::HintInMSM;


    #[test]
    fn test_hint() {
        // let mut prng = ChaCha20Rng::seed_from_u64(0); 
        // let hint_in = HintInMSM {
        //     t: ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::rand(&mut prng), ark_bn254::Fq::one()),
        //     q: vec![ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::rand(&mut prng), ark_bn254::Fq::one())],
        // };



        // hint_msm(&mut sig, sec_out, sec_in, hint_in, 0);
    }

    #[test]
    fn extract_byte_from_fr() {
        let mut prng = ChaCha20Rng::seed_from_u64(0); 
        let msk = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let mut sig = Sig {msk: Some(msk), cache: HashMap::new()};
        let sec_out = 0;
        let sec_in = vec![];

        let window = 8;
        let num_bits = 256;
        let mut hint_in = HintInMSM { 
            t: G1Affine::identity(), 
            scalars: vec![ark_bn254::Fr::rand(&mut prng), ark_bn254::Fr::rand(&mut prng)],
        };
        let qs = vec![G1Affine::rand(&mut prng), G1Affine::rand(&mut prng)];

        for i in 0..num_bits/window {
            println!("index {:?}", i);
            let (aux, scr) = hint_msm(&mut sig, sec_out, sec_in.clone(), hint_in.clone(), i, qs.clone());
            hint_in.t = aux.t;
        }
        println!("check {:?}", hint_in.t == qs[0] * hint_in.scalars[0] + qs[1] * hint_in.scalars[1]);
    }

    #[test]
    fn test_precompute_table() {
        let window = 8;
        let mut prng = ChaCha20Rng::seed_from_u64(2); 
        let q = G1Affine::rand(&mut prng);
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << window) {
            p_mul.push((p_mul.last().unwrap().clone() + q.clone()).into_affine());
        }

        let scr = tap_bake_precompute(q, window);
        let index = u32::rand(&mut prng) % (1 << window);
        println!("script len {:?}", scr.len());
        let script = script!{
            {index}
            {scr}
            {fq_push_not_montgomery(p_mul[index as usize].y)}
            {Fq::equalverify(1, 0)}
            {fq_push_not_montgomery(p_mul[index as usize].x)}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);

    }

    #[test]
    fn test_extract_window_from_scalar() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let scalar = ark_bn254::Fr::rand(&mut prng);

        let index = u32::rand(&mut prng) % 32;
        let window = 8;

        let chunks = scalar
        .into_bigint()
        .to_bits_be()
        .iter()
        .map(|b| if *b { 1_u8 } else { 0_u8 })
        .collect::<Vec<_>>()
        .chunks(window as usize)
        .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
        .collect::<Vec<u32>>();
        let chunk_match = chunks[index as usize];
        println!("chunk_match {:?}", chunk_match);
        let script = script!{
            {fr_push_not_montgomery(scalar)}
            {tap_extract_window_segment_from_scalar(index as usize)}
            {chunk_match}
            OP_EQUALVERIFY
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
    }
}