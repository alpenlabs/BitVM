use crate::bn254::chunk_taps::tup_to_scr;
use crate::bn254::utils::{fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use num_traits::One;

use super::chunk_taps::{Sig};
use super::utils::{Hint};

fn tap_msm() {
    let (hinted_check_tangent1, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_double_line1, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let (hinted_check_tangent2, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_double_line2, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let (hinted_check_tangent3, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_double_line3, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let (hinted_check_tangent4, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_double_line4, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, _) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    // alpha, bias
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
    
    let precomputed_q = p_mul[chunks[index] as usize];
    return precomputed_q;
}

fn hint_msm(sig: &mut Sig, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInMSM, index: usize, qs: Vec<ark_bn254::G1Affine>,) -> (HintOutMSM, Script) {
    const window: u8 = 8;
    const num_pubs: usize = 4;

    // hint_in
    let mut t = hint_in.t.clone();
    assert!(qs.len() <= num_pubs);
    assert_eq!(qs.len(), hint_in.scalars.len());

    
    // constants
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;

    let mut aux_tangent = vec![];

    let mut hints_tangent: Vec<Hint> = Vec::new();

    if index != 0 {
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
            
            aux_tangent.push(alpha);
            aux_tangent.push(bias_minus);
        }
    }

    let mut hints_chord: Vec<Hint> = Vec::new();
    let mut aux_chord = vec![];
    for (qi, qq) in qs.iter().enumerate() {
        let q = get_byte_mul_g1(hint_in.scalars[qi], window, index, *qq);
        let alpha = (t.y - q.y) / (t.x - q.x);
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);  
        aux_chord.push(alpha);
        aux_chord.push(bias_minus);  

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
    }

    let tup = vec![
    ];
   
    let bc_elems = tup_to_scr(sig, tup);


    let simulate_stack_input = script! {
        // tmul hints
        for hint in hints_tangent {
            {hint.push()}
        }
        for hint in hints_chord {
            {hint.push()}
        }
        for aux in aux_tangent {
            {fq_push_not_montgomery(aux)}
        }
        for aux in aux_chord {
            {fq_push_not_montgomery(aux)}
        }

        for bc in bc_elems {
            {bc}
        }
    };

    let hint_out = HintOutMSM {t};

    (hint_out, simulate_stack_input)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;
    use ark_bn254::G1Affine;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
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
            t: G1Affine::new_unchecked(ark_bn254::Fq::one(), ark_bn254::Fq::one()), 
            scalars: vec![ark_bn254::Fr::ONE],
        };
        let qs = vec![G1Affine::rand(&mut prng)];
        for i in 0..num_bits/window {
            let (aux, scr) = hint_msm(&mut sig, sec_out, sec_in.clone(), hint_in.clone(), i, qs.clone());
            hint_in.t = aux.t;
        }
        println!("hint_in.t {:?}", hint_in.t);
        println!("check {:?}", hint_in.t == qs[0] - hint_in.t);
    }
}