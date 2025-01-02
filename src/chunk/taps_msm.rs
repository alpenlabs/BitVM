use std::ops::Neg;
use std::str::FromStr;

use crate::bn254::{self};
use crate::bn254::fr::Fr;
use crate::bn254::utils::fq_push_not_montgomery;
use crate::chunk::primitves::extern_hash_fps;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::One;

use super::hint_models::{ElemFq, ElemG1Point};
use super::primitves::{hash_fp2, HashBytes};
use crate::bn254::fq2::Fq2;

pub(crate) fn tap_msm(window: usize, msm_tap_index: usize, ks: Vec<ark_bn254::Fr>, qs: Vec<ark_bn254::G1Affine>) -> Script {
    let mut g1acc = if msm_tap_index == 0 {
        ark_bn254::G1Affine::identity()
    } else {
        let acc_hints = calc_hints_for_scalar_mul_by_constant_g1(ks.clone(), qs.clone(), window as u32);
        acc_hints[msm_tap_index-1]
    };
    let num_pubs = qs.len();
    let (loop_script, _)= bn254::curves::G1Affine::hinted_scalar_mul_by_constant_g1_ith_step(&mut g1acc, ks, qs, window as u32, msm_tap_index as u32);

    // [G1AccDashHash, G1AccHash, k0, k1, k2]
    // [Dec, G1Acc]
    let ops_script = 
    if msm_tap_index == 0 {
        script!(
            for _ in 0..num_pubs {
                {Fr::fromaltstack()}
            }
            // [Dec, k2, k1, k0]
            for i in 0..num_pubs {
                {Fr::roll(i as u32)}
            }
            // [Dec, k0, k1, k2]
            {loop_script}
            //M: [G1AccDash]
            //A: [G1AccDashHash]
        )
    } else {
        script!(
            // [Dec, G1Acc]
            for _ in 0..num_pubs {
                {Fr::fromaltstack()}
            }
            // [Dec, G1Acc, k2, k1, k0]
            {Fq2::copy(num_pubs as u32)}
            // [Dec, G1Acc, k2, k1, k0, G1Acc]
            {Fq2::toaltstack()}
            // [Dec, G1Acc, k2, k1, k0]
            for i in 0..num_pubs {
                {Fr::roll(i as u32)}
            }
            // [Dec, G1Acc, k0, k1, k2]
            {loop_script}
            //M: [G1AccDash]
            //A: [G1AccDashHash, G1AccHash, G1Acc]
        )
    };

    let hash_script = if msm_tap_index == 0 {
        //M: [G1AccDash]
        //A: [G1AccDashHash]
        script!(
            {hash_fp2()} // [nt]
            {Fq::fromaltstack()}
            {Fq::equal(1,0)} OP_NOT OP_VERIFY
        )
    } else {
        //M: [G1AccDash]
        //A: [G1AccDashHash, G1AccHash, G1Acc]
        script!(
            {hash_fp2()}
            {Fq2::fromaltstack()}
            {Fq::roll(2)} {Fq::toaltstack()}
            {hash_fp2()} {Fq::fromaltstack()}
            {Fq2::fromaltstack()}
            // [nth, th, th, nth]
            {Fq::equalverify(1, 3)}
            {Fq::equal(1, 0)}
            OP_NOT OP_VERIFY
        )
    };

    let sc = script! {
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

fn calc_hints_for_scalar_mul_by_constant_g1(
    g16_scalars: Vec<ark_bn254::Fr>,
    g16_bases: Vec<ark_bn254::G1Affine>,
    window: u32,
) -> Vec<ark_bn254::G1Affine> {
    assert_eq!(g16_scalars.len(), g16_bases.len());

    let glv_scalars: Vec<((u8, ark_bn254::Fr), (u8, ark_bn254::Fr))> = g16_scalars.iter().map(|s| bn254::curves::G1Affine::calculate_scalar_decomposition(*s)).collect();
    let endo_coeffs = BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap();
    let endo_coeffs = ark_bn254::Fq::from(endo_coeffs);
    let glv_bases: Vec<(ark_bn254::G1Affine, ark_bn254::G1Affine)> = g16_bases.iter().map(|b| 
        (*b, ark_bn254::G1Affine::new_unchecked(b.x * endo_coeffs, b.y))
    ).collect();       
    
    let mut scalars: Vec<ark_bn254::Fr> = vec![];
    let mut bases: Vec<ark_bn254::G1Affine> = vec![];

    glv_scalars.iter().enumerate().for_each(|(idx, stup)| {
        let (s0, s1) = stup;
        scalars.push(s0.1);
        scalars.push(s1.1);
        let (mut g0, mut g1) = glv_bases[idx];
        if s0.0 == 2 {
            g0 = g0.neg();
        } 
        if s1.0 == 2 {
            g1 = g1.neg();
        }
        bases.push(g0);
        bases.push(g1);
    });

    let mut expected: ark_bn254::G1Affine = ark_bn254::G1Affine::identity();
    let mut chunks: Vec<Vec<u32>> = vec![];


    let num_bits = (bn254::fr::Fr::N_BITS + 1) / 2;
    for i in 0..scalars.len() {
        let scalar = scalars[i];

        let tmp = scalar
            .into_bigint()
            .to_bits_be()[(256-num_bits as usize)..256]
            .iter()
            .map(|b| if *b { 1_u8 } else { 0_u8 })
            .collect::<Vec<_>>()
            .chunks(window as usize)
            .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
            .collect::<Vec<u32>>();
    
        chunks.push(tmp);

        let cur: ark_bn254::G1Affine = (bases[i] * scalars[i]).into_affine();
        expected = (expected + cur).into();
    }
    
    let mut accs: Vec<ark_bn254::G1Affine> = vec![];
    let mut acc = ark_bn254::G1Affine::identity();
    for itr in 0..((num_bits + window -1)/window) {
        if !acc.is_zero() {
            let depth = std::cmp::min(num_bits - window * itr as u32, window);
            for _ in 0..depth {
                acc = (acc + acc).into_affine();
            }
        }
        for j in 0..bases.len() {
            let base_i = (bases[j]  * ark_bn254::Fr::from(chunks[j][itr as usize])).into_affine();
            acc = (acc + base_i).into_affine();
        }
        accs.push(acc);
    }
    assert_eq!(acc, expected);
    accs
}



pub(crate) fn hint_msm(window: usize, msm_tap_index: usize, ks: Vec<ark_bn254::Fr>, qs: Vec<ark_bn254::G1Affine>) -> (ark_bn254::G1Affine, Script) {
    let aux_hints_scalar_decs = bn254::curves::G1Affine::aux_hints_for_scalar_decomposition(ks.clone());
    let acc_hints = calc_hints_for_scalar_mul_by_constant_g1(ks.clone(), qs.clone(), window as u32);
    let mut g1acc = if msm_tap_index == 0 {
        ark_bn254::G1Affine::identity()
    } else {
        acc_hints[msm_tap_index-1]
    };
    let (_, loop_hints)= bn254::curves::G1Affine::hinted_scalar_mul_by_constant_g1_ith_step(&mut g1acc, ks, qs, window as u32, msm_tap_index as u32);
    let hint_script = script!(
        for h in &loop_hints {
            {h.push()}
        }
        for h in &aux_hints_scalar_decs {
            {h.push()}
        }
        if msm_tap_index > 0 {
            {fq_push_not_montgomery(acc_hints[msm_tap_index-1].x)}
            {fq_push_not_montgomery(acc_hints[msm_tap_index-1].y)}
        }
    );
    (acc_hints[msm_tap_index], hint_script)
}


// Hash P
//vk0: G1Affine
pub(crate) fn tap_hash_p(q: ark_bn254::G1Affine) -> Script {
    let (hinted_add_line, _) = bn254::curves::G1Affine::hinted_add(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_line_pt, _) = bn254::curves::G1Affine::hinted_check_line_through_point(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );

    let ops_script = script!{
        // Altstack:[identity, th, gpy, gpx]
        {Fq::fromaltstack()} {Fq::fromaltstack()} {Fq::fromaltstack()}
        // Stack:[..gpx, gpy, th]
        {Fq::roll(1)} {Fq::roll(2)}
        // Stack:[..th, gpy, gpx]
        {Fq::toaltstack()} {Fq::toaltstack()} {Fq::toaltstack()}
        // Altstack:[identity, gpx, gpy, th]

        //[hinttqa, alpha, bias, tx, ty]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias,tx, ty] 
        { hinted_line_pt.clone() } OP_VERIFY
        //[hinttqa, alpha, bias, tx, ty

        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        {fq_push_not_montgomery(q.x)}
        {fq_push_not_montgomery(q.y)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias, qx, qy]
        { hinted_line_pt.clone() } OP_VERIFY

        //[hinttqa, alpha, bias, tx, ty
        {Fq2::copy(0)}
        {Fq2::toaltstack()}
        {Fq::drop()} {Fq::toaltstack()}
        {Fq::fromaltstack()}

        // //[hinttqa, alpha, bias, tx]
        {fq_push_not_montgomery(q.x)}
        { hinted_add_line.clone() }

        // Altstack:[identity, gpx, gpy, th]
        //[ntx, nty, tx, ty]

        {Fq2::fromaltstack()} {Fq::fromaltstack()}
        {Fq2::roll(3)} {Fq2::toaltstack()} {Fq::toaltstack()}
        { hash_fp2() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)} {Fq2::fromaltstack()} 
        {Fq2::fromaltstack()} {Fq::roll(1)}
        // // [ntx, nty, gpx, gpy]
        {Fq::fromaltstack()}
        {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
        // [ntx, nty, gpx, gpy, zero, 0]
        {Fq::equal(1, 0)}
        OP_IF 
            // equal so, continue verify rest
            {Fq2::equal()}
            OP_NOT OP_VERIFY
        OP_ELSE
            // not equal, disproven, so drop and exit
            {Fq2::drop()}
            {Fq2::drop()}
            {1} OP_VERIFY
        OP_ENDIF
    };

    let sc = script! {
        {ops_script}
        OP_TRUE
    };
    sc
}


pub(crate) fn hint_hash_p(
    hint_in_t: ElemG1Point,
    hint_in_ry: ElemFq,
    hint_in_rx: ElemFq,
    hint_in_q: ark_bn254::G1Affine,
) -> (HashBytes, Script) {
    // r (gp3) = t(msm) + q(vk0)
    let (tx, qx, ty, qy) = (hint_in_t.x, hint_in_q.x, hint_in_t.y, hint_in_q.y);
    
    let (rx, ry) = (hint_in_rx, hint_in_ry);
    let thash = extern_hash_fps(vec![hint_in_t.x, hint_in_t.y], false);

    let rdash = (ark_bn254::G1Affine::new_unchecked(tx, ty) + hint_in_q).into_affine();
    // assert_eq!(rdash, ark_bn254::G1Affine::new_unchecked(rx, ry));
    let zero_nib = [0u8;64];

    let alpha_chord = (ty - qy) / (tx - qx);
    let bias_minus_chord = alpha_chord * tx - ty;
    assert_eq!(alpha_chord * tx - ty, bias_minus_chord);

    let (_, hints_check_chord_t) = bn254::curves::G1Affine::hinted_check_line_through_point(tx, alpha_chord);
    let (_, hints_check_chord_q) = bn254::curves::G1Affine::hinted_check_line_through_point(qx, alpha_chord);
    let (_, hints_add_line) = bn254::curves::G1Affine::hinted_add(tx, qx, alpha_chord);



    let simulate_stack_input = script! {
        // bit commits raw
        for hint in hints_check_chord_t {
            {hint.push()}
        }
        for hint in hints_check_chord_q {
            {hint.push()}
        }
        for hint in hints_add_line {
            {hint.push()}
        }

        {fq_push_not_montgomery(alpha_chord)}
        {fq_push_not_montgomery(bias_minus_chord)}

        {fq_push_not_montgomery(tx)}
        {fq_push_not_montgomery(ty)}
    };
    (zero_nib, simulate_stack_input)
}


#[cfg(test)]
mod test {

    use crate::{
        bigint::bits::limb_to_le_bits, bn254::{curves, fq2::Fq2, utils::fr_push_not_montgomery}, chunk::primitves::extern_nibbles_to_limbs, execute_script_without_stack_limit
    };
    use super::*;
    use ark_bn254::{G1Affine};
    use ark_ff::{Field, MontFp, UniformRand};
    use bitcoin::opcodes::{all::{OP_1SUB, OP_DEPTH, OP_DROP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROLL, OP_TOALTSTACK}, OP_TRUE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::chunk::hint_models::ElemTraitExt;

    fn u32_to_bits_vec(value: u32, window: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity(window);
        for i in (0..window).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
        bits
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

        let scr = script!{ 
            {curves::G1Affine::dfs_with_constant_mul_not_montgomery(0, window as u32 - 1, 0, &p_mul) }
        };
        let index = 1; //u32::rand(&mut prng) % (1 << window);
        let index_bits = u32_to_bits_vec(index, window);

        println!("index_bits {:?}", index_bits);
        println!("script len {:?}", scr.len());
        let script = script! {
            for i in index_bits {
                {i}
            }
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
    fn test_hinted_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha *= three_div_two;
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let nx = alpha.square() - t.x.double();
        let ny = bias_minus - alpha * nx;

        let (hinted_check_line, hints) = bn254::curves::G1Affine::hinted_check_tangent_line(t, alpha);
        let (hinted_double_line, hintsd) = bn254::curves::G1Affine::hinted_double(t, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { fq_push_not_montgomery(t.y) }
            { hinted_check_line.clone() }
            OP_VERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        let script = script! {
            for hint in hintsd {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { hinted_double_line.clone() }
            {fq_push_not_montgomery(nx)}
            {fq_push_not_montgomery(ny)}
            {Fq2::equalverify()}
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_double_line: {} @ {} stack",
            hinted_double_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        // doubling check
    }

    #[test]
    fn test_hinted_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add_line, hints) = bn254::curves::G1Affine::hinted_add(t.x, q.x, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { fq_push_not_montgomery(q.x) }
            { hinted_add_line.clone() }
            { fq_push_not_montgomery(x) }
            { fq_push_not_montgomery(y) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_add_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_tap_hash_p() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let r = (t + q).into_affine();
        let thash = extern_hash_fps(vec![t.x, t.y], false);

        let hash_c_scr = tap_hash_p(q);

        let (hint_out, hint_script) = hint_hash_p( t, r.y, r.x,q);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(thash) {
                {i}
            }
            {Fq::toaltstack()}
            {fq_push_not_montgomery(r.y)}
            {Fq::toaltstack()}   
            {fq_push_not_montgomery(r.x)}
            {Fq::toaltstack()}   
        };


        let tap_len = hash_c_scr.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {hash_c_scr}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let scalar = ark_bn254::Fr::rand(&mut prng);
        let scalars = vec![scalar];
        let qs = vec![q];

        let msm_tap_index = 1;
        let window = 7;
        let tap_msm = tap_msm(window, msm_tap_index, scalars.clone(), qs.clone());
        let acc_hints = calc_hints_for_scalar_mul_by_constant_g1(scalars.clone(), qs.clone(), window as u32);
        let t: ElemG1Point = if msm_tap_index == 0 {
            ark_bn254::G1Affine::identity()
        } else {
            acc_hints[msm_tap_index-1]
        };
        let (hint_out, hint_script) = hint_msm(window, msm_tap_index, scalars.clone(), qs.clone());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            if msm_tap_index > 0 {
                for i in extern_nibbles_to_limbs(t.out()) {
                    {i}
                }
                {Fq::toaltstack()}
            }

            for scalar in scalars {
                {fr_push_not_montgomery(scalar)}
                {Fq::toaltstack()}  
            }
        };


        let tap_len = tap_msm.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {tap_msm}
        };

        let res = execute_script_without_stack_limit(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);

        assert!(!res.success);
        assert!(res.final_stack.len() == 1);

    }


}
