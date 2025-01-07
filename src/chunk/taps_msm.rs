use std::ops::Neg;
use std::str::FromStr;

use crate::bn254::curves::G1Affine;
use crate::bn254::{self};
use crate::bn254::fr::Fr;
use crate::bn254::utils::{fq_push_not_montgomery, Hint};
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

pub(crate) fn tap_msm(window: usize, ks: Vec<ark_bn254::Fr>, qs: Vec<ark_bn254::G1Affine>) -> Vec<Script> {
    let num_pubs = qs.len();
    let chunks = G1Affine::hinted_scalar_mul_by_constant_g1(ks.clone(), qs.clone(), window as u32);

    // [G1AccDashHash, G1AccHash, k0, k1, k2]
    // [Dec, G1Acc]

    let mut chunk_scripts = vec![];
    for (msm_tap_index, chunk) in chunks.iter().enumerate() {
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
                {chunk.1.clone()}
                //M: [G1AccDash]
                //A: [G1AccDashHash]
            )
        } else {
            script!(
                // [Dec, G1Acc]
                for _ in 0..num_pubs {
                    {Fr::fromaltstack()}
                }
                for i in 0..num_pubs {
                    {Fr::roll(i as u32)}
                }
                for i in 0..Fq::N_LIMBS * 2 { // bring acc from top of stack
                    OP_DEPTH {i+1} OP_SUB OP_PICK 
                }
                {Fq2::toaltstack()}
                // [Dec, k0, k1, k2]
                {chunk.1.clone()}
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
                {hash_fp2()} 
                {Fq::fromaltstack()}
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
        chunk_scripts.push(sc);
    }
    chunk_scripts
}

pub(crate) fn hint_msm(window: usize, ks: Vec<ark_bn254::Fr>, qs: Vec<ark_bn254::G1Affine>) -> Vec<(ElemG1Point, Script)> {
    let res: Vec<(ElemG1Point, Script)> = bn254::curves::G1Affine::hinted_scalar_mul_by_constant_g1(ks, qs, window as u32).iter().map(|f| {
        let hint_script = script!(
            for hint in &f.2 {
                {hint.push()}
            }            
        );
        (f.0, hint_script)
    }).collect();
    res
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
        bn254::{curves, fq2::Fq2, utils::fr_push_not_montgomery}, chunk::primitves::extern_nibbles_to_limbs, execute_script_without_stack_limit
    };
    use super::*;
    use ark_bn254::{G1Affine};
    use ark_ff::{Field, UniformRand};
    
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

        let window = 7;
        let scrs_msm = tap_msm(window, scalars.clone(), qs.clone());
        let hints_msm = hint_msm(window, scalars.clone(), qs.clone());

        for msm_chunk_index in 0..scrs_msm.len() {
            let bitcom_scr = script!{
                for i in extern_nibbles_to_limbs(hints_msm[msm_chunk_index].0.out()) {
                    {i}
                }
                {Fq::toaltstack()}
                if msm_chunk_index > 0 {
                    for i in extern_nibbles_to_limbs(hints_msm[msm_chunk_index-1].0.out()) {
                        {i}
                    }
                    {Fq::toaltstack()}
                }
    
                for scalar in &scalars {
                    {fr_push_not_montgomery(*scalar)}
                    {Fr::toaltstack()}  
                }
            };
    
    
            let tap_len = scrs_msm[msm_chunk_index].len();
            let script = script! {
                {hints_msm[msm_chunk_index].1.clone()}
                {bitcom_scr}
                {scrs_msm[msm_chunk_index].clone()}
            };
    
            let res = execute_script_without_stack_limit(script);
            println!("{} script {} stack {}", msm_chunk_index, tap_len, res.stats.max_nb_stack_items);
    
            assert!(!res.success);
            assert!(res.final_stack.len() == 1);
        }


    }


}
