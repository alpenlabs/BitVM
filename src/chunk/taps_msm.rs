use std::ops::Neg;
use std::str::FromStr;

use crate::bn254::curves::G1Affine;
use crate::bn254::{self};
use crate::bn254::fr::Fr;
use crate::bn254::utils::{fq2_push_not_montgomery, fq_push_not_montgomery, hinted_from_eval_point, Hint};
use crate::chunk::primitves::extern_hash_fps;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use num_traits::One;

use super::blake3compiled::hash_messages;
use super::element::{ElemFq, ElemG1Point, ElemTraitExt, ElementType};
use super::primitves::{hash_fp2, HashBytes};
use crate::bn254::fq2::Fq2;

pub(crate) fn chunk_msm(window: usize, ks: Vec<ark_bn254::Fr>, qs: Vec<ark_bn254::G1Affine>) -> Vec<(ElemG1Point, Script, Vec<Hint>)> {
    let num_pubs = qs.len();
    let chunks = G1Affine::hinted_scalar_mul_by_constant_g1(ks.clone(), qs.clone(), window as u32);

    // [G1AccDashHash, G1AccHash, k0, k1, k2]
    // [Dec, G1Acc]

    let mut chunk_scripts = vec![];
    for (msm_tap_index, chunk) in chunks.iter().enumerate() {
        let ops_script = 
        if msm_tap_index == 0 {
            script!(
                {bn254::curves::G1Affine::push_not_montgomery( ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO))}
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
                // [Dec, G1Acc, k0, k1, k2]      
                {Fq2::copy(num_pubs as u32)}          
                {Fq2::toaltstack()}
                // [Dec, G1Acc, k0, k1, k2]
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


        chunk_scripts.push((chunk.0, sc, chunk.2.clone()));
    }
    chunk_scripts
}

// Hash P
//vk0: G1Affine

pub(crate) fn chunk_hash_p(
    hint_in_t: ElemG1Point,
    hint_in_q: ark_bn254::G1Affine,
) -> (ElemG1Point, Script, Vec<Hint>) {
    // r (gp3) = t(msm) + q(vk0)
    let (tx, qx, ty, qy) = (hint_in_t.x, hint_in_q.x, hint_in_t.y, hint_in_q.y);
    let t = ark_bn254::G1Affine::new_unchecked(tx, ty);
    let q = ark_bn254::G1Affine::new_unchecked(qx, qy);
    let (add_scr, add_hints) = bn254::curves::G1Affine::hinted_check_add(t, q);
    let mut r = (t + q).into_affine();
    if r.y.inverse().is_none() {
        r = ElemG1Point::mock();
    }

    let rdy = r.y.inverse().unwrap();
    let rdx = -r.x * rdy;
    let rd = ark_bn254::G1Affine::new_unchecked(rdx, rdy);

    let (on_curve_scr, on_curve_hint) = crate::bn254::curves::G1Affine::hinted_is_on_curve(r.x, r.y);
    let (eval_xy, eval_hints) = hinted_from_eval_point(ark_bn254::G1Affine::new_unchecked(r.x, r.y));    

    let ops_script = script!{
        // [t] [hash_rd, hash_t]
        { Fq2::copy(0)} 
        // [t, t]
        {G1Affine::push_not_montgomery(q)}
        // [t, t, q]
        {add_scr}
        // [t, r]
        {Fq::is_zero_keep_element(0)}
        OP_IF 
            // drop altstack
            {Fq2::fromaltstack()} {Fq2::drop()}
            // drop stack
            {G1Affine::drop()} {G1Affine::drop()}
            for i in 0..eval_hints.len()+on_curve_hint.len() {
                {Fq::drop()}
            }
        OP_ELSE
            // [hints, r]
            {Fq2::copy(0)}
            {on_curve_scr}
            OP_IF
                {eval_xy} 
                // [t, rd]    
                {hash_messages(vec![ElementType::MSMG1, ElementType::MSMG1])}
            OP_ELSE
                {Fq2::fromaltstack()} {Fq2::drop()}
                {G1Affine::drop()} {G1Affine::drop()}
                for i in 0..eval_hints.len() {
                    {Fq::drop()}
                }
            OP_ENDIF
        OP_ENDIF

    };

    let sc = script! {
        {ops_script}
        OP_TRUE
    };

    let mut all_hints = vec![];
    all_hints.extend_from_slice(&add_hints);
    all_hints.extend_from_slice(&on_curve_hint);
    all_hints.extend_from_slice(&eval_hints);

    (rd, sc, all_hints)
}


#[cfg(test)]
mod test {

    use crate::{
        bn254::{curves, fq2::Fq2, utils::fr_push_not_montgomery}, chunk::{element::Element, primitves::extern_nibbles_to_limbs}, execute_script_without_stack_limit
    };
    use super::*;
    use ark_bn254::{G1Affine};
    use ark_ff::{Field, UniformRand};
    
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::chunk::element::ElemTraitExt;

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
    fn test_tap_hash_var_p() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let r = (t + q).into_affine();

        let (hint_out,  hash_c_scr, mut hint_script) = chunk_hash_p( t, q);
        hint_script.extend_from_slice(&Element::G1(t).get_hash_preimage_as_hints());
        
        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(t.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_len = hash_c_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
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
        let hints_msm = chunk_msm(window, scalars.clone(), qs.clone());

        for msm_chunk_index in 0..hints_msm.len() {
            let bitcom_scr = script!{
                for i in extern_nibbles_to_limbs(hints_msm[msm_chunk_index].0.hashed_output()) {
                    {i}
                }
                {Fq::toaltstack()}
                if msm_chunk_index > 0 {
                    for i in extern_nibbles_to_limbs(hints_msm[msm_chunk_index-1].0.hashed_output()) {
                        {i}
                    }
                    {Fq::toaltstack()}
                }

                for scalar in &scalars {
                    {fr_push_not_montgomery(*scalar)}
                    {Fr::toaltstack()}  
                }
            };
    
            let mut op_hints = vec![];
            if msm_chunk_index > 0 {
                op_hints.extend_from_slice(&Element::G1(hints_msm[msm_chunk_index-1].0).get_hash_preimage_as_hints());
            }
            let tap_len = hints_msm[msm_chunk_index].1.len();
            let script = script! {
                for h in &hints_msm[msm_chunk_index].2 {
                    {h.push()}
                }
                for i in op_hints {
                    {i.push()}
                }
                {bitcom_scr}
                {hints_msm[msm_chunk_index].1.clone()}
            };
    
            let res = execute_script_without_stack_limit(script);
            println!("{} script {} stack {}", msm_chunk_index, tap_len, res.stats.max_nb_stack_items);
    
            assert!(!res.success);
            assert!(res.final_stack.len() == 1);
        }


    }


}
