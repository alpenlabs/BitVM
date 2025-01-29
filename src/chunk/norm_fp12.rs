use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;
use core::ops::Neg;
use std::str::FromStr;
use ark_ec::{bn::BnConfig,  CurveGroup};
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq6_push_not_montgomery, hinted_ell_by_constant_affine, Hint};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::primitves::{
    extern_nibbles_to_limbs, hash_fp12_192 
};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ff::{ Fp12Config, Fp6Config};

use super::element::*;

// p1 should have been precomputed
pub fn multi_miller_loop_affine_norm(ps: Vec<ark_bn254::G1Affine>, qs: Vec<ark_bn254::G2Affine>, gc: ark_bn254::Fq12, s: ark_bn254::Fq12) -> ark_bn254::fq12::Fq12 {
    let beta_12x = BigUint::from_str(
        "21575463638280843010398324269430826099269044274347216827212613867836435027261",
    )
    .unwrap();
    let beta_12y = BigUint::from_str(
        "10307601595873709700152284273816112264069230130616436755625194854815875713954",
    )
    .unwrap();
    let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_12x.clone()),
        ark_bn254::Fq::from(beta_12y.clone()),
    ])
    .unwrap();
    let beta_13x = BigUint::from_str(
        "2821565182194536844548159561693502659359617185244120367078079554186484126554",
    )
    .unwrap();
    let beta_13y = BigUint::from_str(
        "3505843767911556378687030309984248845540243509899259641013678093033130930403",
    )
    .unwrap();
    let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_13x.clone()),
        ark_bn254::Fq::from(beta_13y.clone()),
    ])
    .unwrap();
    let beta_22x = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_22x.clone()),
        ark_bn254::Fq::from(beta_22y.clone()),
    ])
    .unwrap();

    let mut cinv = gc.inverse().unwrap();
    cinv = ark_bn254::Fq12::new(cinv.c0/cinv.c1, ark_bn254::Fq6::ONE);
    let mut c =  gc.clone();
    c = ark_bn254::Fq12::new(c.c0/c.c1, ark_bn254::Fq6::ONE);
    
    // let mut f = ark_bn254::Fq12::ONE;
    let mut f = cinv.clone();
    
    let mut ts = qs.clone();
    let ps: Vec<ark_bn254::G1Affine> = ps.iter().map(|p1|ark_bn254::G1Affine::new_unchecked(-p1.x/p1.y, p1.y.inverse().unwrap())).collect();
    let num_pairings = ps.len();
    for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
        // square
        f = f * f;
        if f.c1 != ark_bn254::Fq6::ZERO {
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
        }
        // f = f * f;
        // f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);


        // double and eval
        for i in 0..num_pairings {
            let t = ts[i].clone();
            let p = ps[i].clone();
            let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f = f * le;
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    
            ts[i] = (t + t).into_affine();
        }



        if ate_bit == 1 || ate_bit == -1 {
            let c_or_cinv = if ate_bit == -1 { c.clone() } else { cinv.clone() };
            f = f * c_or_cinv;
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

            for i in 0..num_pairings {
                let t = ts[i].clone();
                let mut q = qs[i].clone();
                let p = ps[i].clone();

                if ate_bit == -1 {
                    q = q.neg();
                };
                let alpha = (t.y - q.y) / (t.x - q.x);
                let neg_bias = alpha * t.x - t.y;
    
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x);
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y);
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;
    
                f = f * le;
                f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

                ts[i] = (t + q).into_affine();
            }
        }

    }
    let cinv_q = cinv.frobenius_map(1);
    let c_q2 = c.frobenius_map(2);
    let cinv_q3 = cinv.frobenius_map(3);

    for mut cq in vec![cinv_q, c_q2, cinv_q3] {
        cq = ark_bn254::Fq12::new(cq.c0/cq.c1, ark_bn254::Fq6::ONE); 
        f = f * cq;
        f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    }

    f = f * s;
    f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

    for i in 0..num_pairings {
        let mut q = qs[i].clone();
        let t = ts[i].clone();
        let p = ps[i].clone();
        
        q.x.conjugate_in_place();
        q.x = q.x * beta_12;
        q.y.conjugate_in_place();
        q.y = q.y * beta_13;
        let alpha = (t.y - q.y) / (t.x - q.x);
        let neg_bias = alpha * t.x - t.y;
        let mut le0 = alpha;
        le0.mul_assign_by_fp(&p.x);
        let mut le1 = neg_bias;
        le1.mul_assign_by_fp(&p.y);
        let mut le = ark_bn254::Fq12::ZERO;
        le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
        le.c1.c0 = le0;
        le.c1.c1 = le1;
    
        f = f * le;
        f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    
        ts[i] = (t + q).into_affine();
    }


    // t + q^3
    for i in 0..num_pairings {
        let mut q = qs[i].clone();
        let t = ts[i].clone();
        let p = ps[i].clone();

        q.x = q.x * beta_22;
    
        let alpha = (t.y - q.y) / (t.x - q.x);
        let neg_bias = alpha * t.x - t.y;
        let mut le0 = alpha;
        le0.mul_assign_by_fp(&p.x);
        let mut le1 = neg_bias;
        le1.mul_assign_by_fp(&p.y);
        let mut le = ark_bn254::Fq12::ZERO;
        le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
        le.c1.c0 = le0;
        le.c1.c1 = le1;
    
        f = f * le;
        if f.c1 != ark_bn254::Fq6::ZERO {
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
        }
        ts[i] = (t + q).into_affine();
    }
    f
}


pub(crate) fn hinted_dense_dense_mul(a: ElemFp6, b: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
    let denom = ark_bn254::Fq6::ONE + a * b * beta_sq;
    let c = (a + b)/denom;

    let (ab_scr, ab_hints) = Fq6::hinted_mul(6, a, 0, b);
    let (denom_mul_c_scr, denom_mul_c_hints) = Fq6::hinted_mul(6, denom, 0, c);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, b, c] []
        {Fq6::toaltstack()}
        // [a b] [c]
        {Fq12::copy(0)}
        // [hints a, b, a, b] [c]
        {ab_scr}
        // [hints, a, b, ab]
        {mul_by_beta_sq_scr}
        // [hints, a, b, ab*beta_sq]
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, a, b, denom]
        {Fq6::fromaltstack()}
        // [hints, a, b, denom, c]
        {Fq6::copy(0)}
        // [hints, a, b, denom, c, c]
        {Fq6::roll(12)} {Fq6::roll(12)}
        // [hints, a, b, c, denom, c]

        {denom_mul_c_scr}

        // [a, b c, denom_c]
        {Fq12::copy(12)}
        // [a, b c, denom_c, a b]
        {Fq6::add(6, 0)}
        // [a, b c, denom_c, a+b]
        {Fq6::equalverify()}
        // [a,c] []
    );

    let mut hints = vec![];
    hints.extend_from_slice(&ab_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    return (c, scr, hints);
}


pub(crate) fn hinted_sparse_sparse_mul(a: ElemFp6, b: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
    let denom = ark_bn254::Fq6::ONE + a * b * beta_sq;
    let c = (a + b)/denom;

 
    let (ab, ab_scr, ab_hints) = utils_fq6_hinted_ss_mul(a, b);
    assert_eq!(ab, a*b);
    let (denom_mul_c_scr, denom_mul_c_hints) = Fq6::hinted_mul(6, denom, 0, c);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, b, c] []
        {Fq6::toaltstack()}
        // [a b] [c]
        {Fq12::copy(0)}
        // [hints a, b, a, b] [c]
        {ab_scr}
        // [hints, a, b, ab]
        {mul_by_beta_sq_scr}
        // [hints, a, b, ab*beta_sq]
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, a, b, denom]
        {Fq6::fromaltstack()}
        // [hints, a, b, denom, c]
        {Fq6::copy(0)}
        // [hints, a, b, denom, c, c]
        {Fq6::roll(12)} {Fq6::roll(12)}
        // [hints, a, b, c, denom, c]

        {denom_mul_c_scr}

        // [a, b c, denom_c]
        {Fq12::copy(12)}
        // [a, b c, denom_c, a b]
        {Fq6::add(6, 0)}
        // [a, b c, denom_c, a+b]
        {Fq6::equalverify()}
        // [a,c] []
    );

    let mut hints = vec![];
    hints.extend_from_slice(&ab_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    return (c, scr, hints);
}


fn utils_fq6_hinted_ss_mul(m: ElemFp6, n: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let d = n.c0;
    let e = n.c1;

    let g = a * d;
    let h = b * d + a * e;
    let i = b * e;
    let result = ark_bn254::Fq6::new(g, h, i);

    let (g_scr, g_hints) = Fq2::hinted_mul(2, d, 0, a);
    let (h_scr, h_hints) = Fq2::hinted_mul_lc4_keep_elements(b, d, e, a);
    let (i_scr, i_hints) = Fq2::hinted_mul(2, e, 0, b);

    let mut hints = vec![];
    for hint in vec![i_hints, g_hints, h_hints] {
        hints.extend_from_slice(&hint);
    }

    let scr = script!(
        // [a, b, d, e]
        {Fq2::copy(0)} {Fq2::copy(6)}
        // [a, b, d, e, e, b]
        {i_scr}
        // [a, b, d, e, i]
        {Fq2::toaltstack()}
        // [a, b, d, e]
        {Fq2::toaltstack()}
        {Fq2::copy(0)} {Fq2::copy(6)}
        // [a, b, d, d, a] [i, e]
        {g_scr}
        // [a, b, d, g] [i, e]
        {Fq2::fromaltstack()} {Fq2::roll(2)}
        {Fq2::toaltstack()}
        // [a, b, d, e] [i, g]
        {Fq2::roll(6)}
        // [b, d, e, a] [i, g]
        {h_scr} {Fq2::toaltstack()}
        // [b, d, e, a] [i, g, h]
        {Fq6::roll(2)}
        // [a, b, d, e] [i, g, h]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq2::roll(2)} {Fq2::fromaltstack()}
        // [a, b, d, e, g, h, i] 
    );
    (result, scr, hints)
}

fn utils_fq6_hinted_sd_mul(m: ElemFp6, n: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let c = m.c2;
    let e = n.c1;
    let f = n.c2;

    let g = (b * f + c * e) * ark_bn254::Fq6Config::NONRESIDUE;
    let h = (a*e ) + (c * f) * ark_bn254::Fq6Config::NONRESIDUE;
    let i = b * e + a * f;
    let result = ark_bn254::Fq6::new(g, h, i);

    let mut hints = vec![];
    let (i_scr, i_hints) = Fq2::hinted_mul_lc4_keep_elements(e, b, f, a);
    let (h_scr, h_hints) = Fq2::hinted_mul_lc4(f * ark_bn254::Fq6Config::NONRESIDUE, c, e, a);
    let (g_scr, g_hints) = Fq2::hinted_mul_lc4_keep_elements(c, e, f, b);


    for hint in vec![i_hints, h_hints, g_hints] {
        hints.extend_from_slice(&hint);
    }

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
    );

    let scr = script!(
        // [a, b, c, e, f]
        {Fq2::toaltstack()} {Fq2::roll(4)}
        {Fq2::fromaltstack()} {Fq2::roll(8)}
        // [c, e, b, f, a]
        {i_scr}
        // [c, e, b, f, a, i]
        {Fq2::toaltstack()}
        // [c, e, b, f, a]
        {Fq2::roll(4)} {Fq2::roll(8)}
        // [e, f, a, b, c]
        {Fq2::roll(8)} {Fq2::roll(8)}
        // [a, b, c, e, f]
        {Fq2::copy(0)}
        // [a, b, c, e, f, f]
        {mul_by_beta_sq_scr.clone()}
        {Fq2::copy(6)}
        // [a, b, c, e, f, f_beta, c]
        {Fq2::copy(6)} {Fq2::copy(14)}
        // [a, b, c, e, f, f_beta, c, e, a]
        {h_scr} 
        // [a, b, c, e, f, h]
        {Fq2::toaltstack()}
        // [a, b, c, e, f] [i, h]
        {Fq2::roll(6)}
        // [a, c, e, f, b] [i, h]
        {g_scr}
        // [c, e, f, b ce + fb] [i, h]
        {mul_by_beta_sq_scr}
        // [a, c, e, f, b, g] [i, h]
        {Fq2::toaltstack()}
        // [a, c, e, f, b] [i, h, g]
        {Fq2::roll(6)} {Fq2::roll(6)} {Fq2::roll(6)}
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        // [b, c, e, f, g, h, i]
    );
    (result, scr, hints)
}

pub(crate) fn hinted_square(a: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
    let denom = (ark_bn254::Fq6::ONE + a * a * beta_sq);
    let c = (a + a)/denom;

    let (asq_scr, asq_hints) = Fq6::hinted_square(a);
    let (denom_mul_c_scr, denom_mul_c_hints) = Fq6::hinted_mul(6, denom, 0, c);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, c] []
        {Fq6::toaltstack()}
        // [a] [c]
        {Fq6::copy(0)}
        // [hints a, a] [c]
        {asq_scr}
        // [hints, a, asq]
        {mul_by_beta_sq_scr}
        // [hints, a, asq*beta_sq]
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, a, denom]
        {Fq6::fromaltstack()}
        // [hints, a, denom, c]
        {Fq6::copy(0)}
        // [hints, a, denom, c, c]
        {Fq6::roll(12)} {Fq6::roll(12)}
        // [hints, a, c, denom, c]

        {denom_mul_c_scr}

        // [a, c, denom_c]
        {Fq6::copy(12)}
        // [a, c, denom_c, a]
        {Fq6::double(0)}
        // [a, c, denom_c, 2a]
        {Fq6::equalverify()}
        // [a,c] []
    );

    let mut hints = vec![];
    hints.extend_from_slice(&asq_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    return (c, scr, hints);
}

#[cfg(test)]
mod test {
    use ark_ff::{AdditiveGroup, Field, Fp12Config, Fp2Config, Fp6Config, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6, utils::{fq2_push_not_montgomery, fq6_push_not_montgomery}}, chunk::{element::{ElemTraitExt, Element, ElementType}, norm_fp12::{utils_fq6_hinted_ss_mul, hinted_dense_dense_mul, hinted_square}, primitves::{extern_nibbles_to_limbs, hash_fp2, hash_fp4, hash_fp6}, taps_mul::*}, execute_script, execute_script_without_stack_limit};

    use super::{utils_fq6_hinted_sd_mul};

    #[test]
    fn test_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = hinted_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);

        let f6_hints = Element::Fp6(f_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let h6_hints = Element::Fp6(h_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        mul_hints.extend_from_slice(&f6_hints);
        mul_hints.extend_from_slice(&h6_hints);

        let tap_len = h_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            {h_scr}
            {fq6_push_not_montgomery(h_n.c1)}
            {Fq6::equalverify()}
            {fq6_push_not_montgomery(f_n.c1)}
            {Fq6::equalverify()}
            OP_TRUE
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_chunk_dense_dense_mul_v2() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = hinted_dense_dense_mul(f_n.c1, g_n.c1);
        assert_eq!(h_n.c1, hint_out);

        let f6_hints = Element::Fp6(f_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let g6_hints = Element::Fp6(g_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let h6_hints = Element::Fp6(h_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        mul_hints.extend_from_slice(&f6_hints);
        mul_hints.extend_from_slice(&g6_hints);
        mul_hints.extend_from_slice(&h6_hints);

        let tap_len = h_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            {h_scr}
            {fq6_push_not_montgomery(h_n.c1)}
            {Fq6::equalverify()}
            {fq6_push_not_montgomery(g_n.c1)}
            {Fq6::equalverify()}
            {fq6_push_not_montgomery(f_n.c1)}
            {Fq6::equalverify()}
            OP_TRUE
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_hinted_fq6_mul_le0_le0() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        m.c2 = ark_bn254::Fq2::ZERO;
        n.c2 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_hinted_ss_mul(m, n);
        assert_eq!(res, o);
        let ops_len = ops_scr.len();
        let scr = script!(
            for h in hints {
                {h.push()}
            }
            {fq2_push_not_montgomery(m.c0)}
            {fq2_push_not_montgomery(m.c1)}
            {fq2_push_not_montgomery(n.c0)}
            {fq2_push_not_montgomery(n.c1)}
            {ops_scr}
            {fq6_push_not_montgomery(o)}
            {Fq6::equalverify()}

            // inputs are in right order
            {fq2_push_not_montgomery(n.c1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(n.c0)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(m.c1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(m.c0)}
            {Fq2::equalverify()}
            OP_TRUE
        );
        let res = execute_script_without_stack_limit(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        println!("scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

    }


    #[test]
    fn test_hinted_fq6_mul_le0_le1() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        n.c0 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_hinted_sd_mul(m, n);

        assert_eq!(res, o);
        let ops_len = ops_scr.len();
        let scr = script!(
            for h in hints {
                {h.push()}
            }
            {fq2_push_not_montgomery(m.c0)}
            {fq2_push_not_montgomery(m.c1)}
            {fq2_push_not_montgomery(m.c2)}
            {fq2_push_not_montgomery(n.c1)}
            {fq2_push_not_montgomery(n.c2)}
            {ops_scr}
            {fq6_push_not_montgomery(o)}

            {Fq6::equalverify()}

            // inputs are in right order
            {fq2_push_not_montgomery(n.c2)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(n.c1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(m.c2)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(m.c1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(m.c0)}
            {Fq2::equalverify()}
            OP_TRUE
        );
        let res = execute_script_without_stack_limit(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        println!("scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

    }

}

