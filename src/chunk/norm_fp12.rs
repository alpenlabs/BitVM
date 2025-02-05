use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;
use core::ops::Neg;
use std::str::FromStr;
use ark_ec::{bn::BnConfig,  CurveGroup};
use crate::bn254;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{fq2_push_not_montgomery, fq6_push_not_montgomery, hinted_ell_by_constant_affine, Hint};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::taps_point_ops::utils_point_add_eval_ate;
use crate::{
    bn254::{fq::Fq},
    treepp::*,
};
use ark_ff::{ Fp12Config, Fp6Config};

use super::element::*;
use super::taps_point_eval::utils_multiply_by_line_eval;
use super::taps_point_ops::{utils_point_add_eval, utils_point_double_eval};

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


pub(crate) fn utils_fq12_mul(a: ElemFp6, b: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
    let denom = ark_bn254::Fq6::ONE + a * b * beta_sq;
    let c = (a + b)/denom;

    let (ab, ab_scr, ab_hints) = {
        let r = Fq6::hinted_mul(6, a, 0, b);
        (a*b, r.0, r.1)
    };
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
        {Fq12::roll(6)}
        // [hints, a, b, c, denom, c]

        {denom_mul_c_scr}

        // [a, b c, denom_c]
        {Fq12::copy(12)}
        // [a, b c, denom_c, a b]
        {Fq6::add(6, 0)}
        // [a, b c, denom_c, a+b]
        {Fq6::equalverify()}
        // [a, b, c] []
    );

    let mut hints = vec![];
    hints.extend_from_slice(&ab_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    return (c, scr, hints);
}

pub(crate) fn utils_fq6_ss_mul_keep_element(m: ElemFp6, n: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
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

pub(crate) fn chunk_hinted_square(a: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let (asq, asq_scr, asq_hints) = hinted_square(a);
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
    );
    let scr = script!(
        // [hints, a, c] [chash, ahash]
        {asq_scr}
        // [a, c] [chash, ahash]
    );

    (asq, scr, asq_hints)
}

pub(crate) fn chunk_dense_dense_mul(a: ElemFp6, b:ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let (amulb, amulb_scr, amulb_hints) = utils_fq12_mul(a, b);
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
    );
    let scr = script!(
        // [hints, a, b, c] [chash, bhash, ahash]
        {amulb_scr}
        // [a, b, c] [chash, bhash, ahash]
    );

    (amulb, scr, amulb_hints)
}

pub(crate) fn chunk_frob_fp12(f: ElemFp6, power: usize) -> (ark_bn254::Fq6, Script, Vec<Hint>) {

    let fp12 = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f);
    let (hinted_frob_scr, hints_frobenius_map) = Fq12::hinted_frobenius_map(power, fp12);
    let g = fp12.frobenius_map(power);

    let ops_scr = script! {
        // [f]
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::copy(6)}
        // [f, (1, f)]
        {hinted_frob_scr}
        // [f, (1, g)]
        {Fq6::roll(6)} 
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::equalverify()}
        // [f, g]
    };

    (g.c1, ops_scr, hints_frobenius_map)
}
 
pub(crate) fn hinted_square(a: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let denom = ark_bn254::Fq6::ONE + a * a * ark_bn254::Fq12Config::NONRESIDUE;
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

pub(crate) fn point_ops_and_mul(
    is_dbl: bool, is_frob: Option<bool>, ate_bit: Option<i8>,
    t4: ark_bn254::G2Affine, p4: ark_bn254::G1Affine, 
    q4: Option<ark_bn254::G2Affine>,

    p3: ark_bn254::G1Affine,
    t3: ark_bn254::G2Affine, q3: Option<ark_bn254::G2Affine>,
    p2: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine, q2: Option<ark_bn254::G2Affine>,
) -> (ElemG2Eval, Script, Vec<Hint> ) {
    // a, b, tx, ty, px, py
    let ((nt, (le0, le1)), nt_scr, nt_hints) = if is_dbl {
        //[a, b, tx, ty, px, py]
        utils_point_double_eval(t4, p4)
    } else {
        // a, b, tx, ty, qx, qy, px, py
        assert!(q4.is_some());
        utils_point_add_eval_ate(t4, q4.unwrap(), p4, is_frob.unwrap(), ate_bit.unwrap())
    };
    let le = ark_bn254::Fq6::new(le0, le1, ark_bn254::Fq2::ZERO);


    let (alpha_t3, neg_bias_t3) = if is_dbl {
        let alpha_t3 = (t3.x.square() + t3.x.square() + t3.x.square()) / (t3.y + t3.y); 
        let neg_bias_t3 = alpha_t3 * t3.x - t3.y;
        (alpha_t3, neg_bias_t3)
    } else {
        let q3 = q3.unwrap();
        let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x); 
        let neg_bias_t3 = alpha_t3 * t3.x - t3.y;
        (alpha_t3, neg_bias_t3)
    };

    let (alpha_t2, neg_bias_t2) = if is_dbl {
        let alpha_t2 = (t2.x.square() + t2.x.square() + t2.x.square()) / (t2.y + t2.y); 
        let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
        (alpha_t2, neg_bias_t2)
    } else {
        let q2 = q2.unwrap();
        let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x); 
        let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
        (alpha_t2, neg_bias_t2)
    };

    let (g, fg_scr, fg_hints) = utils_multiply_by_line_eval(le, alpha_t3, neg_bias_t3, p3);
    let fg = le * g;
    let fpg = le + g;


    let (hinted_ell_t2, hints_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, neg_bias_t2);
    let mut t2le_a = alpha_t2;
    t2le_a.mul_assign_by_fp(&p2.x);
    let mut t2le_b = neg_bias_t2;
    t2le_b.mul_assign_by_fp(&p2.y);

    let mut t3le_a = alpha_t3;
    t3le_a.mul_assign_by_fp(&p3.x);
    let mut t3le_b = neg_bias_t3;
    t3le_b.mul_assign_by_fp(&p3.y);

    let res_hint = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, le) * 
    ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, ark_bn254::Fq6::new(t2le_a, t2le_b, ark_bn254::Fq2::ZERO)) * 
    ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, ark_bn254::Fq6::new(t3le_a, t3le_b, ark_bn254::Fq2::ZERO));
    

    let mut hints = vec![];
    hints.extend_from_slice(&nt_hints);
    hints.extend_from_slice(&fg_hints);
    hints.extend_from_slice(&hints_ell_t2);

    let ops_scr = script!(
        // [hints, t4, (q4), p4, p3, p2]
        {Fq2::toaltstack()}
        {Fq2::copy(2)} {Fq2::toaltstack()}
        {Fq2::toaltstack()}
        // [hints, t4, (q4), p4] [p2, p4, p3]
        {nt_scr}
        // [hints, t4, nt4, le0, le1] [p2, p4, p3]
        // [hints, t4, nt4, le] [p2, p4, p3]
        {Fq2::fromaltstack()}
        // [hints, t4, nt4, le, p3] [p2, p4]
        {fg_scr}
        // [t4, nt4, p3, g, f, fg] [p2, p4]
        {Fq6::toaltstack()}
        // [t4, nt4, p3, g0, g1, f0, f1] [p2, p4, fg]
        {Fq2::add(6, 2)}
        {Fq2::add(4, 2)} 
        {Fq6::fromaltstack()}
        // [t4, nt4, p3, g+f, fg] [p2, p4]
        {Fq2::fromaltstack()}
        // [t4, nt4, p3, g+f, fg, p4] [p2]
        {Fq2::fromaltstack()}
        {Fq2::copy(0)}
        {fq2_push_not_montgomery(alpha_t2)}
        {fq2_push_not_montgomery(neg_bias_t2)}
        // [t4, nt4, p3, g+f, fg, p4, p2, p2, a, b] []
        {Fq2::roll(4)}
        {hinted_ell_t2}
        // [t4, nt4, p3, g+f, fg, p4, p2, p2le] []
    );
    let rearrange_scr = script!(
        // [t4, nt4, p3, g+f, fg, p4, p2, p2le] 
        {Fq6::toaltstack()}
        {Fq2::roll(12)}
        {Fq2::fromaltstack()}
        // [t4, nt4, g+f, fg, p4, p3, p2] [p2le]
        {Fq2::roll(18)} {Fq2::roll(18)}
         // [t4, g+f, fg, p4, p3, p2, nt4] [p2le]

        for _ in 0..5 {
            {Fq2::roll(18)}
        }
         // [t4, p4, p3, p2, nt4, g+f, fg] [p2le]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        // [t4, p4, p3, p2, nt4, g+f, fg, p2le]
    );

    let scr = script!(
        {ops_scr}
        {rearrange_scr}
    );

    let hout = ElemG2Eval{
        t: nt,
        p2le: [t2le_a, t2le_b],
        ab: fg,
        apb: [fpg.c0, fpg.c1],
        res_hint: res_hint.c1/res_hint.c0,
    };

    (hout, scr, hints)

}


pub(crate) fn chunk_point_ops_and_mul(
    is_dbl: bool, is_frob: Option<bool>, ate_bit: Option<i8>,
    t4: ElemG2Eval, p4: ElemG1Point, 
    q4: Option<ark_bn254::G2Affine>,
    p3: ElemG1Point,
    t3: ark_bn254::G2Affine, q3: Option<ark_bn254::G2Affine>,
    p2: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine, q2: Option<ark_bn254::G2Affine>,
) -> (ElemG2Eval, Script, Vec<Hint> ) {
    let (hint_out, ops_scr, hints) = point_ops_and_mul(is_dbl, is_frob, ate_bit, t4.t, p4, q4, p3, t3, q3, p2, t2, q2);
    let pre_hash_scr = script!(
        // [t4, p4, p3, p2, nt4, F] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {Fq::fromaltstack()}
        // [t4, p4, p3, p2, nt4, F, ht4_le] [outhash, p3hash, p4hash, in_t4hash]
        for _ in 0..(2+2+2+4+14) {
            {Fq::roll(24)}
        }
        // [t4, ht4_le, p4, p3, p2, nt4, F] [outhash, p3hash, p4hash, in_t4hash]
    );
    let _hash_scr = script!(
        // [t4, ht4_le, p4, p3, nt4, fg] [outhash, p3hash, p4hash, in_t4hash]
        {hash_messages(vec![ElementType::G2EvalPoint, ElementType::G1, ElementType::G1, ElementType::G1, ElementType::G2Eval])}
    );

    let pre_ops_scr = script!(
        // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash (q4)]
        if !is_dbl {
            // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash q4]
            for _ in 0..4 {
                {Fq::fromaltstack()} // q
            }
            // [hints, {t4, ht4_le}, p4, p3, p2, q4] [outhash, p2hash, p3hash, p4hash, in_t4hash]
            {Fq::roll(10)} {Fq::toaltstack()}
            // [hints, t4, p4, p3, p2, q4] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
            {Fq6::roll(4)}
            // [hints, t4, q4, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        } else {
            // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
            {Fq::roll(6)} {Fq::toaltstack()}
            // [hints, t4, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        }
    );

    let scr = script!(
        {pre_ops_scr}
        // [hints, t4, (q4), p4, p3] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {ops_scr}
        // [t4, p4, p3, nt4, fg] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {pre_hash_scr}
       // {hash_scr}
    );

    (hint_out, scr, hints)
}

pub(crate) fn chunk_complete_point_eval_and_mul(f: ElemG2Eval) -> (ElemFp6, Script, Vec<Hint>) {
    let (ops_res, ops_scr, ops_hints) = complete_point_eval_and_mul(f);
    let scr = script!(
        // [hints, apb, Ab, c, h, Haux_in] [hash_h, hash_in]
        {Fq::toaltstack()}
        // [hints, {apb, Ab, c}, h] [hash_h, hash_in, Haux_in]
        {ops_scr}
        // [{apb, Ab, c}, h] [hash_h, hash_in, Haux_in]
        {Fq::fromaltstack()}
        // [{apb, Ab, c}, h, Haux_in] [hash_h, hash_in]
        {Fq6::roll(1)}
        // [{apb, Ab, c, Haux_in}, h] [hash_h, hash_in]
    );

    let _hash_scr = script!(
        // [t4, ht4_le, p4, p3, nt4, fg] [outhash, p3hash, p4hash, in_t4hash]
        {hash_messages(vec![ElementType::G2EvalMul, ElementType::Fp6])}
        OP_TRUE
    );

    (ops_res, scr, ops_hints)
}

pub(crate) fn complete_point_eval_and_mul(
    f: ElemG2Eval,
) -> (ElemFp6, Script, Vec<Hint>) {
    let ab = f.ab;
    let apb = ark_bn254::Fq6::new( f.apb[0],  f.apb[1], ark_bn254::Fq2::ZERO);
    let c = ark_bn254::Fq6::new( f.p2le[0],  f.p2le[1], ark_bn254::Fq2::ZERO);

    let abc_beta_sq = ab * c * ark_bn254::Fq12Config::NONRESIDUE;
    let apbpc = apb + c;
    let numerator = apbpc + abc_beta_sq;

    let apb_mul_c = c * apb;
    let denom = ark_bn254::Fq6::ONE + (apb_mul_c + ab) * ark_bn254::Fq12Config::NONRESIDUE;

    assert_eq!(f.res_hint * denom, numerator);

    let (abc_out, abc_scr, abc_hints) = utils_fq6_hinted_sd_mul(ab, c);
    assert_eq!(abc_out, ab*c);
    let (apb_mul_c_out, apb_mul_c_scr, apb_mul_c_hints) = utils_fq6_ss_mul_keep_element(apb, c);
    assert_eq!(apb_mul_c, apb_mul_c_out);

    let (den_mul_h_scr, den_mul_h_hints) = Fq6::hinted_mul_keep_elements(6, denom, 0, f.res_hint);

    assert_eq!(apb_mul_c, apb_mul_c_out);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints, apb, Ab, c] [h]
        {Fq6::toaltstack()}
        {abc_scr}
        // [hints, apb, Ab, c, Abc] [h]
        {mul_by_beta_sq_scr.clone()}
        // [hints, apb, Ab, c, Abc_beta_sq] [h]
        {Fq2::copy(18)} {Fq2::copy(18)}
        // [hints, apb, Ab, c, Abc_beta_sq, apb] [h]
        {Fq2::copy(12)} {Fq2::copy(12)}
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c] [h]
        {apb_mul_c_scr}        
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c, Apb_mul_C] [h]
        {Fq6::copy(24)}
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c, Apb_mul_C, Ab] [h]
        {Fq6::add(6, 0)}
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c, Apb_mul_C_p_Ab] [h]
        {mul_by_beta_sq_scr}
        {fq6_push_not_montgomery(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c, denom] [h]
        {Fq6::toaltstack()}
        // [hints, apb, Ab, c, Abc_beta_sq, apb, c] [h, denom]
        {Fq2::add(6, 2)}
        {Fq2::add(4, 2)}
        // [hints, apb, Ab, c, Abc_beta_sq, apbpc] [h, denom]
        {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
        {Fq6::add(6, 0)}
        // [hints, apb, Ab, c, numerator] [h, denom]
        {Fq6::fromaltstack()}
        {Fq6::fromaltstack()}
        // [hints, apb, Ab, c, numerator, denom, h]
        {den_mul_h_scr}
        // [hints, apb, Ab, c, numerator, denom, h, denom_mul_h]
        {Fq12::roll(12)}
        // [hints, apb, Ab, c, h, denom_mul_h, numerator, denom]
        {Fq6::drop()}
        {Fq6::equalverify()}
        // [ apb, Ab, c, h ]
    );
    let mut hints = vec![];
    hints.extend_from_slice(&abc_hints);
    hints.extend_from_slice(&apb_mul_c_hints);
    hints.extend_from_slice(&den_mul_h_hints);
    (f.res_hint, scr, hints)
}


fn utils_fq6_hinted_sd_mul(m: ElemFp6, n: ElemFp6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let c = m.c2;
    let d = n.c0;
    let e = n.c1;

    let g = a*d + c * e * ark_bn254::Fq6Config::NONRESIDUE;
    let h = (b*d ) + (a * e);
    let i = c * d + b * e;
    let result = ark_bn254::Fq6::new(g, h, i);

    let mut hints = vec![];
    let (i_scr, i_hints) = Fq2::hinted_mul_lc4_keep_elements(c, d, e, b);
    let (h_scr, h_hints) = Fq2::hinted_mul_lc4_keep_elements(d, b, e, a); 
    let (g_scr, g_hints) = Fq2::hinted_mul_lc4_keep_elements(e * ark_bn254::Fq6Config::NONRESIDUE, c, d, a);


    for hint in vec![i_hints, h_hints, g_hints] {
        hints.extend_from_slice(&hint);
    }

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
    );

    let scr = script!(
        // [a, b, c, d, e]
        {Fq2::roll(6)}
         // [a, c, d, e, b]
        {i_scr}
        // [a, c, d, e, b, i]
        {Fq2::toaltstack()}

        // [a, c, d, e, b]
        {Fq2::roll(2)}  {Fq2::roll(8)}
        // [c, d, b, e, a]
        {h_scr} 
        {Fq2::toaltstack()}
        // [c, d, b, e, a] [i, h]
        {Fq2::copy(2)} {Fq2::toaltstack()}
        // [c, d, b, e, a] [i, h, e]
        {Fq2::toaltstack()}
        {mul_by_beta_sq_scr}
        // [c, d, b, ebeta] [i, h, e, a]
        {Fq2::roll(6)}
        // [d, b, ebeta, c] [i, h, e, a]
        {Fq2::roll(6)}
        // [b, ebeta, c, d] [i, h, e, a]
        {Fq2::fromaltstack()}
        // [b, ebeta, c, d, a] [i, h, e]
        {g_scr}
        // [b, ebeta, c, d, a, g] [i, h , e]
        {Fq2::toaltstack()}
        // [b, ebeta, c, d, a] [i, h, e, g]
        {Fq2::roll(6)} {Fq2::drop()}
         // [b, c, d, a] [i, h, e g]
        {Fq6::roll(2)}
         // [a,b, c, d,] [i, h, e, g]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} 
         // [a,b, c, d, g, e] [i, h]
         {Fq2::roll(2)} {Fq2::toaltstack()}
        //  {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
        // [a,b, c, d, e, _f] [i, h, g]
        {Fq6::fromaltstack()}
        // [a, b, c, d, e, _f, g, h, i]
    );
    (result, scr, hints)
}


#[cfg(test)]
mod test {
    use ark_ff::{AdditiveGroup, Field, Fp12Config, Fp4Config, Fp6Config, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{curves::G1Affine, fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6, utils::{fq2_push_not_montgomery, fq6_push_not_montgomery, fq_push_not_montgomery, Hint}}, chunk::{blake3compiled::hash_messages, element::{ElemG2Eval, ElemTraitExt, Element, ElementType}, norm_fp12::{chunk_complete_point_eval_and_mul, chunk_dense_dense_mul, chunk_hinted_square, chunk_point_ops_and_mul, complete_point_eval_and_mul, hinted_square, utils_fq12_mul, utils_fq6_hinted_sd_mul, utils_fq6_ss_mul_keep_element}, primitves::{extern_nibbles_to_limbs, hash_fp4, hash_fp6}, taps_mul::*}, execute_script, execute_script_without_stack_limit};

    use super::{chunk_frob_fp12, point_ops_and_mul};

    #[test]
    fn test_chunk_frob_fp12() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let power = 2;
        let (hout, hout_scr, hout_hints) = chunk_frob_fp12(f_n.c1, power);

        let preimage_hints = Element::Fp6(f_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hout.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(f_n.c1.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = hash_scr.len() + hout_scr.len();

        let scr = script!(
            for h in hout_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {hout_scr}
            {hash_scr}
        );

        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_square() {
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
    fn test_chunk_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = chunk_hinted_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);

        let mut preimage_hints = vec![];
        let f6_hints = Element::Fp6(f_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let h6_hints = Element::Fp6(h_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(f_n.c1.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = h_scr.len() + hash_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {h_scr}
            {hash_scr}
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_chunk_dense_dense_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mul_hints) = chunk_dense_dense_mul(f_n.c1, g_n.c1);
        assert_eq!(h_n.c1, hint_out);

        let mut preimage_hints = vec![];
        let f6_hints = Element::Fp6(f_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let g6_hints = Element::Fp6(g_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        let h6_hints = Element::Fp6(h_n.c1).get_hash_preimage_as_hints(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&g6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(g_n.c1.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(f_n.c1.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = h_scr.len() + hash_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {h_scr}
            {hash_scr}
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    

    #[test]
    fn test_dense_dense_mul_v2() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = utils_fq12_mul(f_n.c1, g_n.c1);
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
    fn test_dense_dense_mul_v1() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = utils_fq12_mul(f_n.c1, g_n.c1);
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
    fn test_fq6_mul_le0_le0_keep() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        m.c2 = ark_bn254::Fq2::ZERO;
        n.c2 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_ss_mul_keep_element(m, n);
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
            for v in vec![n.c1, n.c0, m.c1, m.c0] {
                {fq2_push_not_montgomery(v)}
                {Fq2::equalverify()}
            }
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
    fn test_dense_dense_mul_v0() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let mut f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        f_n.c1.c2 = ark_bn254::Fq2::ZERO;

        let g = ark_bn254::Fq12::rand(&mut prng);
        let mut g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);
        g_n.c1.c2 = ark_bn254::Fq2::ZERO;

        let h = f_n * g_n;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = utils_fq12_mul(f_n.c1, g_n.c1);
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
    fn test_point_ops_and_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let is_dbl = false;
        let is_frob: Option<bool> = Some(true);
        let ate_bit: Option<i8> = Some(1);

        assert_eq!(is_dbl, is_frob.is_none() && ate_bit.is_none());
        assert_eq!(!is_dbl, is_frob.is_some() && ate_bit.is_some());

        let (hint_out, ops_scr, ops_hints) = point_ops_and_mul(is_dbl, is_frob, ate_bit, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
     
        let mut preimage_hints = vec![];
        preimage_hints.extend_from_slice(&vec![
            Hint::Fq(t4.x.c0),
            Hint::Fq(t4.x.c1),
            Hint::Fq(t4.y.c0),
            Hint::Fq(t4.y.c1),
        ]);

        if !is_dbl {
            preimage_hints.extend_from_slice(&vec![
                Hint::Fq(q4.x.c0),
                Hint::Fq(q4.x.c1),
                Hint::Fq(q4.y.c0),
                Hint::Fq(q4.y.c1),
            ]);
        }


        preimage_hints.extend_from_slice(&vec![
            Hint::Fq(p4.x),
            Hint::Fq(p4.y),
        ]);
        preimage_hints.extend_from_slice(&vec![
            Hint::Fq(p3.x),
            Hint::Fq(p3.y),
        ]);
        preimage_hints.extend_from_slice(&vec![
            Hint::Fq(p2.x),
            Hint::Fq(p2.y),
        ]);

        let tap_len = ops_scr.len();
        // [hints, t4, (q2), p4, p3, p2]
        let scr = script!(
            for h in &ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
             // [t4, p4, p3, p2, nt4, gpf, fg, p2le]
            {fq2_push_not_montgomery(hint_out.p2le[1])}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(hint_out.p2le[0])}
            {Fq2::equalverify()}
            {fq6_push_not_montgomery(hint_out.ab)}
            {Fq6::equalverify()}
            {fq2_push_not_montgomery(hint_out.apb[1])}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(hint_out.apb[0])}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(hint_out.t.y)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(hint_out.t.x)}
            {Fq2::equalverify()}
            {G1Affine::push_not_montgomery(p2)}
            {Fq2::equalverify()}
            {G1Affine::push_not_montgomery(p3)}
            {Fq2::equalverify()}
            {G1Affine::push_not_montgomery(p4)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(t4.y)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(t4.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let res = execute_script_without_stack_limit(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_complete_point_eval_and_mul() {
        let is_dbl = true;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], ab: ark_bn254::Fq6::ONE, apb: [ark_bn254::Fq2::ONE; 2], res_hint: ark_bn254::Fq6::ONE};
        let (inp, _, _) = chunk_point_ops_and_mul(is_dbl, None, None, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));

        let (_, ops_scr, ops_hints) = complete_point_eval_and_mul(inp);
        
        let mut preimage_hints = vec![];
        let hint_apb: Vec<Hint> = vec![inp.apb[0].c0, inp.apb[0].c1, inp.apb[1].c0, inp.apb[1].c1].into_iter().map(|f| Hint::Fq(f)).collect();
        let hint_ab: Vec<Hint> = inp.ab.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect();
        let hint_p2le: Vec<Hint> = vec![inp.p2le[0].c0, inp.p2le[0].c1, inp.p2le[1].c0, inp.p2le[1].c1].into_iter().map(|f| Hint::Fq(f)).collect();
        let hint_result: Vec<Hint> = inp.res_hint.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect();

        preimage_hints.extend_from_slice(&hint_apb);
        preimage_hints.extend_from_slice(&hint_ab);
        preimage_hints.extend_from_slice(&hint_p2le);
        preimage_hints.extend_from_slice(&hint_result);


        // [hints, apb, ab, c] [h]
        let tap_len= ops_scr.len();
        let scr = script!(
            for h in ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
            for h in preimage_hints.iter().rev() {
                {h.push()}
                {Fq::equalverify(1, 0)}
            }
            OP_TRUE
        );

        let res = execute_script(scr);
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);


    }

    #[test]
    fn test_chunk_complete_point_eval_and_mul() {
        let is_dbl = true;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], ab: ark_bn254::Fq6::ONE, apb: [ark_bn254::Fq2::ONE; 2], res_hint: ark_bn254::Fq6::ONE};
        let (inp, _, _) = chunk_point_ops_and_mul(is_dbl, None, None, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));

        let (hint_out, ops_scr, ops_hints) = chunk_complete_point_eval_and_mul(inp);

        let preimage_hints =  Element::G2Eval(inp).get_hash_preimage_as_hints(ElementType::G2EvalMul);

        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(inp.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::G2EvalMul, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len= ops_scr.len() + hash_scr.len();
        let scr = script!(
            for h in ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {ops_scr}
            {hash_scr}
        );

        let res = execute_script(scr);
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);


    }

    
    #[test]
    fn test_chunk_point_ops_and_mul() {
        let is_dbl = false;
        let is_frob: Option<bool> = Some(true);
        let ate_bit: Option<i8> = Some(-1);

        assert_eq!(is_dbl, is_frob.is_none() && ate_bit.is_none());
        assert_eq!(!is_dbl, is_frob.is_some() && ate_bit.is_some());


        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], ab: ark_bn254::Fq6::ONE, apb: [ark_bn254::Fq2::ONE; 2], res_hint: ark_bn254::Fq6::ONE};
        let (hint_out, ops_scr, ops_hints) = chunk_point_ops_and_mul(is_dbl, is_frob, ate_bit, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
     
        let mut preimage_hints = vec![];
        preimage_hints.extend_from_slice(&Element::G2Eval(t4).get_hash_preimage_as_hints(ElementType::G2EvalPoint));
        preimage_hints.extend_from_slice(&Element::G1(p4).get_hash_preimage_as_hints(ElementType::G1));
        preimage_hints.extend_from_slice(&Element::G1(p3).get_hash_preimage_as_hints(ElementType::G1));
        preimage_hints.extend_from_slice(&Element::G1(p2).get_hash_preimage_as_hints(ElementType::G1));

        // chunk_point_eval_and_mul(hint_out);

        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(p2.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(p3.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(p4.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(t4.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

            if !is_dbl {
                {fq_push_not_montgomery(q4.y.c1)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q4.y.c0)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q4.x.c1)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q4.x.c0)} 
                {Fq::toaltstack()}
            }
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::G2EvalPoint, ElementType::G1, ElementType::G1, ElementType::G1, ElementType::G2Eval])}
            OP_TRUE
        );

        let tap_len = ops_scr.len() + hash_scr.len();
        // [hints, t4, (q2), p4, p3]
        let scr = script!(
            for h in &ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {ops_scr}
            {hash_scr}
        );

        let res = execute_script_without_stack_limit(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }
    
    #[test]
    fn test_hinted_fq6_mul_le0_le1() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        n.c2 = ark_bn254::Fq2::ZERO;
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
            {fq2_push_not_montgomery(n.c0)}
            {fq2_push_not_montgomery(n.c1)}
            {ops_scr}
            {fq6_push_not_montgomery(o)}
            {Fq6::equalverify()}
            {fq2_push_not_montgomery(n.c1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(n.c0)}
            {Fq2::equalverify()}
            {fq6_push_not_montgomery(m)}
            {Fq6::equalverify()}
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

