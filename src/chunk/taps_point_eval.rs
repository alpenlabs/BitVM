use crate::bn254::{self, utils::*};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::primitves::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{G2Affine};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, Field, Zero};
use num_traits::One;
use std::ops::Neg;

use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::element::*;

fn utils_multiply_point_evals_for_fixed_g2(
    alpha_t2: ark_bn254::Fq2,
    neg_bias_t2: ark_bn254::Fq2,
    alpha_t3: ark_bn254::Fq2,
    neg_bias_t3: ark_bn254::Fq2,

    p2: ark_bn254::G1Affine,
    p3: ark_bn254::G1Affine,
) -> (ark_bn254::Fq12, Script, Vec<Hint>) {

    let mut l0_t2 = alpha_t2;
    l0_t2.mul_assign_by_fp(&p2.x);
    let mut l1_t2 = neg_bias_t2;
    l1_t2.mul_assign_by_fp(&p2.y);

    let mut l0_t3 = alpha_t3;
    l0_t3.mul_assign_by_fp(&p3.x);
    let mut l1_t3 = neg_bias_t3;
    l1_t3.mul_assign_by_fp(&p3.y);

    let (hinted_ell_t2, hints_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, neg_bias_t2);
    let (hinted_ell_t3, hints_ell_t3) = hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, neg_bias_t3);

    let mut f = ark_bn254::Fq12::zero();
    f.c0.c0 = ark_bn254::Fq2::one(); // 0
    f.c1.c0 = l0_t2; // 3
    f.c1.c1 = l1_t2; // 4
    let mut g = ark_bn254::Fq12::zero();
    g.c0.c0 = ark_bn254::Fq2::one(); // 0
    g.c1.c0 = l0_t3; // 3
    g.c1.c1 = l1_t3; // 4
    let (hinted_sparse_dense_mul, hints_sparse_dense_mul) = Fq12::hinted_mul_by_34(f, l0_t3, l1_t3);
    
    let scr = script!(
        // [p2x, p2y, p3x, p3y]
        {Fq2::toaltstack()}
        {fq2_push_not_montgomery(alpha_t2)}
        {fq2_push_not_montgomery(neg_bias_t2)}
        // [p2x, p2y, a, b] [p3]
        {Fq2::copy(4)}
        // [p2x, p2y, a, b, p2x, p2y] [p3]
        {hinted_ell_t2}
        // [p2x, p2y, le0x, le0y, le1x, le1y] [p3]
        {Fq2::fromaltstack()}
        // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y]
        {fq2_push_not_montgomery(alpha_t3)}
        {fq2_push_not_montgomery(neg_bias_t3)}
        // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y, a, b]
        {Fq2::copy(4)}
         // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y, a, b, p3x, p3y]
        {hinted_ell_t3}
        // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y, le0x, le0y, le1x, le1y]
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y], [le]

        {fq2_push_not_montgomery(ark_bn254::Fq2::one())} // f0
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f1
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f2
        // [p2x, p2y, le0x, le0y, le1x, le1y, p3x, p3y, 01, 00, 00], [le]
        {Fq2::roll(10)} {Fq2::roll(10)} // f3, f4
        // [p2x, p2y, p3x, p3y, 01, 00, 00, le0, le1], [le]
        {fq2_push_not_montgomery(ark_bn254::Fq2::zero())} // f5
        // [p2, p3, f], [le]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        // [p2, p3, f, le]
        {hinted_sparse_dense_mul}
        // [p2, p3, f*le]
    );

    let mut hints = vec![];
    hints.extend_from_slice(&hints_ell_t2);
    hints.extend_from_slice(&hints_ell_t3);
    hints.extend_from_slice(&hints_sparse_dense_mul);

    (f*g, scr, hints)

}

// DOUBLE EVAL
fn utils_multiply_point_evals_on_tangent_for_fixed_g2(
    p2: ark_bn254::G1Affine,
    p3: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
) -> (ark_bn254::Fq12, Script, Vec<Hint>) {
    let alpha_t2 = (t2.x.square() + t2.x.square() + t2.x.square()) / (t2.y + t2.y); 
    let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
    let alpha_t3 = (t3.x.square() + t3.x.square() + t3.x.square()) / (t3.y + t3.y); 
    let neg_bias_t3 = alpha_t3 * t3.x - t3.y;

    utils_multiply_point_evals_for_fixed_g2(alpha_t2, neg_bias_t2, alpha_t3, neg_bias_t3, p2, p3)
}

// ADD EVAL
fn utils_multiply_point_evals_on_chord_for_fixed_g2(
    p2: ark_bn254::G1Affine,
    p3: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
) -> (ark_bn254::Fq12, Script, Vec<Hint>) {
    let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x); 
    let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
    let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x); 
    let neg_bias_t3 = alpha_t3 * t3.x - t3.y;

    utils_multiply_point_evals_for_fixed_g2(alpha_t2, neg_bias_t2, alpha_t3, neg_bias_t3, p2, p3)
}


pub(crate) fn chunk_multiply_point_evals_on_tangent_for_fixed_g2(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
) -> (ElemSparseEval, Script, Vec<Hint>) {
    fn tap_multiply_point_evals_on_tangent_for_fixed_g2(mul_scr: Script) -> Script {

        let ops_scr = script!(
            // [p2, p3] [hash_g, hash_p2, hash_p3]
            {mul_scr}
            // [p2, p3, g]
        );
        let hash_scr = script! {
            {hash_messages(vec![ElementType::MSMG1, ElementType::MSMG1, ElementType::Fp12v1])}
        };
        let sc = script! {
            {ops_scr}
            {hash_scr}
            OP_TRUE
        };
        sc
    }

    let (t2, t3) = (hint_in_t2, hint_in_t3);
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));

    let (f, scr, hints) = utils_multiply_point_evals_on_tangent_for_fixed_g2(p2, p3, t2, t3);

    let hash = extern_hash_fps(
        f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        false,
    );
    let scr = tap_multiply_point_evals_on_tangent_for_fixed_g2(scr);

    let hint_out = ElemSparseEval {
        t2: (t2 + t2).into_affine(),
        t3: (t3 + t3).into_affine(),
        f: ElemFp12Acc { f, hash }
    };
    (hint_out, scr, hints)
}

// ADD EVAL

pub(crate) fn chunk_multiply_point_evals_on_chord_for_fixed_g2(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    hint_in_q2: ark_bn254::G2Affine,
    hint_in_q3: ark_bn254::G2Affine,
    ate: i8,
) -> (ElemSparseEval, Script, Vec<Hint>) {
    fn tap_multiply_point_evals_on_chord_for_fixed_g2(mul_scr: Script) -> Script {

        let ops_scr = script!(
            // [p2, p3] [hash_g, hash_p2, hash_p3]
            {mul_scr}
            // [p2, p3, g]
        );
        let hash_scr = script! {
            {hash_messages(vec![ElementType::MSMG1, ElementType::MSMG1, ElementType::Fp12v1])}
        };
        let sc = script! {
            {ops_scr}
            {hash_scr}
            OP_TRUE
        };
        sc
    }

    let (t2, t3) = (hint_in_t2, hint_in_t3);
    let (qq2, qq3) = (hint_in_q2, hint_in_q3);
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));

    let mut q2 = qq2.clone();
    if ate == -1 {
        q2 = q2.neg();
    }
    let mut q3 = qq3.clone();
    if ate == -1 {
        q3 = q3.neg();
    }

    let (f, scr, hints) = utils_multiply_point_evals_on_chord_for_fixed_g2(p2, p3, t2, t3, q2, q3);

    let hash = extern_hash_fps(
        f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        false,
    );
    let scr = tap_multiply_point_evals_on_chord_for_fixed_g2(scr);

    let hint_out = ElemSparseEval {
        t2: (t2 + q2).into_affine(),
        t3: (t3 + q3).into_affine(),
        f: ElemFp12Acc { f, hash }
    };
    (hint_out, scr, hints)
}


pub(crate) fn get_hint_for_add_with_frob(q: ark_bn254::G2Affine, t: ark_bn254::G2Affine, ate: i8) -> ark_bn254::G2Affine {
    let mut qq = q.clone();
    if ate == 1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(qq);
        qq = qdash;
    } else if ate == -1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(qq);
        qq = qdash;
    }
    let r = (t + qq).into_affine();
    r

}


pub(crate) fn chunk_multiply_point_evals_on_chord_for_fixed_g2_with_frob(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    hint_in_q2: ark_bn254::G2Affine,
    hint_in_q3: ark_bn254::G2Affine,
    ate: i8,
) -> (ElemSparseEval, Script, Vec<Hint>) {
    fn tap_multiply_point_evals_on_chord_for_fixed_g2(mul_scr: Script) -> Script {

        let ops_scr = script!(
            // [p2, p3] [hash_g, hash_p2, hash_p3]
            {mul_scr}
            // [p2, p3, g]
        );
        let hash_scr = script! {
            {hash_messages(vec![ElementType::MSMG1, ElementType::MSMG1, ElementType::Fp12v1])}
        };
        let sc = script! {
            {ops_scr}
            {hash_scr}
            OP_TRUE
        };
        sc
    }

    let (t2, t3) = (hint_in_t2, hint_in_t3);
    let (qq2, qq3) = (hint_in_q2, hint_in_q3);
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));

    let mut q2 = qq2.clone();
    if ate == 1 {
        q2 = bn254::curves::G2Affine::hinted_p_power_endomorphism(q2).0;
    } else {
        q2 = bn254::curves::G2Affine::hinted_endomorphism_affine(q2).0;
    }

    let mut q3 = qq3.clone();
    if ate == 1 {
        q3 = bn254::curves::G2Affine::hinted_p_power_endomorphism(q3).0;
    } else {
        q3 = bn254::curves::G2Affine::hinted_endomorphism_affine(q3).0;
    }


    let (f, scr, hints) = utils_multiply_point_evals_on_chord_for_fixed_g2(p2, p3, t2, t3, q2, q3);

    let hash = extern_hash_fps(
        f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        false,
    );
    let scr = tap_multiply_point_evals_on_chord_for_fixed_g2(scr);

    let hint_out = ElemSparseEval {
        t2: (t2 + q2).into_affine(),
        t3: (t3 + q3).into_affine(),
        f: ElemFp12Acc { f, hash }
    };
    (hint_out, scr, hints)
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::bn254::curves::{G1Affine, G2Affine};

    use super::*;


    #[test]
    fn test_multiply_point_evals_for_fixed_g2() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);

        let (res, scr, hints) = utils_multiply_point_evals_on_tangent_for_fixed_g2(p2, p3, t2, t3);

        let tap_len = scr.len();
        let script = script! {
            for h in hints {
                { h.push() }
            }
            {G1Affine::push_not_montgomery(p2)}
            {G1Affine::push_not_montgomery(p3)}
            {scr}
            {fq12_push_not_montgomery(res)}
            {Fq12::equalverify()}
            {G1Affine::push_not_montgomery(p2)}
            {G1Affine::push_not_montgomery(p3)}
            {G2Affine::equal()} OP_VERIFY
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

}