use crate::bn254::{self, utils::*};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{G2Affine};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, Field, Zero};
use num_bigint::BigUint;
use num_traits::One;
use std::ops::Neg;
use std::str::FromStr;

use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::hint_models::*;

// DOUBLE EVAL

pub(crate) fn hint_double_eval_mul_for_fixed_Qs(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
) -> (ElemSparseEval, Script) {
    // assert_eq!(sec_in.len(), 4);
    let (t2, t3) = (hint_in_t2, hint_in_t3);
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));
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

    let mut b = f;
    b.mul_by_034(&ark_bn254::Fq2::ONE, &c3x, &c3y);

    let mut hints = vec![];
    let (_, hint_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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

    let b_hash = extern_hash_fps(
        vec![
            b.c0.c0.c0, b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0, b.c0.c2.c1, b.c1.c0.c0,
            b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0, b.c1.c2.c1,
        ],
        false,
    );
    let p2dash_x = extern_fq_to_nibbles(p2.x);
    let p2dash_y = extern_fq_to_nibbles(p2.y);
    let p3dash_x = extern_fq_to_nibbles(p3.x);
    let p3dash_y = extern_fq_to_nibbles(p3.y);


    let simulate_stack_input = script! {
        for hint in hints {
            { hint.push() }
        }

        // { bc_elems }

    };

    let hint_out = ElemSparseEval {
        t2: G2Affine::new_unchecked(x2, y2),
        t3: G2Affine::new_unchecked(x3, y3),
        f: ElemFp12Acc { f: b, hash: b_hash }
    };

    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_double_eval_mul_for_fixed_Qs(
    t2: G2Affine,
    t3: G2Affine,
) -> (Script, G2Affine, G2Affine) {
    // First
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t2 = t2.x.square();
    alpha_t2 /= t2.y;
    alpha_t2.mul_assign_by_fp(&three_div_two);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x.double();
    let y2 = bias_t2 - alpha_t2 * x2;

    // Second
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_t3 = t3.x.square();
    alpha_t3 /= t3.y;
    alpha_t3.mul_assign_by_fp(&three_div_two);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x.double();
    let y3 = bias_t3 - alpha_t3 * x3;

    let (hinted_ell_t2, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_sparse_dense_mul, _) = Fq12::hinted_mul_by_34(
        ark_bn254::Fq12::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let ops_scr = script! {
        // Altstack: [bhash, P3y, P3x, P2y, P2x]
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Altstack: [bhash: out]
        // Stack: [P2x, P2y, P3x, P3y]
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

    let hash_scr = script! {
        { hash_fp12_192() }
        { Fq::fromaltstack() } // bhash:out
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };

    let sc = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    (
        sc,
        G2Affine::new_unchecked(x2, y2),
        G2Affine::new_unchecked(x3, y3),
    )
}

// ADD EVAL

pub(crate) fn hint_add_eval_mul_for_fixed_Qs(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    hint_in_q2: ark_bn254::G2Affine,
    hint_in_q3: ark_bn254::G2Affine,
    ate: i8,
) -> (ElemSparseEval, Script) {
    let (t2, t3, qq2, qq3) = (
        hint_in_t2, hint_in_t3,  hint_in_q2, hint_in_q3,
    );
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));
    
    let mut q2 = qq2.clone();
    if ate == -1 {
        q2 = q2.neg();
    }
    let mut q3 = qq3.clone();
    if ate == -1 {
        q3 = q3.neg();
    }

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

    let mut b = f;
    b.mul_by_034(&ark_bn254::Fq2::ONE, &c3x, &c3y);

    let mut hints = vec![];
    let (_, hint_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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

    let b_hash = extern_hash_fps(
        vec![
            b.c0.c0.c0, b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0, b.c0.c2.c1, b.c1.c0.c0,
            b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0, b.c1.c2.c1,
        ],
        false,
    );
    let p2dash_x = extern_fq_to_nibbles(p2.x);
    let p2dash_y = extern_fq_to_nibbles(p2.y);
    let p3dash_x = extern_fq_to_nibbles(p3.x);
    let p3dash_y = extern_fq_to_nibbles(p3.y);

    let simulate_stack_input = script! {
        for hint in hints {
            { hint.push() }
        }
        // bit commits
        // { bc_elems }
    };

    let hint_out = ElemSparseEval {
        t2: G2Affine::new_unchecked(x2, y2),
        t3: G2Affine::new_unchecked(x3, y3),
        f: ElemFp12Acc { f: b, hash: b_hash }
    };

    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_add_eval_mul_for_fixed_Qs(
    t2: G2Affine,
    t3: G2Affine,
    q2: G2Affine,
    q3: G2Affine,
    ate: i8,
) -> (Script, G2Affine, G2Affine) {
    // WARN: use ate bit the way tap_point_ops did
    assert!(ate == 1 || ate == -1);

    let mut qq2 = q2.clone();
    let mut qq3 = q3.clone();
    if ate == -1 {
        qq2 = qq2.neg();
        qq3 = qq3.neg();
    }
    // First
    let alpha_t2 = (t2.y - qq2.y) / (t2.x - qq2.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - qq2.x;
    let y2 = bias_t2 - alpha_t2 * x2;
    // Second
    let alpha_t3 = (t3.y - qq3.y) / (t3.x - qq3.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - qq3.x;
    let y3 = bias_t3 - alpha_t3 * x3;

    let (hinted_ell_t2, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t3,
        bias_t3,
    );
    let (hinted_sparse_dense_mul, _) = Fq12::hinted_mul_by_34(
        ark_bn254::Fq12::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let ops_scr = script! {
        // Alt: [bhash]
        // Stack: [P2x, P2y, P3x, P3y]
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
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

    let hash_scr = script! {
        { hash_fp12_192() }
        { Fq::fromaltstack() }
        {Fq::equal(1, 0)}
        OP_NOT OP_VERIFY
    };
    let sc = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    (
        sc,
        G2Affine::new_unchecked(x2, y2),
        G2Affine::new_unchecked(x3, y3),
    )
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

pub(crate) fn hint_add_eval_mul_for_fixed_Qs_with_frob(
    hint_in_p3y: ElemFq,
    hint_in_p3x: ElemFq,
    hint_in_p2y: ElemFq,
    hint_in_p2x: ElemFq,
    
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    hint_in_q2: ark_bn254::G2Affine,
    hint_in_q3: ark_bn254::G2Affine,
    ate: i8,
) -> (ElemSparseEval, Script) {

    let (t2, t3, qq2, qq3) = (
        hint_in_t2, hint_in_t3,  hint_in_q2, hint_in_q3,
    );
    let (p2, p3) = (ark_bn254::G1Affine::new_unchecked(hint_in_p2x, hint_in_p2y), ark_bn254::G1Affine::new_unchecked(hint_in_p3x, hint_in_p3y));


    // First
    let mut qq = qq2.clone();
    if ate == 1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(qq);
        qq = qdash;
    } else {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(qq);
        qq = qdash;
    }
    let alpha_t2 = (t2.y - qq.y) / (t2.x - qq.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - qq.x;
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
    let mut qq = qq3.clone();
    if ate == 1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(qq);
        qq = qdash;
    } else {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(qq);
        qq = qdash;
    }
    let alpha_t3 = (t3.y - qq.y) / (t3.x - qq.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - qq.x;
    let y3 = bias_t3 - alpha_t3 * x3;
    let mut c3x = alpha_t3;
    c3x.mul_assign_by_fp(&p3.x);
    let mut c3y = bias_t3;
    c3y.mul_assign_by_fp(&p3.y);

    let mut b = f;
    b.mul_by_034(&ark_bn254::Fq2::ONE, &c3x, &c3y);

    let mut hints = vec![];
    let (_, hint_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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

    let b_hash = extern_hash_fps(
        vec![
            b.c0.c0.c0, b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0, b.c0.c2.c1, b.c1.c0.c0,
            b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0, b.c1.c2.c1,
        ],
        false,
    );
    let p2dash_x = extern_fq_to_nibbles(p2.x);
    let p2dash_y = extern_fq_to_nibbles(p2.y);
    let p3dash_x = extern_fq_to_nibbles(p3.x);
    let p3dash_y = extern_fq_to_nibbles(p3.y);

    let simulate_stack_input = script! {
        for hint in hints {
            { hint.push() }
        }
        // bit commits
        // { bc_elems }
    };

    let hint_out = ElemSparseEval {
        t2: G2Affine::new_unchecked(x2, y2),
        t3: G2Affine::new_unchecked(x3, y3),
        f: ElemFp12Acc { f: b, hash: b_hash }
    };

    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_add_eval_mul_for_fixed_Qs_with_frob(
    t2: G2Affine,
    t3: G2Affine,
    qq2: G2Affine,
    qq3: G2Affine,
    ate: i8,
) -> (Script, G2Affine, G2Affine) {

    // First
    let mut qq = qq2.clone();
    if ate == 1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(qq);
        qq = qdash;
    } else {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(qq);
        qq = qdash;
    }

    let alpha_t2 = (t2.y - qq.y) / (t2.x - qq.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - qq.x;
    let y2 = bias_t2 - alpha_t2 * x2;

    // Second
    let mut qq = qq3.clone();
    if ate == 1 {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(qq);
        qq = qdash;
    } else {
        let (qdash, _, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(qq);
        qq = qdash;
    }

    let alpha_t3 = (t3.y - qq.y) / (t3.x - qq.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - qq.x;
    let y3 = bias_t3 - alpha_t3 * x3;

    let (hinted_ell_t2, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t3,
        bias_t3,
    );
    let (hinted_sparse_dense_mul, _) = Fq12::hinted_mul_by_34(
        ark_bn254::Fq12::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let ops_scr = script! {
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack: [P2x, P2y, P3x, P3y]
        // Altstack: [bhash]
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

    let hash_scr = script! {
        { hash_fp12_192() }
        {Fq::fromaltstack()}
        {Fq::equal(1, 0)}
        OP_NOT OP_VERIFY
    };
    let sc = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };

    (
        sc,
        G2Affine::new_unchecked(x2, y2),
        G2Affine::new_unchecked(x3, y3),
    )
}
