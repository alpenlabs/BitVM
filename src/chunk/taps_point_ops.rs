use crate::bn254::{self, utils::*};
use crate::bn254::{fq2::Fq2};
use crate::chunk::primitves::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{ G2Affine};
use ark_ff::{AdditiveGroup, Field};
use num_traits::One;
use std::ops::Neg;

use super::primitves::{extern_hash_fps};
use super::hint_models::*;


pub(crate) fn hash_g2acc_with_hashed_le() -> Script {
    script! {
        //Stack: [tx, ty, hash_inaux, hash_result]
        //T
        {Fq2::toaltstack()} 
        {hash_fp4()} // HT

        {Fq::fromaltstack()}
        {hash_fp2()}

        { Fq::fromaltstack()}
        {Fq::equal(1, 0)}
    }
}

pub(crate) fn hash_g2acc_with_raw_le(is_dbl:bool) -> Script {
    script!{
         // Stack: [tx, ty, dbl_le, hash_result]
        {Fq::toaltstack()} {Fq2::toaltstack()} {Fq2::toaltstack()}
        {hash_fp4()} {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // [HT, dbl_le]
        {Fq::roll(4)} {Fq::toaltstack()} // [dbl_le]
        {hash_fp4()} // [Hdbl_le]
        for _ in 0..9 {
            {0}
        }
        if !is_dbl {
            {Fq::roll(1)}
        }
        {hash_fp2()} // [Hle]
        {Fq::fromaltstack()} // [Hle, HT]
        {Fq::roll(1)}
        {hash_fp2()} // [Hash_calc]
        {Fq::fromaltstack()}
        {Fq::equal(1, 0)}
    }
}

pub(crate) fn hash_g2acc_with_both_raw_le() -> Script {
    script!{
        //Stack: [tx, ty, dbl_le, add_le, hash_result]
        {Fq::toaltstack()} 
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {hash_fp4()} 
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} // [HT, dbl_le]
        {Fq::roll(4)} {Fq::toaltstack()} // [dbl_le]
        {hash_fp4()} // [Hdbl_le]
        {Fq::fromaltstack()} // [Hdbl_le, HT]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} // [Hdbl_le, HT, add_le]
        {Fq2::roll(4)} {Fq2::toaltstack()} // [add_le]
        {hash_fp4()} // [Hadd_le]
        {Fq::fromaltstack()} // [Hadd_le, Hdbl_le]
        {Fq::roll(1)}
        {hash_fp2()} // [Hle]
        {Fq::fromaltstack()} // [Hle, HT]
        {Fq::roll(1)}
        {hash_fp2()} // [HTcacl]
        {Fq::fromaltstack()}
        {Fq::equal(1, 0)}
    }
}

pub(crate) fn hash_g2acc_with_hashed_t(is_dbl: bool) -> Script {
    script!{
        //Stack: [Ht, cur_le, Hother_le, hash_result]
        {Fq::toaltstack()} 
        {Fq::roll(5)} {Fq::toaltstack()} 
        {Fq::toaltstack()}
        // A:[hash_result, Ht, Hother_le]
        // M:[cur_le]
        {hash_fp4()} 

        {Fq::fromaltstack()}
        // [HC_le, HO_le]
        if !is_dbl {
            {Fq::roll(1)}
        }
        {hash_fp2()}
        // [Hle]
        {Fq::fromaltstack()}
        // [Hle, HT]
        {Fq::roll(1)}
        {hash_fp2()}
        {Fq::fromaltstack()}
        {Fq::equal(1, 0)}
    }
}

// POINT DBL

pub(crate) fn chunk_point_dbl(
    hint_t: ElemG2PointAcc,
    hint_py: ElemFq,
    hint_px: ElemFq,
) -> (ElemG2PointAcc, Script, Script) {

    fn chunk_point_dbl(hinted_check_tangent: Script, hinted_double_line: Script, hinted_ell_tangent: Script) -> Script {
        let ops_script = script! {
            {Fq::fromaltstack()}
            {Fq::fromaltstack()} // py
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
            { Fq2::roll(6)} // alpha
            //[a, tx, ty, a]
            { Fq2::roll(6)} // bias
            //[tx, ty, a, b]
            { Fq2::copy(6)} // t.x
            //[tx, ty, a, b, tx]
            { hinted_double_line } // R
            // [t, R]
    
            { Fq2::fromaltstack() } // le.0
            { Fq2::fromaltstack() } // le.1
            // [t, R, le]
    
            // Altstack: [hash_out, hash_in, hash_inaux]
            // Stack: [t, R, le]
        };
    
        let hash_script = script! {
            //Altstack: [hash_out, hash_in, hash_inaux]
            //Stack: [tx, ty, Rx, Ry, le0, le1]
            {Fq::fromaltstack()} {Fq::fromaltstack()}
            //Stack: [tx, ty, Rx, Ry, le0, le1, hash_inaux, hash_in]
            {Fq2::roll(8)} {Fq2::roll(8)} {Fq2::roll(8)} {Fq2::roll(8)}
            // [tx, ty, hash_inaux, hash_in, Rx, Ry, le0, le1]
            {Fq2::toaltstack()} {Fq2::toaltstack()} {Fq2::toaltstack()} {Fq2::toaltstack()}
            // [tx, ty, hash_inaux, hash_in]
            {hash_g2acc_with_hashed_le()} //[1]
            OP_VERIFY
    
            {Fq2::fromaltstack()} {Fq2::fromaltstack()} {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            {Fq::fromaltstack()}
            // [Rx, Ry, le0, le1, hash_out]
            {hash_g2acc_with_raw_le(true)}
            OP_NOT OP_VERIFY
        };
    
        let sc = script! {
            {ops_script}
            {hash_script}
            OP_TRUE
        };
        sc
    }
    
    
    // assert_eq!(sec_in.len(), 3);
    let t = hint_t.t;
    let p = ark_bn254::G1Affine::new_unchecked(hint_px, hint_py);
    let hash_le_aux = hint_t.hash_le();

    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_tangent = t.x.square();
    alpha_tangent /= t.y;
    alpha_tangent.mul_assign_by_fp(&three_div_two);
    // -bias
    let bias_minus_tangent = alpha_tangent * t.x - t.y;

    //println!("hint_point_dbl alpha {:?} bias {:?}",alpha_tangent, bias_minus_tangent);

    let new_tx = alpha_tangent.square() - t.x.double();
    let new_ty = bias_minus_tangent - alpha_tangent * new_tx;
    let (hinted_double_line, hints_double_line) =
        hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (hinted_check_tangent, hints_check_tangent) =
        hinted_check_tangent_line(t, alpha_tangent, bias_minus_tangent);

    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&p.x);

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&p.y);

    let (hinted_ell_tangent, hints_ell_tangent) =
        hinted_ell_by_constant_affine(p.x, p.y, alpha_tangent, bias_minus_tangent);

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

    let pdash_x = extern_fq_to_nibbles(p.x);
    let pdash_y = extern_fq_to_nibbles(p.y);

    let hash_new_t =
        extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le =
        extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
    let hash_add_le = [0u8; 64]; // constant
    let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
    let hash_root_claim = extern_hash_nibbles(vec![hash_new_t, hash_le], true);

    let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
    let aux_hash_le = extern_nibbles_to_limbs(hash_le_aux); // mock
    let hash_input = extern_hash_nibbles(vec![hash_t, hash_le_aux], true);


    let simulate_stack_input = script! {
        // tmul_hints
        for hint in all_qs {
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

        // {bc_elems}
    };
    let hint_out: ElemG2PointAcc = ElemG2PointAcc {
        t: G2Affine::new_unchecked(new_tx, new_ty),
        dbl_le: Some((dbl_le0, dbl_le1)),
        add_le: None,
        // hash: hash_root_claim,
    };
    (hint_out, chunk_point_dbl(hinted_check_tangent, hinted_double_line, hinted_ell_tangent), simulate_stack_input)
}

pub(crate) fn chunk_point_add_with_frob(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_py: ElemFq,
    hint_px: ElemFq,
    ate: i8,
) -> (ElemG2PointAcc, Script, Script) {

    fn tap_point_add_with_frob(ate: i8, scripts: [Script; 5]) -> Script {
        assert!(ate == 1 || ate == -1);
        let mut ate_unsigned_bit = 1; // Q1 = pi(Q), T = T + Q1 // frob
        if ate == -1 {
            // Q2 = pi^2(Q), T = T - Q2 // frob_sq and negate
            ate_unsigned_bit = 0;
        }

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
            { scripts[1].clone() }
            { Fq2::copy(12)} // alpha
            { Fq2::copy(12)} // bias
            { Fq2::copy(12)} // tx
            { Fq2::copy(12)} // ty
            { scripts[2].clone() }


            //[a, b, tx, ty, p, qx, qy]
            { Fq2::copy(12) } // alpha
            { Fq2::copy(12) } // bias
            { Fq2::roll(8) } // p_dash
            { scripts[3].clone() }
            { Fq2::toaltstack() } // le.0
            { Fq2::toaltstack() } // le.1

            //[a, b, tx, ty, qx, qy]
            { Fq2::roll(10) } // alpha
            //[a, tx, ty, qx, qy, b]
            { Fq2::roll(10) } // bias
            //[tx, ty, qx, qy, a, b]
            { Fq2::roll(6) } //q.x
            //[tx, ty, qy, b, a, qx]
            { Fq2::copy(10) } // t.x from altstack
            //[tx, ty, qy, b, a, qx, tx]
            { scripts[4].clone() } // alpha, bias chord consumed
            //[tx, ty, qy, R]

            { Fq2::fromaltstack() } // le
            { Fq2::fromaltstack() } // le
            // [tx, ty, qy, Rx, Ry, le0, le1]
            {Fq2::roll(8)}
            {Fq2::drop()}
            // Altstack: [hash_out, hash_in, hash_inaux]
            // Stack: [tx, ty, Rx, Ry, le0, le1]
        };

        let hash_script = script! {
            //Altstack: [hash_out, hash_in, hash_inaux]
            //Stack: [tx, ty, Rx, Ry, le0, le1]
            {Fq::fromaltstack()} {Fq::fromaltstack()}
            //Stack: [tx, ty, Rx, Ry, le0, le1, hash_inaux, hash_in]
            {Fq2::roll(8)} {Fq2::roll(8)} {Fq2::roll(8)} {Fq2::roll(8)}
            // [tx, ty, hash_inaux, hash_in, Rx, Ry, le0, le1]
            {Fq2::toaltstack()} {Fq2::toaltstack()} {Fq2::toaltstack()} {Fq2::toaltstack()}
            // [tx, ty, hash_inaux, hash_in]
            {hash_g2acc_with_hashed_le()} //[1]
            OP_VERIFY

            {Fq2::fromaltstack()} {Fq2::fromaltstack()} {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            {Fq::fromaltstack()}
            // [Rx, Ry, le0, le1, hash_out]
            {hash_g2acc_with_raw_le(false)}
            OP_NOT OP_VERIFY
        };

        let (_, beta_22_scr, _) = bn254::curves::G2Affine::hinted_endomorphism_affine(ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE));
        let (_, beta_12_scr, _) = bn254::curves::G2Affine::hinted_p_power_endomorphism(ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE));

        let precompute_script = script! {
            // bring back from altstack
            for _ in 0..8 {
                {Fq::fromaltstack()}
            }

            // Input: [px, py, qx0, qx1, qy0, qy1, in, out]
            {Fq::toaltstack()}
            {Fq::toaltstack()}

            {ate_unsigned_bit} 1 OP_NUMEQUAL
            OP_IF
                {beta_12_scr}
            OP_ELSE
                {beta_22_scr}
            OP_ENDIF

            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
            // Output: [px, py, qx0', qx1', qy0', qy1', in, out]
        };

        let sc = script! {
            {precompute_script}
            {ops_script}
            {hash_script}
            OP_TRUE
        };
        sc
    }

    assert!(ate == 1 || ate == -1);
    let (tt, p) = (hint_t.t, ark_bn254::G1Affine::new_unchecked(hint_px, hint_py));
    let q = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
    let hash_le_aux = hint_t.hash_le();
    let mut qq = q.clone();
    let mut frob_hint = vec![];
    let mut frob_scr = script!();
    if ate == 1 {
        let (qdash, fscr, beta_12_hint) = bn254::curves::G2Affine::hinted_p_power_endomorphism(q);
        qq = qdash;
        frob_hint = beta_12_hint;
        frob_scr = fscr;
    } else {
        let (qdash, fscr, beta_22_hint) = bn254::curves::G2Affine::hinted_endomorphism_affine(q);
        qq = qdash;
        frob_hint = beta_22_hint;
        frob_scr = fscr;
    }

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    let new_tx = alpha_chord.square() - tt.x - qq.x;
    let new_ty = bias_minus_chord - alpha_chord * new_tx;
    let p_dash_x = p.x;
    let p_dash_y = p.y;

    let (hinted_check_chord_t, hints_check_chord_t) =
        hinted_check_line_through_point(tt.x, alpha_chord, bias_minus_chord);
    let (hinted_check_chord_q, hints_check_chord_q) =
        hinted_check_line_through_point(qq.x, alpha_chord, bias_minus_chord);
    let (hinted_add_line, hints_add_line) = hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&p.x);

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&p.y);

    let (hinted_ell_chord, hints_ell_chord) =
        hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

    let mut all_qs = vec![];
    let all_scripts = [frob_scr, hinted_check_chord_q, hinted_check_chord_t, hinted_ell_chord, hinted_add_line];
    for hint in frob_hint {
        all_qs.push(hint);
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

    let pdash_x = extern_fq_to_nibbles(p.x);
    let pdash_y = extern_fq_to_nibbles(p.y);
    let qdash_x0 = extern_fq_to_nibbles(q.x.c0);
    let qdash_x1 = extern_fq_to_nibbles(q.x.c1);
    let qdash_y0 = extern_fq_to_nibbles(q.y.c0);
    let qdash_y1 = extern_fq_to_nibbles(q.y.c1);

    let hash_new_t =
        extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le = [0u8; 64];
    let hash_add_le =
        extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
    let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
    let hash_root_claim = extern_hash_nibbles(vec![hash_new_t, hash_le], true);

    let hash_t = extern_hash_fps(vec![tt.x.c0, tt.x.c1, tt.y.c0, tt.y.c1], true);
    let aux_hash_le = extern_nibbles_to_limbs(hash_le_aux); // mock
    let hash_input = extern_hash_nibbles(vec![hash_t, hash_le_aux], true);


    let simulate_stack_input = script! {
        // tmul_hints
        for hint in all_qs {
            { hint.push() }
        }
        // aux
        { fq2_push_not_montgomery(alpha_chord)}
        { fq2_push_not_montgomery(bias_minus_chord)}
        { fq2_push_not_montgomery(tt.x) }
        { fq2_push_not_montgomery(tt.y) }

        for i in 0..aux_hash_le.len() {
            {aux_hash_le[i]}
        }

        // bit commits raw
    };
    let hint_out = ElemG2PointAcc {
        t: G2Affine::new_unchecked(new_tx, new_ty),
        add_le: Some((add_le0, add_le1)),
        dbl_le: None,
        // hash: hash_root_claim,
    };
    (hint_out, tap_point_add_with_frob(ate, all_scripts), simulate_stack_input)
}

// POINT DBL AND ADD

pub(crate) fn chunk_point_ops(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_py: ElemFq,
    hint_px: ElemFq,
    ate: i8,
) -> (ElemG2PointAcc, Script, Script) {
    pub(crate) fn tap_point_ops(ate: i8, scripts: [Script; 7]) -> Script {
        assert!(ate == 1 || ate == -1);
    
        let mut ate_unsigned_bit = 1;
        if ate == -1 {
            ate_unsigned_bit = 0;
        }
        let ate_mul_y_toaltstack = script! {
            {ate_unsigned_bit}
            1 OP_NUMEQUAL
            OP_IF
                {Fq::toaltstack()}
            OP_ELSE // -1
                {Fq::neg(0)}
                {Fq::toaltstack()}
            OP_ENDIF
        };
        let precompute_scr = script!{
            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
            {Fq::fromaltstack()}
    
            {ate_mul_y_toaltstack.clone()}
            {ate_mul_y_toaltstack}
    
            {Fq::toaltstack()}
            {Fq::toaltstack()}
            {Fq::toaltstack()}
            {Fq::toaltstack()}
        };
    
        let bcsize = 6 + 3;
        let ops_script = script! {
            {precompute_scr}
            
            // bring back from altstack
            for _ in 0..8 {
                {Fq::fromaltstack()}
            }
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
            { scripts[0].clone() }
    
            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(4 + 7) } // p_dash
            { scripts[1].clone() }
            { Fq2::toaltstack() } // le.0
            { Fq2::toaltstack() } // le.1
    
    
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::copy(bcsize+6)} // t.x
            { scripts[2].clone() }
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
            { scripts[3].clone() }
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::fromaltstack() } // TT
            { Fq2::fromaltstack() }
            { Fq2::copy(2)} // t.x
            { Fq2::toaltstack() } // t.x to altstack
            { scripts[4].clone() }
    
    
            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(10+1) } // p_dash
            { scripts[5].clone() }
    
            { Fq2::roll(6+bcsize+4) } // alpha
            { Fq2::roll(6+bcsize+4) } // bias
            { Fq2::copy(4+4+4+1) } //q.x
            { Fq2::fromaltstack() } // t.x from altstack
            { scripts[6].clone() } // alpha, bias chord consumed
    
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
    
        let hash_script = script! {
            // Altstack: [dbl_le, R, add_le, hash_out, hash_in, hash_inaux]
            // Stack: [t]
            
            {Fq::fromaltstack()} {Fq::fromaltstack()}
            // [tx, ty, hash_inaux, hash_in]
            {hash_g2acc_with_hashed_le()} //[1]
            OP_VERIFY
    
            {Fq::fromaltstack()}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            
            //[hash_out, add_le, R, dbl_le]
            {Fq2::roll(10)} {Fq2::roll(10)}
            // [hash_out, R, dbl_le, add_le]
            {Fq::roll(12)}
            // [R, dbl_le, add_le, hash_out]
            {hash_g2acc_with_both_raw_le()}
            OP_NOT OP_VERIFY
        };
    
        let sc = script! {
            {ops_script}
            {hash_script}
            OP_TRUE
        };
        sc
    }
    
    // assert_eq!(sec_in.len(), 7);
    let (t, p, hash_le_aux) = (hint_t.t, ark_bn254::G1Affine::new_unchecked(hint_px, hint_py), hint_t.hash_le());
    let q = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
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

    //println!("alphat {:?} biast {:?}", alpha_tangent, bias_minus_tangent);

    let tx = alpha_tangent.square() - t.x.double();
    let ty = bias_minus_tangent - alpha_tangent * tx;
    let (hinted_double_line, hints_double_line) =
        hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (hinted_check_tangent, hints_check_tangent) =
        hinted_check_tangent_line(t, alpha_tangent, bias_minus_tangent);

    let tt = G2Affine::new_unchecked(tx, ty);

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    //println!("alphac {:?} biasc {:?}", alpha_chord, bias_minus_chord);

    let new_tx = alpha_chord.square() - tt.x - qq.x;
    let new_ty = bias_minus_chord - alpha_chord * new_tx;
    let p_dash_x = p.x;
    let p_dash_y = p.y;

    let (hinted_check_chord_t, hints_check_chord_t) =
        hinted_check_line_through_point(tt.x, alpha_chord, bias_minus_chord);
    let (hinted_check_chord_q, hints_check_chord_q) =
        hinted_check_line_through_point(qq.x, alpha_chord, bias_minus_chord);
    let (hinted_add_line, hints_add_line) = hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&p.x);

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&p.y);

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&p.x);

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&p.y);

    let (hinted_ell_tangent, hints_ell_tangent) =
        hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
    let (hinted_ell_chord, hints_ell_chord) =
        hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

    let all_scripts = [
        hinted_check_tangent, hinted_ell_tangent, 
        hinted_double_line, hinted_check_chord_q, 
        hinted_check_chord_t, hinted_ell_chord, 
        hinted_add_line,
    ];
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

    let pdash_x = extern_fq_to_nibbles(p.x);
    let pdash_y = extern_fq_to_nibbles(p.y);
    let qdash_x0 = extern_fq_to_nibbles(q.x.c0);
    let qdash_x1 = extern_fq_to_nibbles(q.x.c1);
    let qdash_y0 = extern_fq_to_nibbles(q.y.c0);
    let qdash_y1 = extern_fq_to_nibbles(q.y.c1);

    let hash_new_t =
        extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le =
        extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
    let hash_add_le =
        extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
    let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
    let hash_root_claim = extern_hash_nibbles(vec![hash_new_t, hash_le], true);

    let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
    let aux_hash_le = extern_nibbles_to_limbs(hash_le_aux);
    let hash_input = extern_hash_nibbles(vec![hash_t, hash_le_aux], true);

    let simulate_stack_input = script! {
        // tmul_hints
        for hint in all_qs {
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

        // bit commits
        // { bc_elems }
    };

    let hint_out = ElemG2PointAcc {
        t: G2Affine::new_unchecked(new_tx, new_ty),
        add_le: Some((add_le0, add_le1)),
        dbl_le: Some((dbl_le0, dbl_le1)),
        // hash: hash_root_claim,
    };

    (hint_out, tap_point_ops(ate, all_scripts), simulate_stack_input)
}

