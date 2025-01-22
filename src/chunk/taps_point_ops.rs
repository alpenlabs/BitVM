use crate::bn254::curves::{G2Affine};
use crate::bn254::{self, utils::*};
use crate::bn254::{fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use std::ops::Neg;

use super::element::*;

fn utils_point_double_eval(t: ark_bn254::G2Affine, p: ark_bn254::G1Affine) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let (alpha, bias) = if t_is_zero {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    } else {
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    };

    let (hinted_script1, hint1) = hinted_check_tangent_line(t,alpha, -bias);
    let (hinted_script2, hint2) = hinted_affine_double_line(t.x,alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut dbl_le0 = alpha;
    dbl_le0.mul_assign_by_fp(&p.x);
    let mut dbl_le1 = -bias;
    dbl_le1.mul_assign_by_fp(&p.y);
    
    let result = ((t + t).into_affine(), (dbl_le0, dbl_le1));
    if !t_is_zero { 
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
    }
 
    let script = script! {    
        // a, b, tx, ty, px, py
        { Fq2::toaltstack()}
        { bn254::curves::G2Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
        OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // -bias, ...,  x, y, alpha
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // x, y, alpha, -bias
            { Fq2::copy(2) }                          // x, y, alpha, -bias, alpha
            { Fq2::copy(2) }                          // x, y, alpha, -bias, alpha, -bias
            { Fq2::copy(10) }                          // x, y, alpha, -bias, alpha, -bias, x
            { Fq2::copy(10) }                          // x, y, alpha, -bias, alpha, -bias, x, y
            { hinted_script1 }                       // x, y, alpha, -bias, is_tangent_line_correct 
            { Fq2::copy(2) } {Fq2::copy(2)}           // x, y alpha, -bias, alpha, -bias
            { Fq2::copy(10) }                          // x, y alpha, -bias, alpha, -bias, x
            { hinted_script2 }                       // x, y, alpha, -bias, x', y'
            {Fq2::fromaltstack()}                   // x, y, alpha, -bias, x', y', px, py
            {Fq2::roll(4)} {Fq2::roll(4)}           // x, y, alpha, -bias, px, py,  x', y'
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            { hinted_script3 }                         // x, y, le,
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // x, y, le0, le1, x', y'
            {Fq2::roll(6)} {Fq2::roll(6)}                            // x, y, x', y', le
        OP_ENDIF
    };
    (result, script, hints)
}

fn utils_point_add_eval(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine, p: ark_bn254::G1Affine) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let q_is_zero = q.is_zero() || (q == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // q is none or Some(0)
    
    let (alpha, bias) = if !t_is_zero && !q_is_zero && t != -q { // todo: add if t==q and if t == -q
        let alpha = (t.y - q.y) / (t.x - q.x);
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    } else {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    };

    let (hinted_script1, hint1) = hinted_check_chord_line(t, q, alpha, -bias); // todo: remove unused arg: bias
    let (hinted_script2, hint2) = hinted_affine_add_line(t.x, q.x, alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut add_le0 = alpha;
    add_le0.mul_assign_by_fp(&p.x);
    let mut add_le1 = -bias;
    add_le1.mul_assign_by_fp(&p.y);

    let result = ((t + q).into_affine(), (add_le0, add_le1));

    if !t.is_zero() && !q.is_zero() && t != -q {
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
    }

    let script = script! {        // tx ty qx qy
        // a, b, tx, ty, qx, qy, px, py
        {Fq2::toaltstack()}
        { G2Affine::is_zero_keep_element() }
        OP_IF
            { G2Affine::drop() }
        OP_ELSE
            { G2Affine::roll(1) }
            { G2Affine::is_zero_keep_element() }
            OP_IF
                { G2Affine::drop() }
            OP_ELSE                                // qx qy tx ty
                {G2Affine::copy(1)}
                // qx qy tx ty qx qy
                { Fq2::neg(0)}
                // qx qy tx ty qx -qy
                {G2Affine::copy(1)}
                // qx qy tx ty qx -qy tx ty
                {G2Affine::equal()} 
                // qx qy tx ty 0/1
                OP_IF // qx == tx
                    {G2Affine::drop()}
                    {G2Affine::drop()}
                    {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
                    {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
                OP_ELSE
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }                                  // qx qy tx ty c3 c4
                    { Fq2::copy(2) }
                    { Fq2::copy(2) }                    // qx qy tx ty c3 c4 c3 c4
                    { Fq2::copy(10) }
                    { Fq2::copy(10) }                    // qx qy tx ty c3 c4 c3 c4 tx ty
                    { Fq2::copy(18) }
                    { Fq2::roll(18) }                    // qx tx ty c3 c4 c3 c4 tx ty qx qy
                    { hinted_script1 }                 // qx tx ty c3 c4 0/1

                    {Fq2::copy(2)} {Fq2::copy(2)}     // qx tx ty c3 c4, c3 c4
                    { Fq2::copy(10) }                    // qx tx ty c3 c4, c3 c4, tx
                    { Fq2::roll(14) }                    // c3 c4 tx qx
                    { hinted_script2 }                 // tx, ty, c3, c4, x' y'
                    {Fq2::fromaltstack()}             // tx, ty, c3, c4, x' y', px, py
                    {Fq2::roll(4)} {Fq2::roll(4)}           // tx, ty, alpha, -bias, px, py,  x', y'
                    {Fq2::toaltstack()} {Fq2::toaltstack()}
                    { hinted_script3 }                         // tx, ty, le,
                    {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // tx, ty, le0, le1, x', y'
                    {Fq2::roll(6)} {Fq2::roll(6)}                            // tx, ty, x', y', le
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    };
    (result, script, hints)
}

pub(crate) fn chunk_point_add_with_frob(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_p: ElemG1Point,
    ate: i8,
) -> (ElemG2PointAcc, Script, Vec<Hint>) {
    fn tap_point_add(frob_scr: Script, add_eval_scr: Script) -> Script {

        let ops_script = script! {
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            //[a, b, tx, ty, p, qx, qy]

            {Fq2::roll(4)} {Fq2::copy(0)} {Fq2::toaltstack()} 
            {Fq::roll(6)} {Fq::toaltstack()}

            //[a, b, tx, ty, qx, qy, px, py]
            {add_eval_scr}
            // [t, R, le]
    
            // Altstack: [hash_out, hash_p, hash_t, p, hash_inaux]
            // Stack: [t, R, le]
        };

        let pre_hash_script = script!{
            {Fq::fromaltstack()}
            {Fq2::fromaltstack()}
            // Altstack: [hash_out, hash_in]
            // Stack: [t, R, le, hash_inaux, p]
            for _ in 0..8 {
                {Fq::roll(10)}
            }
            // Altstack: [hash_out, hash_p_in, hash_t_in]
            // Stack: [t, hash_inaux, p, R, le]
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            // [t, hash_inaux, p, R, 0, le]
        };
    
        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, Rx, Ry, 0, 0, le0, le1, le1]
            {hash_messages(vec![ElementType::G2AddEval, ElementType::G1, ElementType::G2DblAddEval])}
            // [Rx, Ry, le0, le1, 0, 0]
            OP_TRUE
        };
        
        let precompute_script = script! {
            // bring back from altstack
            for _ in 0..4 {
                {Fq::fromaltstack()}
            }
            {frob_scr}
            for _ in 0..4 {
                {Fq::toaltstack()}
            }
            // Output: [tx, ty, px, py] [Hout, Hpin, Htin, Q]
        };
    

        let sc = script! {
            {precompute_script}
            {ops_script}
            {pre_hash_script}
            // {hash_script}
        };
        sc
    }
    
    
    assert!(ate == 1 || ate == -1);
    let t = hint_t.t;
    let p = hint_p;
    let q = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
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

    let mut hints = frob_hint;
    let ((new_t, (add_le0, add_le1)), add_scr, add_hint) = utils_point_add_eval(t, qq, p);
    hints.extend_from_slice(&add_hint);

    let hint_out: ElemG2PointAcc = ElemG2PointAcc {
        t: new_t,
        add_le: Some((add_le0, add_le1)),
        dbl_le: None,
    };
    (hint_out, tap_point_add(frob_scr, add_scr), hints)
}

pub(crate) fn chunk_point_dbl(
    hint_t: ElemG2PointAcc,
    hint_p: ElemG1Point,
) -> (ElemG2PointAcc, Script, Vec<Hint>) {
    fn tap_point_dbl(dbl_eval_scr: Script) -> Script {

        let ops_script = script! {
            //[a, b, tx, ty, aux_t_in, px, py]
            {Fq2::copy(0)} {Fq2::toaltstack()}
            {Fq::roll(2)}
            {Fq::toaltstack()} // hash aux_t_in
    
            //[a, b, tx, ty, px, py]
            {dbl_eval_scr}
            // [t, R, le]
    
            // Altstack: [hash_out, hash_p, hash_t, p, hash_inaux]
            // Stack: [t, R, le]
        };
        
        let pre_hash_script = script!{
            {Fq::fromaltstack()}
            {Fq2::fromaltstack()}
            // Altstack: [hash_out, hash_p_in, hash_t_in]
            // Stack: [t, R, le, hash_inaux, p]
            for _ in 0..8 {
                {Fq::roll(10)}
            }
            // Altstack: [hash_out, hash_p_in, hash_t_in]
            // Stack: [t, hash_inaux, p, R, le]
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
        };
    
        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, p, Rx, Ry, le0, le1, 0, 0]
            {hash_messages(vec![ElementType::G2DblEval, ElementType::G1, ElementType::G2DblAddEval])}
            OP_TRUE

        };
    
        let sc = script! {
            {ops_script}
            {pre_hash_script}
            // {hash_script}
        };
        sc
    }
    
    // assert_eq!(sec_in.len(), 3);
    let t = hint_t.t;
    let p = hint_p;
    
    let ((new_t, (dbl_le0, dbl_le1)), scr, hints) = utils_point_double_eval(t, p);
    // affine mode as well

    let hint_out: ElemG2PointAcc = ElemG2PointAcc {
        t: new_t,
        dbl_le: Some((dbl_le0, dbl_le1)),
        add_le: None,
    };
    (hint_out, tap_point_dbl(scr), hints)
}

pub(crate) fn chunk_point_ops(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_p: ElemG1Point,
    ate: i8,
) -> (ElemG2PointAcc, Script, Vec<Hint>) {
    fn tap_point_dbl_and_add(double_scr: Script, add_eval_scr: Script, ate: i8) -> Script {

        let ops_script = script! {
            //[a, b, tx, ty, p]

            {Fq2::copy(0)} {Fq2::toaltstack()}
            {Fq::roll(2)}
            {Fq::toaltstack()} // hash aux_t_in

            //[a, b, tx, ty px, py] [q, p, hash_t_in]
            {double_scr}
            // [hints.., t, 2t, dbl_le]

            {Fq::fromaltstack()} {Fq2::fromaltstack()} // hash_t_in and p
            {Fq2::fromaltstack()} {Fq2::fromaltstack()} // q
            // [hints.., t, 2t, dbl_le, hash_t_in, p, q]
            {Fq2::copy(4)} {Fq2::toaltstack()}
            // [hints.., t, 2t, dbl_le, hash_t_in, p, q]
            {Fq::roll(6)} {Fq::toaltstack()}
            // [hints.., t, 2t, dbl_le, p, q]
            {Fq2::roll(8)} {Fq2::roll(8)}
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            // [hints.., t, 2t, p, q]
            {Fq2::roll(4)}
            // [hints.., t, 2t, q, p]            
            {add_eval_scr}

            // [t, 2t, nt, add_le], [p, hash_t_in, dbl_le]
            for _ in 0..4 {
                {Fq2::toaltstack()}
            }
            {Fq2::drop()} {Fq2::drop()}
            for _ in 0..4 {
                {Fq2::fromaltstack()}
            }
            // [t, nt, add_le], [p, hash_t_in, dbl_le]
            {Fq2::fromaltstack()} {Fq2::fromaltstack()} 
            // [t, nt, add_le, dbl_le], [p, hash_t_in]
            {Fq2::roll(6)} {Fq2::roll(6)}
            // [t, nt, dbl_le, add_le], [p, hash_t_in]
        };



        let pre_hash_script = script!{
            // [t, nt, dbl_le, add_le], [p, hash_t_in]
            {Fq2::roll(14)} {Fq2::roll(14)}
            // [nt, dbl_le, add_le, t], [p, hash_t_in]
            {Fq::fromaltstack()}
            {Fq2::fromaltstack()} 
            // [nt, dbl_le, add_le, t, hash_t_in, p]
            for _ in 0..12*Fq::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL
            }
            // [t, hash_t_in, p, nt, dbl_le, add_le]
        };
    
        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, p, Rx, Ry, 0, 0, le0, le1, le1]
            {hash_messages(vec![ElementType::G2AddEval, ElementType::G1, ElementType::G2DblAddEval])}
            // [Rx, Ry, le0, le1, 0, 0]
            OP_TRUE
        };
        
        let mut precompute_script = script!();
        if ate == -1 {
            precompute_script = script! {
                // bring back from altstack
                {Fq::fromaltstack()}
                {Fq::fromaltstack()}
                {Fq::fromaltstack()}
                {Fq::neg(0)}
                {Fq::fromaltstack()}
                {Fq::neg(0)}
                for _ in 0..4 {
                    {Fq::toaltstack()}
                }
                // Output: [tx, ty, px, py] [Hout, Hpin, Htin, Q]
            };
        }

        let sc = script! {
            {precompute_script}
            {ops_script}
            {pre_hash_script}
            // {hash_script}
        };
        sc
    }
    
    
    assert!(ate == 1 || ate == -1);
    let t = hint_t.t;
    let p = hint_p;
    let q = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
    
    let mut qq = q.clone();
    if ate == -1 {
        qq = q.neg();
    }

    let mut hints = vec![];
    let ((two_t, (dbl_le0, dbl_le1)), double_scr, double_hint) = utils_point_double_eval(t, p);
    let ((new_t, (add_le0, add_le1)), add_scr, add_hint) = utils_point_add_eval(two_t, qq, p);
    hints.extend_from_slice(&double_hint);    
    hints.extend_from_slice(&add_hint);

    let hint_out: ElemG2PointAcc = ElemG2PointAcc {
        t: new_t,
        add_le: Some((add_le0, add_le1)),
        dbl_le: Some((dbl_le0, dbl_le1)),
    };
    (hint_out, tap_point_dbl_and_add(double_scr, add_scr, ate), hints)
}

#[cfg(test)]
mod test {
    use ark_ff::{Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{curves::{G1Affine, G2Affine}, fp254impl::Fp254Impl, fq::Fq, fq2::Fq2}, chunk::taps_point_ops::{fq2_push_not_montgomery, fq_push_not_montgomery, utils_point_add_eval, ElemG2PointAcc, ElemTraitExt, Element}, execute_script, execute_script_without_stack_limit};

    use super::utils_point_double_eval;


    #[test]
    fn test_point_double_eval() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        
        let ((r, le), scr, hints) = utils_point_double_eval(t, p);

        // a, b, tx, ty, px, py

        let script = script!(
            for h in hints {
                {h.push()}
            }
            {G2Affine::push_not_montgomery(t)}
            {G1Affine::push_not_montgomery(p)}
            // [hints, tx, ty, px, py]
            {scr}
            // t, R, dbl_le
            {fq2_push_not_montgomery(le.1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(le.0)}
            {Fq2::equalverify()}

            {fq2_push_not_montgomery(r.y)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(r.x)}
            {Fq2::equalverify()}
            
            {fq2_push_not_montgomery(t.y)}
            {Fq2::equalverify()}

            {fq2_push_not_montgomery(t.x)}
            {Fq2::equalverify()}

            OP_TRUE
        );
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
        assert!(res.final_stack.len() == 1);    
    }


    #[test]
    fn test_point_add_eval() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        let ((r, le), hinted_check_add, hints) = utils_point_add_eval(t, q, p);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { G1Affine::push_not_montgomery(p) }
            { hinted_check_add.clone() }
            // [x']

            {fq2_push_not_montgomery(le.1)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(le.0)}
            {Fq2::equalverify()}

            {fq2_push_not_montgomery(r.y)}
            {Fq2::equalverify()}
            {fq2_push_not_montgomery(r.x)}
            {Fq2::equalverify()}
            
            {fq2_push_not_montgomery(t.y)}
            {Fq2::equalverify()}

            {fq2_push_not_montgomery(t.x)}
            {Fq2::equalverify()}
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "point_add_eval: {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

}