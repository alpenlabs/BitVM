use crate::bigint::U254;
use crate::bn254::utils::{
    fq12_push_not_montgomery, fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_check_tangent_line, new_hinted_ell_by_constant_affine, new_hinted_x_from_eval_point, new_hinted_y_from_eval_point, Hint
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::*;
use crate::chunk::wots::wots_compact_checksig_verify_with_pubkey;
use crate::signatures::wots::{wots160, wots256};
use crate::bn254;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, Field, Zero};
use num_bigint::BigUint;
use num_traits::One;
use std::collections::HashMap;
use std::ops::Neg;
use std::str::FromStr;

use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::wots::WOTSPubKey;
use super::{hint_models::*};

pub(crate) type HashBytes = [u8; 64];

pub type Link = (u32, bool);

#[derive(Debug, Clone)]
pub enum SigData {
    Sig256(wots256::Signature),
    Sig160(wots160::Signature),
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub(crate) msk: Option<&'static str>,
    pub(crate) cache: HashMap<u32, SigData>,
}

pub(crate) fn tup_to_scr(sig: &mut Sig, tup: Vec<(Link, [u8; 64])>) -> (Script, bool) {
    let mut compact_bc_scripts = script!();
    let mut execute: bool = false;
    if !sig.cache.is_empty() {
        for (skey, elem) in tup {
            let bcelem = sig.cache.get(&skey.0).unwrap();
            let scr = match bcelem {
                SigData::Sig160(signature) => {
                    let s = script! {
                        for (sig, _) in signature {
                            { sig.to_vec() }
                        }
                    };
                    let msg: Vec<u8> = signature.iter().map(|(_, c)| *c).collect();
                    let mut msg: [u8; 40] = msg[0..40].try_into().unwrap();
                    msg.reverse();
                    let mut padded_nibs = [0u8; 64]; 
                    padded_nibs[24..64].copy_from_slice(&msg[0..40]);
                    if padded_nibs != elem {
                        execute = true;
                    }
                    s
                }
                SigData::Sig256(signature) => {
                    let s = script! {
                        for (sig, _) in signature {
                            { sig.to_vec() }
                        }
                    };
                    let msg: Vec<u8> = signature.iter().map(|(_, c)| *c).collect();
                    let mut msg: [u8; 64] = msg[0..64].try_into().unwrap();
                    msg.reverse();
                    if msg != elem {
                        execute = true;
                    }
                    s
                }
            };
            compact_bc_scripts = compact_bc_scripts.push_script(scr.compile());
        }        
    }
    (compact_bc_scripts, execute)
}

pub(crate) fn wots_locking_script(link: Link, link_ids: &HashMap<u32, WOTSPubKey>) -> Script {
    wots_compact_checksig_verify_with_pubkey(link_ids.get(&link.0).unwrap())
}

pub(crate) fn gen_bitcom(
    link_ids: &HashMap<u32, WOTSPubKey>,
    sec_out: Link,
    sec_ins: Vec<Link>,
) -> Script {
    let mut tot_script = script!();
    tot_script = tot_script.push_script(wots_locking_script(sec_out, link_ids).compile());  // hash_in
    tot_script = tot_script.push_script({Fq::toaltstack()}.compile());
    // [px, py, qx0, qx1, qy0, qy1, in, out]
    for sec_in in sec_ins {
        tot_script = tot_script.push_script(wots_locking_script(sec_in, link_ids).compile());  // hash_in
        tot_script = tot_script.push_script({Fq::toaltstack()}.compile());
    }
    tot_script
}


// POINT DBL
pub(crate) fn tap_point_dbl() -> Script {
    let (hinted_double_line, _) = new_hinted_affine_double_line(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_check_tangent, _) = new_hinted_check_tangent_line(
        ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );


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
        { Fq2::roll(4)} // bias
        //[a, tx, ty, b]
        { Fq2::roll(6)} // alpha
        //[tx, ty, b, a]
        { Fq2::copy(6)} // t.x
        //[tx, ty, b, a, tx]
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
        //T
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {hash_fp4()} // HT

        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq::roll(4)} 
        {Fq::toaltstack()}
        {hash_fp4()} // HR

        { Fq::fromaltstack()} // [HR, HT]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq2::roll(4)} 
        {Fq2::toaltstack()}
        {hash_fp4()} // Hle
        // [Hle]

        for _ in 0..9 {
            {0}
        }
        {hash_fp2()}

        { Fq::fromaltstack() } // [ Hle, HR ]
        { Fq::roll(1) }
        {hash_fp2()}
        // [Hout]

        {Fq::fromaltstack()} {Fq::fromaltstack()} // [Hout, HT, Hinaux]
        {Fq::roll(2)} {Fq::toaltstack()} // [HT, inaux]
        {hash_fp2()}
        {Fq::fromaltstack()} {Fq::fromaltstack()} {Fq::fromaltstack()} //[Hin_calc, Hout_calc, hash_in_claim, Hout_claimed]
        {Fq::equalverify(1, 3)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };

    let sc = script! {
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}


pub(crate) fn hint_point_dbl(
    hint_t: ElemG2PointAcc,
    hint_py: ElemFq,
    hint_px: ElemFq,
) -> (ElemG2PointAcc, Script) {
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
    let (_, hints_double_line) =
        new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) =
        new_hinted_check_tangent_line(t, alpha_tangent, bias_minus_tangent);

    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&p.x);

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&p.y);

    let (_, hints_ell_tangent) =
        new_hinted_ell_by_constant_affine(p.x, p.y, alpha_tangent, bias_minus_tangent);

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
    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_point_add_with_frob(ate: i8) -> Script {
    assert!(ate == 1 || ate == -1);
    let mut ate_unsigned_bit = 1; // Q1 = pi(Q), T = T + Q1 // frob
    if ate == -1 {
        // Q2 = pi^2(Q), T = T - Q2 // frob_sq and negate
        ate_unsigned_bit = 0;
    }

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_add_line, _) = new_hinted_affine_add_line(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

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
        { hinted_check_chord_q }
        { Fq2::copy(12)} // alpha
        { Fq2::copy(12)} // bias
        { Fq2::copy(12)} // tx
        { Fq2::copy(12)} // ty
        { hinted_check_chord_t }


         //[a, b, tx, ty, p, qx, qy]
        { Fq2::copy(12) } // alpha
        { Fq2::copy(12) } // bias
        { Fq2::roll(8) } // p_dash
        { hinted_ell_chord }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1

        //[a, b, tx, ty, qx, qy]
        { Fq2::roll(8) } // bias
        //[a, tx, ty, qx, qy, b]
        { Fq2::roll(10) } // alpha
        //[tx, ty, qx, qy, b, a]
        { Fq2::roll(6) } //q.x
        //[tx, ty, qy, b, a, qx]
        { Fq2::copy(10) } // t.x from altstack
        //[tx, ty, qy, b, a, qx, tx]
        { hinted_add_line } // alpha, bias chord consumed
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
        //T
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {Fq2::toaltstack()} {Fq2::toaltstack()}
        {hash_fp4()} // HT

        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq::roll(4)} 
        {Fq::toaltstack()}
        {hash_fp4()} // HR

        { Fq::fromaltstack()} // [HR, HT]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq2::roll(4)} 
        {Fq2::toaltstack()}
        {hash_fp4()} // Hle
        // [Hle]

        for _ in 0..9 {
            {0}
        }
        {Fq::roll(1)}
        {hash_fp2()}

        { Fq::fromaltstack() } // [ Hle, HR ]
        { Fq::roll(1) }
        {hash_fp2()}
        // [Hout]

        {Fq::fromaltstack()} {Fq::fromaltstack()} // [Hout, HT, Hinaux]
        {Fq::roll(2)} {Fq::toaltstack()} // [HT, inaux]
        {hash_fp2()}
        {Fq::fromaltstack()} {Fq::fromaltstack()} {Fq::fromaltstack()} //[Hin_calc, Hout_calc, hash_in_claim, Hout_claimed]
        {Fq::equalverify(1, 3)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };

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

    let (beta12_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_12);
    let (beta13_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_13);

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

    let (beta22_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_22);

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
            {Fq::neg(0)}
            {fq2_push_not_montgomery(beta_13)} // beta_13
            {beta13_mul}
            {Fq2::toaltstack()}
            {Fq::neg(0)}
            {fq2_push_not_montgomery(beta_12)} // beta_12
            {beta12_mul}
            {Fq2::fromaltstack()}
        OP_ELSE
            {Fq2::toaltstack()}
            {fq2_push_not_montgomery(beta_22)} // beta_22
            {beta22_mul}
            {Fq2::fromaltstack()}
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

pub(crate) fn hint_point_add_with_frob(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_py: ElemFq,
    hint_px: ElemFq,
    ate: i8,
) -> (ElemG2PointAcc, Script) {
    assert!(ate == 1 || ate == -1);
    let (tt, p) = (hint_t.t, ark_bn254::G1Affine::new_unchecked(hint_px, hint_py));
    let q = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
    let mut qq = q.clone();
    let hash_le_aux = hint_t.hash_le();

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

    let mut frob_hint: Vec<Hint> = vec![];
    if ate == 1 {
        qq.x.conjugate_in_place();
        let (_, hint_beta12_mul) = Fq2::hinted_mul(2, qq.x, 0, beta_12);
        qq.x = qq.x * beta_12;

        qq.y.conjugate_in_place();
        let (_, hint_beta13_mul) = Fq2::hinted_mul(2, qq.y, 0, beta_13);
        qq.y = qq.y * beta_13;

        for hint in hint_beta13_mul {
            frob_hint.push(hint);
        }
        for hint in hint_beta12_mul {
            frob_hint.push(hint);
        }
    } else if ate == -1 {
        // todo: correct this code block
        let (_, hint_beta22_mul) = Fq2::hinted_mul(2, qq.x, 0, beta_22);
        qq.x = qq.x * beta_22;

        for hint in hint_beta22_mul {
            frob_hint.push(hint);
        }
    }

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    let new_tx = alpha_chord.square() - tt.x - qq.x;
    let new_ty = bias_minus_chord - alpha_chord * new_tx;
    let p_dash_x = p.x;
    let p_dash_y = p.y;

    let (_, hints_check_chord_t) =
        new_hinted_check_line_through_point(tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) =
        new_hinted_check_line_through_point(qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&p.x);

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&p.y);

    let (_, hints_ell_chord) =
        new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

    let mut all_qs = vec![];
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
    (hint_out, simulate_stack_input)
}

// POINT DBL AND ADD
pub(crate) fn tap_point_ops(ate: i8) -> Script {
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
    let (hinted_double_line, _) = new_hinted_affine_double_line(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_check_tangent, _) = new_hinted_check_tangent_line(
        ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_add_line, _) = new_hinted_affine_add_line(
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );

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
        { hinted_check_tangent }

        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(4 + 7) } // p_dash
        { hinted_ell_tangent }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1


        { Fq2::copy(bcsize+4)} // bias
        { Fq2::copy(bcsize+8)} // alpha
        { Fq2::copy(bcsize+6)} // t.x
        { hinted_double_line }
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
        { hinted_check_chord_q }
        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::fromaltstack() } // TT
        { Fq2::fromaltstack() }
        { Fq2::copy(2)} // t.x
        { Fq2::toaltstack() } // t.x to altstack
        { hinted_check_chord_t }


        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(10+1) } // p_dash
        { hinted_ell_chord }

        { Fq2::roll(4+bcsize+4) } // bias
        { Fq2::roll(6+bcsize+4) } // alpha
        { Fq2::copy(4+4+4+1) } //q.x
        { Fq2::fromaltstack() } // t.x from altstack
        { hinted_add_line } // alpha, bias chord consumed

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
        //T
        {hash_fp4()}

        { Fq::fromaltstack()} // inaux
        {hash_fp2()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}


        // Altstack: [dbl_le, R, add_le, hash_out]
        // Stack: []
        {Fq::fromaltstack()}
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq::roll(4)} {Fq::toaltstack()}
        {hash_fp4()}
        // Altstack: [dbl_le, R, hash_out]
        // Stack: [Hadd_le]

        {Fq::fromaltstack()}
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq2::roll(4)} {Fq2::toaltstack()}
        {hash_fp4()}
        // Altstack: [dbl_le, hash_out, Hadd_le]
        // Stack: [HR]

        {Fq2::fromaltstack()}
        // [HR, Hadd_le, hash_out]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq::roll(4)} {Fq::toaltstack()}
        {Fq::roll(4)} {Fq::toaltstack()}
        {Fq::roll(4)} {Fq::toaltstack()}
        {hash_fp4()}

        // Altstack: [hash_out, Hadd_le, HR]
        // Stack: [Hdbl_le]

        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        // Stack: [Hdbl_le, HR, Hadd_le]
        { Fq::roll(1)} {Fq::toaltstack()}
        { hash_fp2() }
        // [Hash_le]
        { Fq::fromaltstack() }
        { Fq::roll(1) }
        { hash_fp2() }
        { Fq::fromaltstack() }

        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };

    let sc = script! {
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}


pub(crate) fn hint_point_ops(
    hint_t: ElemG2PointAcc,
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    hint_py: ElemFq,
    hint_px: ElemFq,
    ate: i8,
) -> (ElemG2PointAcc, Script) {
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
    let (_, hints_double_line) =
        new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) =
        new_hinted_check_tangent_line(t, alpha_tangent, bias_minus_tangent);

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

    let (_, hints_check_chord_t) =
        new_hinted_check_line_through_point(tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) =
        new_hinted_check_line_through_point(qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&p.x);

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&p.y);

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&p.x);

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&p.y);

    let (_, hints_ell_tangent) =
        new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
    let (_, hints_ell_chord) =
        new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

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

    (hint_out, simulate_stack_input)
}

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
    let (_, hint_ell_t2) = new_hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = new_hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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

    let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(
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
    let (_, hint_ell_t2) = new_hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = new_hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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

    let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(
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


pub(crate) fn add_with_frob(q: ark_bn254::G2Affine, t: ark_bn254::G2Affine, ate: i8) -> ark_bn254::G2Affine {
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
        ark_bn254::Fq::from(beta_12y),
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
        ark_bn254::Fq::from(beta_13y),
    ])
    .unwrap();
    let beta_22x = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_22x.clone()),
        ark_bn254::Fq::from(beta_22y),
    ])
    .unwrap();

    let mut q = q.clone();
    if ate == 1 {
        q.x.conjugate_in_place();
        q.x = q.x * beta_12;
        q.y.conjugate_in_place();
        q.y = q.y * beta_13;
    } else if ate == -1 {
        q.x = q.x * beta_22;
    }
    let r = (t + q).into_affine();
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
        ark_bn254::Fq::from(beta_12y),
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
        ark_bn254::Fq::from(beta_13y),
    ])
    .unwrap();
    let beta_22x = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_22x.clone()),
        ark_bn254::Fq::from(beta_22y),
    ])
    .unwrap();

    // First
    let mut qq = qq2.clone();
    if ate == 1 {
        qq.x.conjugate_in_place();
        qq.x = qq.x * beta_12;
        qq.y.conjugate_in_place();
        qq.y = qq.y * beta_13;
    } else if ate == -1 {
        qq.x = qq.x * beta_22;
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
        qq.x.conjugate_in_place();
        qq.x = qq.x * beta_12;
        qq.y.conjugate_in_place();
        qq.y = qq.y * beta_13;
    } else if ate == -1 {
        qq.x = qq.x * beta_22;
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
    let (_, hint_ell_t2) = new_hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, bias_t2);
    let (_, hint_ell_t3) = new_hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, bias_t3);
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
        ark_bn254::Fq::from(beta_12y),
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
        ark_bn254::Fq::from(beta_13y),
    ])
    .unwrap();
    let beta_22x = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_22x.clone()),
        ark_bn254::Fq::from(beta_22y),
    ])
    .unwrap();

    // First
    let mut qq = qq2.clone();
    if ate == 1 {
        qq.x.conjugate_in_place();
        qq.x = qq.x * beta_12;
        qq.y.conjugate_in_place();
        qq.y = qq.y * beta_13;
    } else if ate == -1 {
        qq.x = qq.x * beta_22;
    }
    let alpha_t2 = (t2.y - qq.y) / (t2.x - qq.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - qq.x;
    let y2 = bias_t2 - alpha_t2 * x2;

    // Second
    let mut qq = qq3.clone();
    if ate == 1 {
        qq.x.conjugate_in_place();
        qq.x = qq.x * beta_12;
        qq.y.conjugate_in_place();
        qq.y = qq.y * beta_13;
    } else if ate == -1 {
        qq.x = qq.x * beta_22;
    }
    let alpha_t3 = (t3.y - qq.y) / (t3.x - qq.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - qq.x;
    let y3 = bias_t3 - alpha_t3 * x3;

    let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        alpha_t2,
        bias_t2,
    );
    let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(
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


// HASH_C
pub(crate) fn tap_hash_c() -> Script {
    let hash_scr = script! {
        for _ in 0..12 {
            {Fq::fromaltstack()}
        }
        // Stack:[f11 ..,f0]
        // Altstack: [f_hash_claim]
        for i in 0..12 {
            {Fq::roll(i)} // reverses order [f0..f11]
            {Fq::copy(0)}
            { Fq::push_hex_not_montgomery(Fq::MODULUS) }
            { U254::lessthan(1, 0) } // a < p
            OP_TOALTSTACK
        }
        for _ in 0..12 {
            OP_FROMALTSTACK
        }
        for _ in 0..11 {
            OP_BOOLAND
        }
        OP_IF // all less than p
            { hash_fp12_192() }
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)} OP_NOT OP_VERIFY
        OP_ELSE
            for _ in 0..12 {
                {Fq::drop()}
            }
            {Fq::fromaltstack()}
            {Fq::drop()}
        OP_ENDIF
    };
    let sc = script! {
        {hash_scr}
        OP_TRUE
    };
    sc
}


pub(crate) fn hint_hash_c(
    hint_in_c: Vec<ElemFq>,
) -> (ElemFp12Acc, Script) {
    let fvec = hint_in_c;
    let fhash = extern_hash_fps(fvec.clone(), false);

    let simulate_stack_input = script! {
        // bit commits raw
        // { bc_elems }
    };
    let f = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(fvec[0], fvec[1]),
            ark_bn254::Fq2::new(fvec[2], fvec[3]),
            ark_bn254::Fq2::new(fvec[4], fvec[5]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(fvec[6], fvec[7]),
            ark_bn254::Fq2::new(fvec[8], fvec[9]),
            ark_bn254::Fq2::new(fvec[10], fvec[11]),
        ),
    );
    (
        ElemFp12Acc {
            f,
            hash: fhash,
        },
        simulate_stack_input,
    )
}

// HASH_C
pub(crate) fn tap_hash_c2() -> Script {
    let hash_scr = script! {

        // {Fq::fromaltstack()} 
        // {Fq::fromaltstack()}
        // // Stack:[f_hash_claim, hash_in]

        // {Fq::toaltstack()}
        // {Fq::toaltstack()}
        {Fq12::copy(0)}
        { hash_fp12() }
        {Fq::toaltstack()}
        {hash_fp12_192()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        //[calc_192, calc_12, claim_12, inp_192]
        {Fq::equalverify(3, 1)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };
    let sc = script! {
        {hash_scr}
        OP_TRUE
    };
    sc
}

pub(crate) fn hint_hash_c2(
    hint_in_c: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let f = hint_in_c.f;
    let f = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let inhash = extern_hash_fps(f.clone(), false);
    let outhash = extern_hash_fps(f.clone(), true);

    let simulate_stack_input = script! {
        // bit commits raw
        {fq12_push_not_montgomery(hint_in_c.f)}
        // hash
        // hash192
        // { bc_elems }
    };
    (
        ElemFp12Acc {
            f: hint_in_c.f,
            hash: outhash,
        },
        simulate_stack_input,
    )
}

// precompute P
pub(crate) fn tap_precompute_Px() -> Script {
    let (eval_x, _) = new_hinted_x_from_eval_point(
        G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        ark_bn254::Fq::ONE,
    );

    let (on_curve_scr, _) =
        crate::bn254::curves::G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    let ops_scr = script! {
        {Fq::fromaltstack()} // pyd
        {Fq::fromaltstack()} // px
        {Fq::fromaltstack()} // py
        // {Fq::fromaltstack()} // pxd

        // Stack: [hints, pxd, pyd, px, py]
        // UpdatedStack: [hints, pyd, px, py]
        // Altstack: [pxd]
        {Fq::copy(0)}
        {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
        {Fq::equal(1, 0)}
        OP_IF
            for _ in 0..8 {
                {Fq::drop()}
            }
            {Fq::fromaltstack()} {Fq::drop()}
        OP_ELSE
            // Stack: [hints, pyd, px, py]
            {Fq2::copy(0)}
            // Stack: [hints, pyd, px, py, px, py]
            {on_curve_scr}
            OP_IF
                {eval_x}
                {Fq::fromaltstack()} // pxd
                {Fq::equal(1, 0)} OP_NOT OP_VERIFY
            OP_ELSE
                {Fq2::drop()}
                {Fq2::drop()}
                {Fq::drop()}
                {Fq::fromaltstack()} {Fq::drop()}
            OP_ENDIF
        OP_ENDIF
    };

    script! {
        {ops_scr}
        OP_TRUE
    }
}

// precompute P
pub(crate) fn tap_precompute_Py() -> Script {
    let (y_eval_scr, _) = new_hinted_y_from_eval_point(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);

    let ops_scr = script! {
        // [hints, pyd_calc] A:[pyd_claim, py]
        {Fq::copy(0)}
        {Fq::fromaltstack()}
        // [hints, pyd_calc, pyd_calc, py] A:[pyd_claim]
        {Fq::copy(0)}
        {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
        {Fq::equal(1, 0)}
        OP_IF
            {Fq2::drop()}
            {Fq::drop()}
            {Fq::fromaltstack()} {Fq::drop()}
        OP_ELSE
            // Stack: [hints, pyd_calc, pyd_calc, py]
            {y_eval_scr}
            // [hints, pyd_calc]
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)} OP_NOT OP_VERIFY
        OP_ENDIF
    };

    script! {
        {ops_scr}
        OP_TRUE
    }
}

pub(crate) fn hints_precompute_Px(
    hint_in_py: ark_bn254::Fq,
    hint_in_px: ark_bn254::Fq,
    hint_in_pdy: ark_bn254::Fq,
) -> (ark_bn254::Fq, Script) {
    // assert_eq!(sec_in.len(), 3);
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px, hint_in_py);
    let pdy = hint_in_pdy;
    // if p.y.inverse().is_some() {
    //     pdy = p.y.inverse().unwrap();
    // }
    let pdx = -p.x * pdy;
    let (_, hints) = { new_hinted_x_from_eval_point(p, pdy) };

    let pdash_x = extern_fq_to_nibbles(pdx);
    let pdash_y = extern_fq_to_nibbles(pdy);
    let p_x = extern_fq_to_nibbles(p.x);
    let p_y = extern_fq_to_nibbles(p.y);

    let (_, on_curve_hint) = crate::bn254::curves::G1Affine::hinted_is_on_curve(p.x, p.y);

    let simulate_stack_input = script! {
        for hint in on_curve_hint {
            { hint.push() }
        }
        for hint in hints {
            { hint.push() }
        }
        // bit commits raw
        // { bc_elems }
    };
    (pdx, simulate_stack_input)
}

pub(crate) fn hints_precompute_Py(
    hint_in_p: ark_bn254::Fq,
) -> (ark_bn254::Fq, Script) {
    // assert_eq!(sec_in.len(), 1);
    let p = hint_in_p.clone();

    let mut pdy = ark_bn254::Fq::ONE;
    if p.inverse().is_some() {
        pdy = p.inverse().unwrap();
    } else {
        println!("non-invertible input point");
    }
    let pdash_y = extern_fq_to_nibbles(pdy);

    let (_, hints) = new_hinted_y_from_eval_point(p, pdy);

    let p_y = extern_fq_to_nibbles(p);


    let simulate_stack_input = script! {
        for hint in hints {
            { hint.push() }
        }
        {fq_push_not_montgomery(pdy)} // calc pdy

        // bit commits raw
        // { bc_elems }
    };
    (pdy, simulate_stack_input)
}

// hash T4
pub(crate) fn tap_initT4() -> Script {
    let (on_curve_scr, _) =
        bn254::curves::G2Affine::hinted_is_on_curve(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);

    let hash_scr = script! {
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack:[f_hash_claim, x0,x1,y0,y1]
        // Altstack : [f_hash]
        {Fq2::copy(2)}
        {Fq2::copy(2)}
        {on_curve_scr}
        OP_IF
            { hash_fp4() }
            for _ in 0..64 {
                {0}
            }
            {pack_nibbles_to_limbs()}
            {hash_fp2()}
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)} OP_NOT OP_VERIFY
        OP_ELSE
            {Fq2::drop()}
            {Fq2::drop()}
            {Fq::fromaltstack()} {Fq::drop()}
        OP_ENDIF
        // if the point is not on curve
    };
    let sc = script! {
        {hash_scr}
        OP_TRUE
    };

    sc
}

pub(crate) fn hint_init_T4(
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
) -> (ElemG2PointAcc, Script) {
    let t4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0, hint_q4x1), ark_bn254::Fq2::new(hint_q4y0, hint_q4y1));
    let t4hash = extern_hash_fps(vec![t4.x.c0, t4.x.c1, t4.y.c0, t4.y.c1], false);
    let t4hash = extern_hash_nibbles(vec![t4hash, [0u8; 64]], true);

    let (_, hints) = bn254::curves::G2Affine::hinted_is_on_curve(t4.x, t4.y);

    let simulate_stack_input = script! {
        // bit commits raw
        for hint in hints {
            {hint.push()}
        }
    };
    let hint_out: ElemG2PointAcc = ElemG2PointAcc {
        t: t4,
        dbl_le: None,
        add_le: None,
        // hash: t4hash,
    };
    (hint_out, simulate_stack_input)
}

// POST MILLER

// FROB Fq12
pub(crate) fn tap_frob_fp12(power: usize) -> Script {
    let (hinted_frobenius_map, _) = Fq12::hinted_frobenius_map(power, ark_bn254::Fq12::one());

    let ops_scr = script! {
        // [f]
        {Fq12::copy(0)}
        // [f, f]
        {hinted_frobenius_map}
        // [f, g]
    };
    let hash_scr = script! {
        {Fq12::roll(12)}
        // [g,f]
        { hash_fp12_192() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
        { hash_fp12_192() }
        {Fq::fromaltstack()}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };
    let sc = script! {
        {ops_scr}
       {hash_scr}
        OP_TRUE
    };
    sc
}

pub(crate) fn hints_frob_fp12(
    hint_in_f: ElemFp12Acc,
    power: usize,
) -> (ElemFp12Acc, Script) {
    let f = hint_in_f.f;
    let (_, hints_frobenius_map) = Fq12::hinted_frobenius_map(power, f);

    let g = f.frobenius_map(power);

    let fhash = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        false,
    );
    let ghash = extern_hash_fps(
        vec![
            g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
        ],
        false,
    );

    let simulate_stack_input = script! {
        for hint in hints_frobenius_map {
            { hint.push() }
        }
        { fq12_push_not_montgomery(f) }
    };
    (ElemFp12Acc { f: g, hash: ghash }, simulate_stack_input)
}
