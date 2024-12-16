use crate::bigint::U254;
use crate::bn254::utils::*;
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::*;
use crate::bn254;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{G1Affine};
use ark_ff::{AdditiveGroup, Field};


use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::hint_models::*;


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
        {Fq12::copy(0)}
        {Fq12::toaltstack()}
        { hash_fp12() }
        {Fq12::fromaltstack()}
        { Fq::roll(12) } { Fq::toaltstack() }
        {hash_fp12_192()}

        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // [calc_192, calc_12, claim_12, inp_192]
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
