use crate::bigint::U254;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::*;
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::*;
use crate::bn254;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::{G1Affine};
use ark_ff::{AdditiveGroup, Field, MontFp};


use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::hint_models::*;
use super::taps_point_ops::hash_g2acc_with_hashed_le;


// HASH_C

pub(crate) fn chunk_hash_c(
    hint_in_c: Vec<ElemFq>,
) -> (ElemFp12Acc, Script, Script) {
    fn chunk_hash_c() -> Script {
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
        chunk_hash_c(),
        simulate_stack_input,
    )
}

// HASH_C
pub(crate) fn chunk_hash_c2(
    hint_in_c: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Script) {

    fn chunk_hash_c2() -> Script {
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
        chunk_hash_c2(),
        simulate_stack_input,
    )
}

// precompute P
pub(crate) fn chunk_precompute_px(
    hint_in_py: ark_bn254::Fq,
    hint_in_px: ark_bn254::Fq,
    hint_in_pdy: ark_bn254::Fq,
) -> (ark_bn254::Fq, Script, Script) {
    fn tap_precompute_px(on_curve_scr: Script) -> Script {
        let (eval_x, _) = hinted_x_from_eval_point(
            G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
            ark_bn254::Fq::ONE,
        );
    
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


    // assert_eq!(sec_in.len(), 3);
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px, hint_in_py);
    let pdy = hint_in_pdy;
    // if p.y.inverse().is_some() {
    //     pdy = p.y.inverse().unwrap();
    // }
    let pdx = -p.x * pdy;
    let (_, hints) = { hinted_x_from_eval_point(p, pdy) };

    let pdash_x = extern_fq_to_nibbles(pdx);
    let pdash_y = extern_fq_to_nibbles(pdy);
    let p_x = extern_fq_to_nibbles(p.x);
    let p_y = extern_fq_to_nibbles(p.y);

    let (on_curve_scr, on_curve_hint) = crate::bn254::curves::G1Affine::hinted_is_on_curve(p.x, p.y);

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
    (pdx, tap_precompute_px(on_curve_scr), simulate_stack_input)
}

// precompute P
pub(crate) fn chunk_precompute_py(
    hint_in_p: ark_bn254::Fq,
) -> (ark_bn254::Fq, Script, Script) {
    // assert_eq!(sec_in.len(), 1);
    fn tap_precompute_py(y_eval_scr: Script) -> Script {
    
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
                {Fq2::drop()}
                {Fq::fromaltstack()} 
                {Fq::drop()}
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
    
    
    
    let p = hint_in_p.clone();

    let mut pdy = ark_bn254::Fq::ONE;
    if p.inverse().is_some() {
        pdy = p.inverse().unwrap();
    } else {
        println!("non-invertible input point");
    }
    let pdash_y = extern_fq_to_nibbles(pdy);

    let (y_eval_scr, hints) = hinted_y_from_eval_point(p, pdy);

    let p_y = extern_fq_to_nibbles(p);


    let simulate_stack_input = script! {
        for hint in hints {
            { hint.push() }
        }
        {fq_push_not_montgomery(pdy)} // calc pdy

        // bit commits raw
        // { bc_elems }
    };
    (pdy, tap_precompute_py(y_eval_scr), simulate_stack_input)
}

// hash T4
pub(crate) fn tap_init_t4() -> Script {
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
            for _ in 0..9 { // aux_le
                {0}
            }
            {Fq::fromaltstack()}
            {hash_g2acc_with_hashed_le()}
            OP_NOT OP_VERIFY
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

pub(crate) fn hint_init_t4(
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


// INVERSE
pub(crate) fn tap_inv0() -> Script {

    let a = ElemFp12Acc::mock();

    let a = a.f;

    let (s_t1, _) = Fq6::hinted_square(a.c1);
    let (s_t0, _) = Fq6::hinted_square(a.c0);

    let ops_scr = script!{
        // [c0, c1]
       { Fq6::copy(0) }

        // compute beta * v1 = beta * c1^2
        { s_t1 }
        { Fq12::mul_fq6_by_nonresidue() }
        // [c0, beta * c1^2]

        // copy c0
        { Fq6::copy(12) }

        // compute v0 = c0^2 + beta * v1
        { s_t0 }
        // [yt1, t0]
        { Fq6::sub(0, 6) }
        // [c0, c1, t0]
    };

    let hash_scr = script!{
        {Fq6::toaltstack()}
        {hash_fp12()}
        {Fq6::fromaltstack()}
        {Fq::roll(6)} {Fq::toaltstack()}
        {hash_fp6()}
        {Fq::fromaltstack()}
        {Fq::roll(1)}
        // [Hc, Ht0]
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        // [Hc, Ht0, HKc, HKt0]
        {Fq::equalverify(1, 3)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };

    let scr = script!{
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn tap_inv1() -> Script {
    let a = ElemFp12Acc::mock();
    let t0 = a.f.c0;

    let (s_t0inv, _) = Fq6::hinted_inv(t0);

    let ops_scr = script!{
        // [aux, t0]
        {Fq6::copy(0)}
        // [aux, t0, t0]
        {Fq6::toaltstack()}
        {s_t0inv}
        {Fq6::fromaltstack()}
        {Fq6::roll(6)}
    }; // [t0, t1]
    let hash_scr = script!{
        {Fq6::toaltstack()}
        {hash_fp6()}
        {Fq6::fromaltstack()}
        {Fq::roll(6)} {Fq::toaltstack()}
        {hash_fp6()}
        {Fq::fromaltstack()}
        {Fq::roll(1)}
        // [Hc, Ht0]
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        // [Hc, Ht0, HKc, HKt0]
        {Fq::equalverify(1, 3)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };
    let scr = script!{
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn tap_inv2() -> Script {
    let (a, t1) = (ElemFp12Acc::mock(), ElemFp12Acc::mock());
    let t1 = t1.f.c0;
    let a = a.f;

    let (s_c0, _) = Fq6::hinted_mul(0, t1, 18, a.c0);
    let (s_c1, _) = Fq6::hinted_mul(0, -a.c1, 12, t1);

    let ops_scr = script!{
        {Fq12::copy(6)}
        // [c0, c1, t1]
        { Fq6::copy(12) }
        // [c0, c1, t1, c0, c1, t1]

        // dup inv v0
        { Fq6::copy(0) }
        // [c0, c1, t1, t1]

        // compute c0
        { s_c0 }
        // [c1, t1, d0]

        // compute c1
        { Fq6::neg(12) }
        // [t1, d0, -c1]
        { s_c1 }
        // [c0, c1, t1, d0, d1]
    };
    let hash_scr = script!{
        {Fq12::toaltstack()}
        {Fq6::toaltstack()}
        {hash_fp12()}

        {Fq6::fromaltstack()}
        {Fq::roll(6)} {Fq::toaltstack()}
        {hash_fp6()} {Fq::fromaltstack()}

        {Fq12::fromaltstack()}
        {Fq2::roll(12)} {Fq2::toaltstack()}
        {hash_fp12_192()} {Fq2::fromaltstack()}

        // [Hd, Ht, Hc]

        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // // [Hd, Ht, Hc, HKc, HKt, HKd]

        {Fq::equalverify(1, 4)}
        {Fq::equalverify(1, 2)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    };
    let scr = script!{
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn hint_inv2(
    t1: ElemFp12Acc,
    a: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let t1 = t1.f.c0;
    let a = a.f;

    let c0 = a.c0 * t1;
    let c1 = -a.c1 * t1;

    let (_, h_c0) = Fq6::hinted_mul(0, t1, 18, a.c0);
    let (_, h_c1) = Fq6::hinted_mul(0, -a.c1, 12, t1);

    let mut hints: Vec<Hint> = vec![];
    for hint in vec![h_c0, h_c1] {
        hints.extend_from_slice(&hint);
    }

    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in hints {
            { hint.push() }
        }
        {fq12_push_not_montgomery(a)}
        {fq6_push_not_montgomery(t1)}
    };

    let hash_h = extern_hash_fps(
        fp12_to_vec(ark_bn254::Fq12::new(c0, c1)),
        false,
    );

    let hout: ElemFp12Acc = ElemFp12Acc { f: ark_bn254::Fq12::new(c0, c1), hash: hash_h };
    (
        hout,
        simulate_stack_input,
    )
}

pub(crate) fn hint_inv1(
    a: ElemFp12Acc
) -> (ElemFp12Acc, Script) {
    let t0 = a.f.c0;
    let t1 = t0.inverse().unwrap();

    let (_, h_t0inv) = Fq6::hinted_inv(t0);
    let aux_t6 = Fq6::calc_fp2_inv_aux(t0);

    let hash_h = extern_hash_fps(
        vec![
            t1.c0.c0, t1.c0.c1, t1.c1.c0, t1.c1.c1, t1.c2.c0, t1.c2.c1,
        ],
        true,
    );

    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in h_t0inv {
            { hint.push() }
        }
        {fq_push_not_montgomery(aux_t6)}
        {fq6_push_not_montgomery(t0)}
    };

    let hout: ElemFp12Acc = ElemFp12Acc { f: ark_bn254::Fq12::new(t1, ark_bn254::Fq6::ZERO), hash: hash_h };
    (
        hout,
        simulate_stack_input,
    )
}

pub(crate) fn hint_inv0(
    a: ElemFp12Acc
) -> (ElemFp12Acc, Script) {
    let a = a.f;

    fn mul_fp6_by_nonresidue_in_place(fe: ark_bn254::Fq6) -> ark_bn254::Fq6 {
        let mut fe = fe.clone();
        const NONRESIDUE: ark_bn254::Fq2 = ark_bn254::Fq2::new(MontFp!("9"), ark_bn254::Fq::ONE);
        let old_c1 = fe.c1;
        fe.c1 = fe.c0;
        fe.c0 = fe.c2 * NONRESIDUE;
        fe.c2 = old_c1;
        fe
    }

    let t1 = a.c1 * a.c1;
    let t0 = a.c0 * a.c0;
    let yt1 = mul_fp6_by_nonresidue_in_place(t1);
    let t0 = t0-yt1;

    let (_, h_t1) = Fq6::hinted_square(a.c1);
    let (_, h_t0) = Fq6::hinted_square(a.c0);

    let mut hints: Vec<Hint> = vec![];
    for hint in vec![h_t1, h_t0] {
        hints.extend_from_slice(&hint);
    }

    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in hints {
            { hint.push() }
        }
        {fq12_push_not_montgomery(a)}
    };

    let hash_h = extern_hash_fps(
        vec![
            t0.c0.c0, t0.c0.c1, t0.c1.c0, t0.c1.c1, t0.c2.c0, t0.c2.c1,
        ],
        true,
    );

    let hout: ElemFp12Acc = ElemFp12Acc { f: ark_bn254::Fq12::new(t0, ark_bn254::Fq6::ZERO), hash: hash_h };
    (
        hout,
        simulate_stack_input,
    )
}

