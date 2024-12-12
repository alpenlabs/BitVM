use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{
    fq12_push_not_montgomery, fq2_push_not_montgomery, fq6_push_not_montgomery, fq_push_not_montgomery, Hint
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::{
    extern_hash_nibbles,  extern_nibbles_to_limbs, hash_fp12,
    hash_fp12_with_hints, hash_fp2, hash_fp4, hash_fp6, 
};
use crate::chunk::taps::{tup_to_scr};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ff::{AdditiveGroup, Field, MontFp, Zero};
use bitcoin::opcodes::OP_TRUE;
use num_traits::One;

use super::primitves::{extern_hash_fps, fp12_to_vec, hash_fp12_192};
use super::taps::{HashBytes, Link, Sig};
use super::hint_models::*;
// SPARSE DENSE

pub(crate) fn tap_sparse_dense_mul(dbl_blk: bool) -> Script {
    let (hinted_script, _) = Fq12::hinted_mul_by_34(
        ark_bn254::Fq12::one(),
        ark_bn254::Fq2::one(),
        ark_bn254::Fq2::one(),
    );
    let mut add = 0;
    if dbl_blk == false {
        add = 1;
    }

    let ops_script = script! {
        // Stack: [...,hash_out, hash_in1, hash_in2]
        // Move aux hashes to alt stack
        {Fq::toaltstack()}
        {Fq::toaltstack()}

        // Stack [f, dbl_le0, dbl_le1]
        {Fq12::copy(4)}
        {Fq2::copy(14)}
        {Fq2::copy(14)}

        // Stack [f, dbl_le0, dbl_le1, f, dbl_le0, dbl_le]
        { hinted_script }
        // Stack [f, dbl_le0, dbl_le1, f1]
        // Fq_equal verify
    };
    let hash_script = script! {
        {hash_fp12()}
        // Stack [f, dbl_le0, dbl_le1, Hf1]

        {Fq2::roll(3)}
        {Fq2::roll(3)}
        {hash_fp4()} // hash_le
        {Fq::fromaltstack()} // addle
        // {Fq::fromaltstack()}
        {add} 1 OP_NUMEQUAL
        OP_IF
            {Fq::roll(1)}
        OP_ENDIF

        {hash_fp2()}
        {Fq::fromaltstack()} // T_le
        {Fq::roll(1)}
        {hash_fp2()}

        {Fq::fromaltstack()} // hash_in_sparse
        {Fq::equalverify(1, 0)}

        {Fq::toaltstack()} // Hf1 to altstack
        {hash_fp12()} // Hash_calcin
        {Fq::fromaltstack()} // Hash_calcout
        {Fq::fromaltstack()} // Hash_claimin
        {Fq::fromaltstack()} // Hash_claimout
        {Fq::equalverify(3, 1)}
        {Fq::equal(1,0)} OP_NOT OP_VERIFY
    };
    let scr = script! {
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    scr
}

pub(crate) fn hint_sparse_dense_mul(
    hint_in_a: ElemFp12Acc,
    hint_in_g: ElemG2PointAcc,
    dbl_blk: bool,
) -> (ElemFp12Acc, Script) {
    //assert_eq!(sec_in.len(), 2);
    if dbl_blk {
        assert!(hint_in_g.dbl_le.is_some());
    } else {
        assert!(hint_in_g.add_le.is_some());
    }

    let mut cur_le = (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
    if dbl_blk {
        cur_le = hint_in_g.dbl_le.unwrap();
    } else {
        cur_le = hint_in_g.add_le.unwrap();
    }
    
    let (f, cur_le0, cur_le1) = (hint_in_a.f, cur_le.0, cur_le.1);
    let (_, hints) = Fq12::hinted_mul_by_34(f, cur_le0, cur_le1);
    let mut f1 = f;
    f1.mul_by_034(&ark_bn254::Fq2::ONE, &cur_le0, &cur_le1);

    // assumes sparse-dense after doubling block, hashing arrangement changes otherwise
    let hash_new_t = extern_hash_fps(vec![hint_in_g.t.x.c0, hint_in_g.t.x.c1, hint_in_g.t.y.c0, hint_in_g.t.y.c1], true);
    let hash_cur_le =
        extern_hash_fps(vec![cur_le0.c0, cur_le0.c1, cur_le1.c0, cur_le1.c1], true);
    let hash_other_le = hint_in_g.hash_other_le(dbl_blk);
    let mut hash_le = extern_hash_nibbles(vec![hash_cur_le, hash_other_le], true);
    if !dbl_blk {
        hash_le = extern_hash_nibbles(vec![hash_other_le, hash_cur_le], true);
    }
    let hash_sparse_input = extern_hash_nibbles(vec![hash_new_t, hash_le], true);

    let hash_dense_input = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    );
    let hash_dense_output = extern_hash_fps(
        vec![
            f1.c0.c0.c0,
            f1.c0.c0.c1,
            f1.c0.c1.c0,
            f1.c0.c1.c1,
            f1.c0.c2.c0,
            f1.c0.c2.c1,
            f1.c1.c0.c0,
            f1.c1.c0.c1,
            f1.c1.c1.c0,
            f1.c1.c1.c1,
            f1.c1.c2.c0,
            f1.c1.c2.c1,
        ],
        true,
    );
    let hash_other_le_limbs = extern_nibbles_to_limbs(hash_other_le);
    let hash_t_limbs = extern_nibbles_to_limbs(hash_new_t);

    // data passed to stack in runtime

    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq2_push_not_montgomery(cur_le0)}
        {fq2_push_not_montgomery(cur_le1)}

        for i in 0..hash_other_le_limbs.len() {
            {hash_other_le_limbs[i]}
        }
        for i in 0..hash_t_limbs.len() {
            {hash_t_limbs[i]}
        }

        // { bc_elems }
    };

    (
        ElemFp12Acc {
            f: f1,
            hash: hash_dense_output,
        },
        simulate_stack_input,
       // should_validate
    )
}

// DENSE DENSE MUL ZERO

pub(crate) fn tap_dense_dense_mul0() -> Script {
    let check_is_identity: bool = false;
    let (hinted_mul, _) =
        Fq12::hinted_mul_first(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }

    let hash_scr = script! {
        {hash_fp6()} // c
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} //
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c
        // Alt: [od, d, s], [c0, d, s]
        // Stack: [gc, fc, hc, gk, fk, hk]
        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g

        {Fq::equalverify(1, 4)}
        {Fq::equalverify(1, 3)}
        {Fq::equal(0, 1)} OP_NOT OP_VERIFY
    };

    let ops_scr = script! {
        { hinted_mul }
        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            {fq_push_not_montgomery(ark_bn254::Fq::one())}
            for _ in 0..5 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn hints_dense_dense_mul0(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;

    let (_, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);

    let hash_f = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    ); // dense
    let hash_g = extern_hash_fps(
        vec![
            g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
        ],
        false,
    ); // sparse
    let hash_h = extern_hash_fps(
        vec![
            h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
        ],
        true,
    );

    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in mul_hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes
        // in2: SS or c' link
        // in1: SD or DD1 link
        // out
        // { bc_elems }
    };

    (
        ElemFp12Acc {
            f: h,
            hash: hash_h,
        },
        simulate_stack_input,
    )
}


// DENSE DENSE MUL ONE

pub(crate) fn tap_dense_dense_mul1() -> Script {
    let check_is_identity: bool = false;
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let (hinted_mul, _) =
        Fq12::hinted_mul_second(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let hash_scr = script! {
        {Fq::fromaltstack()} // Hc0
        {hash_fp12_with_hints()} // Hc
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} //
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c

        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g
        // [gc, fc, hc,  gk, fk, hk]
        {Fq::equalverify(1, 4)}
        {Fq::equalverify(1, 3)}
        {Fq::equal(0, 1)} OP_NOT OP_VERIFY
    };

    let ops_scr = script! {
        { hinted_mul }
        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            for _ in 0..6 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn hints_dense_dense_mul1(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
    hint_in_c0: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let (_, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;

    let hash_f = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    );
    let hash_g = extern_hash_fps(
        vec![
            g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
        ],
        false,
    );

    // let hash_c0 = extern_hash_fps(
    //     vec![
    //         h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
    //     ],
    //     true,
    // );
    let hash_c = extern_hash_fps(
        vec![
            h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1, h.c1.c0.c0,
            h.c1.c0.c1, h.c1.c1.c0, h.c1.c1.c1, h.c1.c2.c0, h.c1.c2.c1,
        ],
        true,
    );


    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in mul_hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes

        // in3: links to DD0
        // in2: SS or c' link
        // in1: SD or DD1 link
        // out
        // { bc_elems }
    };
    (
        ElemFp12Acc {
            f: h,
            hash: hash_c,
        },
        simulate_stack_input,
    )
}


// SQUARING

pub(crate) fn hint_squaring(
    hint_in_a: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let a = hint_in_a.f;
    let (_, hints) = Fq12::hinted_square(a);
    let b = a.square();
    let a_hash = extern_hash_fps(
        vec![
            a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0,
            a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1,
        ],
        true,
    );
    let b_hash = extern_hash_fps(
        vec![
            b.c0.c0.c0, b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0, b.c0.c2.c1, b.c1.c0.c0,
            b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0, b.c1.c2.c1,
        ],
        true,
    );
   //assert_eq!(hint_in.ahash, a_hash);

    // let tup = vec![(sec_in[0], a_hash), (sec_out, b_hash)];
    // let (bc_elems, should_validate) = tup_to_scr(sig, tup);

    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(a)}

        // {bc_elems}
    };
    let hint_out = ElemFp12Acc { hash: b_hash, f: b };
    return (hint_out, simulate_stack_input);
}

pub(crate) fn tap_squaring() -> Script {
    let (sq_script, _) = Fq12::hinted_square(ark_bn254::Fq12::ONE);
    let hash_sc = script! {
        { hash_fp12() }
        { Fq::toaltstack() }
        { hash_fp12() }
        //Alt:[hash_out, hash_in, hash_calc_out]
        //Main:[hash_calc_in]
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        //Alt:[]
        //Main:[hash_calc_in, hash_calc_out, hash_in, hash_out]
        { Fq::equalverify(3, 1)}
        { Fq::equal(1, 0)} // 1 if matches, 0 doesn't match
        OP_NOT // 0 if matches, 1 doesn't match
        OP_VERIFY // verify that output doesn't match
    };
    let sc = script! {
        {Fq12::copy(0)}
        {sq_script}
        {hash_sc}
        OP_TRUE
    };
    sc
}


// DENSE DENSE MUL BY CONSTANT

pub(crate) fn tap_dense_dense_mul0_by_constant(g: ark_bn254::Fq12) -> Script {
    let check_is_identity: bool = true;
    let (hinted_mul, _) =
        Fq12::hinted_mul_first(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());
    let ghash = extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);
    let const_hash_limb = extern_nibbles_to_limbs(ghash);
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }

    let hash_scr = script! {
        {hash_fp6()} // c
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} //
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c
        // Alt: [od, d, s], [c0, d, s]
        // Stack: [gc, fc, hc, gk, fk, hk]
        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g

        {Fq::equalverify(1, 4)}
        {Fq::equalverify(1, 3)}
        {Fq::equal(0, 1)} OP_NOT OP_VERIFY
    };

    let ops_scr = script! {
        for l in const_hash_limb {
            {l}
        }
        {Fq::toaltstack()}
        { hinted_mul }

        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            {fq_push_not_montgomery(ark_bn254::Fq::one())}
            for _ in 0..5 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}


pub(crate) fn hints_dense_dense_mul0_by_constant(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;

    let (_, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);

    let hash_f = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    ); // dense
    // let hash_g = emulate_extern_hash_fps(
    //     vec![
    //         g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
    //         g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
    //     ],
    //     false,
    // ); // sparse => constant => bakedin
    let hash_h = extern_hash_fps(
        vec![
            h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
        ],
        true,
    );

    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in mul_hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes
        // in2: SS or c' link
        // in1: SD or DD1 link
        // out
        // { bc_elems }
    };

    (
        ElemFp12Acc {
            f: h,
            hash: hash_h,
        },
        simulate_stack_input,
    )
}

// DENSE DENSE MUL ONE

pub(crate) fn tap_dense_dense_mul1_by_constant(g: ark_bn254::Fq12) -> Script {
    let check_is_identity: bool = true;
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let (hinted_mul, _) =
        Fq12::hinted_mul_second(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let ghash = extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);
    let const_hash_limb = extern_nibbles_to_limbs(ghash);


    let hash_scr = script! {
        {Fq::fromaltstack()} // Hc0
        {hash_fp12_with_hints()} // Hc
        { Fq::toaltstack()}

        {Fq12::roll(12)}
        { hash_fp12()} //
        { Fq::toaltstack()}

        {hash_fp12_192()} // Hash_g
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_c

        { Fq::fromaltstack()} // Hash_c
        { Fq::fromaltstack()} // Hash_f
        { Fq::fromaltstack()} // Hash_g
        // [gc, fc, hc,  gk, fk, hk]
        {Fq::equalverify(1, 4)}
        {Fq::equalverify(1, 3)}
        {Fq::equal(0, 1)} OP_NOT OP_VERIFY
    };

    let ops_scr = script! {
        for l in const_hash_limb {
            {l}
        }
        {Fq::fromaltstack()}
        {Fq::roll(1)}
        {Fq::toaltstack()}
        {Fq::toaltstack()}
        { hinted_mul }
        {check_id} 1 OP_NUMEQUAL
        OP_IF
            {Fq6::copy(0)}
            for _ in 0..6 {
                {fq_push_not_montgomery(ark_bn254::Fq::zero())}
            }
            {Fq6::equalverify()}
        OP_ENDIF
    };
    let scr = script! {
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}

pub(crate) fn hints_dense_dense_mul1_by_constant(
    hint_in_a: ElemFp12Acc,
    hint_in_c0: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script) {
    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let (_, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;

    let hash_f = extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    );

    // let hash_c0 = extern_hash_fps(
    //     vec![
    //         h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
    //     ],
    //     true,
    // );
    let hash_c = extern_hash_fps(
        vec![
            h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1, h.c1.c0.c0,
            h.c1.c0.c1, h.c1.c1.c0, h.c1.c1.c1, h.c1.c2.c0, h.c1.c2.c1,
        ],
        true,
    );

    // data passed to stack in runtime
    let simulate_stack_input = script! {
        // quotients for tmul
        for hint in mul_hints {
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes

        // in3: links to DD0
        // in2: SS or c' link
        // in1: SD or DD1 link
        // out
    };
    (
        ElemFp12Acc {
            f: h,
            hash: hash_c,
        },
        simulate_stack_input,
    )
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
        {hash_fp6()}
        {Fq::toaltstack()}
        {hash_fp12()}
        {Fq::fromaltstack()}
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
        {hash_fp6()}
        {Fq::toaltstack()}
        {hash_fp6()}
        {Fq::fromaltstack()}
        // [Ht0, Ht1]
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        // [Ht0, Ht1, HKt0, Hkt1]
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
        {hash_fp6()}
        {Fq::toaltstack()}
        {hash_fp12()}
        {Fq::fromaltstack()}
        {Fq12::fromaltstack()}
        {hash_fp12_192()}
        // [Hc, Ht, Hd]

        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // // [Hc, Ht, Hd, HKc, HKt, HKd]

        {Fq::equalverify(1, 4)}
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


#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{chunk::primitves::pack_nibbles_to_limbs, execute_script_without_stack_limit};

    use super::*;


     #[test]
    fn test_bn254_fq12_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);

            let a = ark_bn254::Fq12::rand(&mut prng);

            let hash_in = extern_hash_fps(fp12_to_vec(a), true);
            let (hout0, hscr0) = hint_inv0(ElemFp12Acc { f: a, hash: hash_in });
            let tscr0 = tap_inv0();
            let bscr0 = script!{
                for h in hout0.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hash_in {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };
            let script = script! {
                { hscr0 }
                { bscr0 }
                { tscr0 }
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv0 len {} and stack {}", len, res.stats.max_nb_stack_items);


            let (hout1, hscr1) = hint_inv1(hout0);
            let tscr1 = tap_inv1();
            let bscr1 = script!{
                for h in hout1.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout0.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };

            let script = script! {
                { hscr1 }
                { bscr1 }
                { tscr1 }
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv1 len {} and stack {}", len, res.stats.max_nb_stack_items);



            let (hout2, hscr2) = hint_inv2(ElemFp12Acc { f: a, hash: hash_in }, hout1);
            let tscr2 = tap_inv2();
            assert_eq!(hout2.f, a.inverse().unwrap());
            let bscr2 = script!{
                for h in hout2.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout1.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}                
                for h in hash_in {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };

            let script = script! {
                { bscr2 }
                { hscr2 }
                { tscr2 }
            };
            let len = script.len();
            let res = execute_script_without_stack_limit(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv2 len {} and stack {}", len, res.stats.max_nb_stack_items);
    }   
}