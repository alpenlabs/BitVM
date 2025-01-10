use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{
    fq12_push_not_montgomery, fq2_push_not_montgomery, fq_push_not_montgomery, Hint,
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::primitves::{
    extern_hash_nibbles,  extern_nibbles_to_limbs, hash_fp12,
    hash_fp12_with_hints, hash_fp6, 
};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ff::{AdditiveGroup, Field, Zero};
use num_traits::One;

use super::primitves::{extern_hash_fps, hash_fp12_192};
use super::hint_models::*;
use super::taps_point_ops::hash_g2acc_with_hashed_t;

// SPARSE DENSE
pub(crate) fn chunk_sparse_dense_mul(
    hint_in_a: ElemFp12Acc,
    hint_in_g: ElemG2PointAcc,
    dbl_blk: bool,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_sparse_dense_mul(dbl_blk: bool, hinted_script: Script) -> Script {
    
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
            // Altstack: [Hout, Hin_f, Hin_g, HT, Hauxle]
            // Stack [f, cur_le0, cur_le1, f1]
            
            {Fq::fromaltstack()} {Fq::fromaltstack()}  {Fq::fromaltstack()}
            // M: [f, cur_le0, cur_le1, f1, Hauxle, HT, Hin_g]  
            {Fq12::roll(3)} {Fq12::toaltstack()}      
            {Fq12::roll(7)} {Fq12::toaltstack()}      
    
            // A: [Hout, Hin_f, f1, f]
            // M: [cur_le0, cur_le1, Hauxle, HT, Hin_g]  
            {Fq::roll(1)}
            {Fq2::roll(5)} {Fq2::roll(5)}
            // M: [Hauxle, Hin_g, HT, cur_le0, cur_le1 ]  
            {Fq2::roll(5)}
            // M: [HT, cur_le0, cur_le1, Hauxle, Hin_g ]  
            {hash_g2acc_with_hashed_t(dbl_blk)}
            OP_VERIFY
    
            {Fq12::fromaltstack()}
            {hash_fp12()} // Hf
            {Fq12::fromaltstack()} // f1
            {Fq::roll(12)} {Fq::toaltstack()}
            {hash_fp12()} {Fq::fromaltstack()}
    
            // [Hf1, Hf]
            {Fq::fromaltstack()} {Fq::fromaltstack()}
            // [Hf1, Hf, Hin_f, Hout]
            {Fq::equalverify(2, 1)}
            {Fq::equal(1, 0)} OP_NOT OP_VERIFY
        };
        let scr = script! {
            {ops_script}
            {hash_script}
            OP_TRUE
        };
        scr
    }
    
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
    let (hinted_script, hints) = Fq12::hinted_mul_by_34(f, cur_le0, cur_le1);
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

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let hash_dense_input = extern_hash_fps(
        fvec.clone(),
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

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    }
    simulate_stack_input.push(Hint::Fq(cur_le0.c0));
    simulate_stack_input.push(Hint::Fq(cur_le0.c1));
    simulate_stack_input.push(Hint::Fq(cur_le1.c0));
    simulate_stack_input.push(Hint::Fq(cur_le1.c1));
    simulate_stack_input.push(Hint::Hash(hash_other_le_limbs));
    simulate_stack_input.push(Hint::Hash(hash_t_limbs));

    (
        ElemFp12Acc {
            f: f1,
            hash: hash_dense_output,
        },
        tap_sparse_dense_mul(dbl_blk, hinted_script),
        simulate_stack_input,
    )
}

// DENSE DENSE MUL ZERO

fn hash_mul(is_zero: bool) -> Script {
    script!{
        {Fq6::toaltstack()}
        {Fq12::toaltstack()}
        {hash_fp12()}

        {Fq12::fromaltstack()}
        {Fq::roll(12)} {Fq::toaltstack()}
        {hash_fp12_192()} { Fq::fromaltstack() }

        if is_zero {
            {Fq6::fromaltstack()}
            {Fq2::roll(6)} {Fq2::toaltstack()}
            {hash_fp6()} {Fq2::fromaltstack()}
        } else {
            {Fq6::fromaltstack()} 
            {Fq::fromaltstack()} // Hc0
            {Fq2::roll(7)} {Fq2::toaltstack()}
            {hash_fp12_with_hints()} {Fq2::fromaltstack()}
        }

        // [Hc0, Hg, Hf]
        {Fq::fromaltstack()} {Fq::fromaltstack()} {Fq::fromaltstack()}
        // [Hc0, Hg, Hf, Hkg, Hkf, Hkc0]
        {Fq::equalverify(1, 3)}
        {Fq::equalverify(1, 2)}
        {Fq::equal(1, 0)} OP_NOT OP_VERIFY
    }
}

pub(crate) fn chunk_dense_dense_mul0(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_dense_dense_mul0(hinted_mul: Script) -> Script {
        let check_is_identity: bool = false;
        let mut check_id = 1;
        if !check_is_identity {
            check_id = 0;
        }


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
            {hash_mul(true)}
            OP_TRUE
        };
        scr
    }



    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;

    let (hinted_mul_scr, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let hash_f = extern_hash_fps(
        fvec.clone(),
        true,
    ); // dense

    let gvec = vec![
        g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
    ];
    let hash_g = extern_hash_fps(
        gvec.clone(),
        false,
    ); // sparse
    let hash_h = extern_hash_fps(
        vec![
            h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
        ],
        true,
    );

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    }
    for f in &gvec {
        simulate_stack_input.push(Hint::Fq(*f));
    }

    (
        ElemFp12Acc {
            f: h,
            hash: hash_h,
        },
        tap_dense_dense_mul0(hinted_mul_scr),
        simulate_stack_input,
    )
}


// DENSE DENSE MUL ONE

pub(crate) fn chunk_dense_dense_mul1(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
    hint_in_c0: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {


    fn tap_dense_dense_mul1(hinted_mul: Script) -> Script {
        let check_is_identity: bool = false;
        let mut check_id = 1;
        if !check_is_identity {
            check_id = 0;
        }
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
            {hash_mul(false)}
            OP_TRUE
        };
        scr
    }



    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let (hinted_mul_scr, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let hash_f = extern_hash_fps(
        fvec.clone(),
        true,
    );
    let gvec = vec![
        g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
    ];
    let hash_g = extern_hash_fps(
        gvec.clone(),
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


    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    }
    for f in &gvec {
        simulate_stack_input.push(Hint::Fq(*f));
    }

    (
        ElemFp12Acc {
            f: h,
            hash: hash_c,
        },
        tap_dense_dense_mul1(hinted_mul_scr),
        simulate_stack_input,
    )
}


// SQUARING

pub(crate) fn chunk_squaring(
    hint_in_a: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_squaring(sq_script: Script) -> Script {
        let hash_sc = script! {
            {Fq12::toaltstack()}
            { hash_fp12() }
            {Fq12::fromaltstack()}
            {Fq::roll(12)} {Fq::toaltstack()}
            { hash_fp12() } 
            //Alt:[hash_out, hash_in, hash_calc_out]
            //Main:[hash_calc_in]
            { Fq::fromaltstack() }
            {Fq::roll(1)}
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

    let a = hint_in_a.f;
    let (sq_script, hints) = Fq12::hinted_square(a);
    let b = a.square();
    let avec = vec![
        a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0,
        a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1,
    ];
    let a_hash = extern_hash_fps(
        avec.clone(),
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

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints);
    for f in &avec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 

    let hint_out = ElemFp12Acc { hash: b_hash, f: b };
    return (hint_out, tap_squaring(sq_script), simulate_stack_input);
}




// DENSE DENSE MUL BY CONSTANT

pub(crate) fn chunk_dense_dense_mul0_by_constant(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_dense_dense_mul0_by_constant(g: ark_bn254::Fq12, hinted_mul: Script) -> Script {
        let check_is_identity: bool = true;
        let ghash = extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);
        let const_hash_limb = extern_nibbles_to_limbs(ghash);
        let mut check_id = 1;
        if !check_is_identity {
            check_id = 0;
        }

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
            {hash_mul(true)}
            OP_TRUE
        };
        scr
    }

    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;

    let (hint_mul_scr, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let gvec = vec![
        g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
    ];
    let hash_f = extern_hash_fps(
        fvec.clone(),
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

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 
    for f in &gvec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 

    (
        ElemFp12Acc {
            f: h,
            hash: hash_h,
        },
        tap_dense_dense_mul0_by_constant(g, hint_mul_scr),
        simulate_stack_input,
    )
}

// DENSE DENSE MUL ONE
pub(crate) fn chunk_dense_dense_mul1_by_constant(
    hint_in_a: ElemFp12Acc,
    hint_in_c0: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {


    fn tap_dense_dense_mul1_by_constant(g: ark_bn254::Fq12, hinted_mul: Script) -> Script {
        let check_is_identity: bool = true;
        let mut check_id = 1;
        if !check_is_identity {
            check_id = 0;
        }
    
        let ghash = extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);
        let const_hash_limb = extern_nibbles_to_limbs(ghash);


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
            {hash_mul(false)}
            OP_TRUE
        };
        scr
    }



    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let (hinted_mul_scr, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let hash_f = extern_hash_fps(
        fvec.clone(),
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
    let gvec = vec![
        g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
    ];

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 
    for f in &gvec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 

    (
        ElemFp12Acc {
            f: h,
            hash: hash_c,
        },
        tap_dense_dense_mul1_by_constant(g, hinted_mul_scr),
        simulate_stack_input,
    )
}

// FROB Fq12
pub(crate) fn chunk_frob_fp12(
    hint_in_f: ElemFp12Acc,
    power: usize,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_frob_fp12(power: usize, hinted_frobenius_map: Script) -> Script {

        let ops_scr = script! {
            // [f]
            {Fq12::copy(0)}
            // [f, f]
            {hinted_frobenius_map}
            // [f, g]
        };
        let hash_scr = script! {
            {Fq12::toaltstack()}
            { hash_fp12_192() }
            {Fq12::fromaltstack()}
            { Fq::roll(12) } {Fq::toaltstack()}
            { hash_fp12_192() }
            {Fq::fromaltstack()}

            {Fq::fromaltstack()} {Fq::fromaltstack()}

            {Fq::equalverify(1, 2)}
            {Fq::equal(1, 0)} OP_NOT OP_VERIFY
        };
        let sc = script! {
            {ops_scr}
        {hash_scr}
            OP_TRUE
        };
        sc
    }

    let f = hint_in_f.f;
    let (hinted_frob_scr, hints_frobenius_map) = Fq12::hinted_frobenius_map(power, f);

    let g = f.frobenius_map(power);

    let fvec = vec![
        f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
        f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    ];
    let fhash = extern_hash_fps(
        fvec.clone(),
        false,
    );
    let ghash = extern_hash_fps(
        vec![
            g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
        ],
        false,
    );


    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints_frobenius_map);
    for f in &fvec {
        simulate_stack_input.push(Hint::Fq(*f));
    } 
    (ElemFp12Acc { f: g, hash: ghash }, tap_frob_fp12(power, hinted_frob_scr), simulate_stack_input)
}
