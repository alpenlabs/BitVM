use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{
    fq_push_not_montgomery, Hint,
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::primitves::{
    extern_hash_nibbles,  extern_nibbles_to_limbs, hash_fp12,
    hash_fp12_with_hints, hash_fp6, new_hash_g2acc_with_hashed_t, 
};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ff::{AdditiveGroup, Field};
use num_traits::One;

use super::primitves::{extern_hash_fps};
use super::element::*;

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
            // [T, f] [Hg, Hf, Ht], T=[le, Hauxt, Hauxle]
            {Fq12::copy(0)}
            // [[le0, le1, Hauxt, Hauxle], f, f]
            {Fq2::copy(28)}
            {Fq2::copy(28)}
            // [[le0, le1, Hauxt, Hauxle], f, f, le0, le1]
            { hinted_script }
            // Stack [T, f, g]
        };
    
        let hash_script = script! {
            // Altstack: [Hg, Hf, HT]
            // Stack [T, f, g]
            if dbl_blk {
                {hash_messages(vec![ElementType::G2DblEvalMul, ElementType::Fp12v0, ElementType::Fp12v0])}
            } else {
                {hash_messages(vec![ElementType::G2AddEvalMul, ElementType::Fp12v0, ElementType::Fp12v0])}
            }

        };
        let scr = script! {
            {ops_script}
            {hash_script}
            OP_TRUE
        };
        scr
    }
    
    let cur_le = if dbl_blk {
        hint_in_g.dbl_le.unwrap()
    } else {
        hint_in_g.add_le.unwrap()
    };
    
    let (f, cur_le0, cur_le1) = (hint_in_a.f, cur_le.0, cur_le.1);
    let (hinted_script, hints) = Fq12::hinted_mul_by_34(f, cur_le0, cur_le1);
    let mut f1 = f;
    f1.mul_by_034(&ark_bn254::Fq2::ONE, &cur_le0, &cur_le1);

    let hash_dense_output = extern_hash_fps(
        f1.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        true,
    );
    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints);

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
pub(crate) fn chunk_dense_dense_mul0(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
) -> (ElemFp6, Script, Vec<Hint>) {

    fn tap_dense_dense_mul0(hinted_mul: Script) -> Script {
        let ops_scr = script! {
            { hinted_mul }
        };
        let scr = script! {
            {ops_scr}
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v1, ElementType::Fp6])} //{hash_mul(true)}
            OP_TRUE
        };
        scr
    }


    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;

    let (hinted_mul_scr, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);

    let fvec: Vec<ark_bn254::Fq> = f.to_base_prime_field_elements().collect();
    let hash_f = extern_hash_fps(
        fvec.clone(),
        true,
    ); // dense

    let gvec: Vec<ark_bn254::Fq> = g.to_base_prime_field_elements().collect();
    let hash_g = extern_hash_fps(
        gvec.clone(),
        false,
    ); // sparse

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);

    (
        h.c0,
        tap_dense_dense_mul0(hinted_mul_scr),
        simulate_stack_input,
    )
}


// DENSE DENSE MUL ONE

pub(crate) fn chunk_dense_dense_mul1(
    hint_in_a: ElemFp12Acc,
    hint_in_b: ElemFp12Acc,
    hint_in_c0: ElemFp6,
) -> (ElemFp12Acc, Script, Vec<Hint>) {


    fn tap_dense_dense_mul1(hinted_mul: Script) -> Script {

        let ops_scr = script! {
            {Fq::copy(0)}
            // [f, g, hc0, hc1_aux]
            { Fq2::toaltstack() }
            { hinted_mul }
            { Fq2::fromaltstack() }
            // [f, g, c1, hc0, hc1_aux]
            { Fq6::roll(2)}
            { Fq::roll(6) }
            // [f, g, hc0, c1, hc1_aux]
            // [Fp12v0, Fp12v1, HashBytes, Fp12v2]
        };
        let scr = script! {
            {ops_scr}
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v1, ElementType::HashBytes, ElementType::Fp12v2])} 
            OP_TRUE
        };
        scr
    }



    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let (hinted_mul_scr, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;

    let fvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
    let hash_f = extern_hash_fps(
        fvec.clone(),
        true,
    );
    let gvec = g.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
    let hash_g = extern_hash_fps(
        gvec.clone(),
        false,
    );

    let hash_c0 = extern_hash_fps(
        h.c0.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        true,
    );
    let hash_c = extern_hash_fps(
        h.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        true,
    );


    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&mul_hints);

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
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v0])} 
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
    let avec = a.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
    let a_hash = extern_hash_fps(
        avec.clone(),
        true,
    );
    let b_hash = extern_hash_fps(
        b.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        true,
    );
   //assert_eq!(hint_in.ahash, a_hash);

    // let tup = vec![(sec_in[0], a_hash), (sec_out, b_hash)];
    // let (bc_elems, should_validate) = tup_to_scr(sig, tup);

    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints);
    // for f in &avec {
    //     simulate_stack_input.push(Hint::Fq(*f));
    // } 

    let hint_out = ElemFp12Acc { hash: b_hash, f: b };
    return (hint_out, tap_squaring(sq_script), simulate_stack_input);
}




// DENSE DENSE MUL BY CONSTANT

pub(crate) fn chunk_final_verify(
    hint_in_a: ElemFp12Acc, // 
    hint_in_b: ElemFp12Acc,
) -> (ElemFp12Acc, Script, Vec<Hint>) {

    fn tap_final_verify(g: ark_bn254::Fq12) -> Script {
        let ginv = g.inverse().unwrap();
        let ginv_hash = extern_hash_fps(ginv.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(), true);
        let const_hash_limb = extern_nibbles_to_limbs(ginv_hash);

        let ops_scr = script! {
            // [f] [fhash]
            {hash_fp12()}
            {Fq::copy(0)}
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}
            for l in const_hash_limb {
                {l}
            }
            // [hashf, ginv]
            {Fq::equal(1, 0)}
            OP_NOT OP_VERIFY
        };
        let scr = script! {
            {ops_scr}
            OP_TRUE
        };
        scr
    }

    let (f, g) = (hint_in_a.f, hint_in_b.f);
    let h = f * g;
    let hash_h = extern_hash_fps(h.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(), true);
    (
        ElemFp12Acc {
            f: h,
            hash: hash_h,
        },
        tap_final_verify(g),
        vec![],
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
            {hash_messages(vec![ElementType::Fp12v1, ElementType::Fp12v1])}
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

    let fvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
    let fhash = extern_hash_fps(
        fvec.clone(),
        false,
    );
    let ghash = extern_hash_fps(
        g.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        false,
    );


    let mut simulate_stack_input = vec![];
    simulate_stack_input.extend_from_slice(&hints_frobenius_map);
    // for f in &fvec {
    //     simulate_stack_input.push(Hint::Fq(*f));
    // } 
    (ElemFp12Acc { f: g, hash: ghash }, tap_frob_fp12(power, hinted_frob_scr), simulate_stack_input)
}
