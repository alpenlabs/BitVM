use crate::bn254::chunk_primitves::{emulate_extern_hash_nibbles, emulate_fq_to_nibbles, emulate_nibbles_to_limbs, hash_fp12, hash_fp12_with_hints, hash_fp2, hash_fp4, hash_fp6, pack_nibbles_to_limbs, read_script_from_file, unpack_limbs_to_nibbles};
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{ fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine, new_hinted_x_from_eval_point, new_hinted_y_from_eval_point};
use crate::signatures::winternitz_compact::{self, checksig_verify_fq};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::ops::Neg;
use std::str::FromStr;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use num_traits::One;

use super::chunk_primitves::{emulate_extern_hash_fps, hash_fp12_192};
use super::utils::{fq12_push_not_montgomery, Hint};

pub(crate) type HashBytes = [u8;64];

pub(crate) struct HintInSquaring {
    a: ark_bn254::Fq12,
    ahash: HashBytes,
}

impl HintInSquaring {
    pub(crate) fn from_grothc(g: HintOutGrothC) -> Self {
        HintInSquaring { a: g.c, ahash: g.chash }
    }
    pub(crate) fn from_dmul1(g: HintOutDenseMul1) -> Self {
        HintInSquaring { a: g.c, ahash: g.hash_out }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutSquaring {
    b: ark_bn254::Fq12,
    bhash: HashBytes,
}

#[derive(Debug, Clone)]
pub(crate) enum HintOut {
    Squaring(HintOutSquaring),
    Double(HintOutDouble),
    DblAdd(HintOutDblAdd),
    SparseDbl(HintOutSparseDbl),
    SparseAdd(HintOutSparseAdd),
    SparseDenseMul(HintOutSparseDenseMul),
    DenseMul0(HintOutDenseMul0),
    DenseMul1(HintOutDenseMul1),

    PubIdentity(HintOutPubIdentity),
    FixedAcc(HintOutFixedAcc),

    FieldElem(ark_bn254::Fq),
    GrothC(HintOutGrothC), // c, s, cinv

    HashC(HintOutHashC),
    InitT4(HintOutInitT4),

    FrobFp12(HintOutFrobFp12),
    Add(HintOutAdd),
}

// SQUARING
pub(crate) fn hints_squaring(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInSquaring)-> (HintOutSquaring, Script) {
    assert_eq!(sec_in.len(), 1);
    let a = hint_in.a;
    let (_, hints) = Fq12::hinted_square(a);
    let b = a.square();
    let a_hash = emulate_extern_hash_fps(vec![a.c0.c0.c0,a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0,a.c0.c2.c1, a.c1.c0.c0,a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0,a.c1.c2.c1], true);
    let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], true);
    assert_eq!(hint_in.ahash, a_hash);

    // data passed to stack in runtime 
    let simulate_stack_input = script!{
        // quotients for tmul
        for hint in hints { 
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(a)}
        // aux_a
        {fq12_push_not_montgomery(a)}
        // hash_a
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), b_hash)}
        // hash_b
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), a_hash)}
    };
    let hint_out = HintOutSquaring {
        bhash: b_hash,
        b,
    };
    return (hint_out, simulate_stack_input);
    
}

pub(crate) fn tap_squaring(sec_key: &str, sec_out: u32, sec_in: Vec<u32>)-> Script {
    assert_eq!(sec_in.len(), 1);
    let (sq_script, _) = Fq12::hinted_square(ark_bn254::Fq12::ONE);
    let bitcomms_sc = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
    };
    let hash_sc  = script!{
        { hash_fp12() } // Hash(b)
        { Fq::fromaltstack() } // hash_b
        { Fq::equalverify(1, 0)} // NOTE: WE SHOULD BE SHOWING INEQUALITY, WILL DO LATER
        { hash_fp12() } // Hash(a)
        { Fq::fromaltstack() } // hash_a
        { Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_sc}
        {sq_script}
        {hash_sc}
        OP_TRUE
    };
    sc
}


// POINT DBL
pub(crate) fn tap_point_dbl(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    
    assert_eq!(sec_in.len(), 3);
    let (hinted_double_line, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_tangent, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let ops_script = script! {
        // { fq2_push_not_montgomery(alpha_tangent)}
        // { fq2_push_not_montgomery(bias_minus_tangent)}
        // { fq2_push_not_montgomery(t.x) }
        // { fq2_push_not_montgomery(t.y) }
        // { fq_push_not_montgomery(aux_hash) } 

        // {hash_aux}

        // { fq_push_not_montgomery(p_dash_x) }
        // { fq_push_not_montgomery(p_dash_y) }

        // { hash_in } // hash
        // { hash_out_claim } // hash
       
        // move aux hash to MOVE_AUX_HASH_HERE
        {Fq::toaltstack()} // hash out
        {Fq::toaltstack()} // hash in
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

    let hash_script = script!{
        //Altstack: [hash_out, hash_in, hash_inaux]
        //Stack: [tx, ty, Rx, Ry, le0, le1]
        //T
        {Fq2::roll(10)}
        {Fq2::roll(10)}

        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        //{pack_nibbles_to_limbs()}
        //[T, R, le]

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}

        // // [HashOut]
        // // [Rx, Ry, le0, le1]

        {Fq2::roll(6)}
        {Fq2::roll(6)}
        // // [HashOut]
        // // [le, R]
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // // [HashOut, HashR]
        // // [le]
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        // // [HashOut, HashR]
        // // [Hashle]
        for _ in 0..64 {
            {0}
        }
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        // // [HashOut]
        // // [Hashle, HashR]
        {unpack_limbs_to_nibbles()}
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
    };

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // pdash_x

        {Fq::fromaltstack()} // py
        {Fq::fromaltstack()} // in
        {Fq::fromaltstack()} // out
        // [x, y, in, out]
    };


    let sc = script!{
        {bitcomms_script.clone()}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

pub(crate) struct HintInDouble {
    t: ark_bn254::G2Affine,
    p:ark_bn254::G1Affine,
    hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

impl HintInDouble {
    pub(crate) fn from_initT4(it: HintOutInitT4, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        HintInDouble {t: it.t4, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: it.hash_le_aux}
    }
    pub(crate) fn from_double(g: HintOutDouble, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInDouble {t: g.t, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: hash_le}
    }

    pub(crate) fn from_doubleadd(g: HintOutDblAdd, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInDouble {t: g.t, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: hash_le}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDouble {
    t: ark_bn254::G2Affine,
    dbl_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    hash_add_le_aux: HashBytes,
    hash_out: HashBytes,
}

pub(crate) fn hint_point_dbl(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInDouble) -> (HintOutDouble, Script) {
    assert_eq!(sec_in.len(), 3);
    let t = hint_in.t;
    let p = hint_in.p;

    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
    let mut alpha_tangent = t.x.square();
    alpha_tangent /= t.y;
    alpha_tangent.mul_assign_by_fp(&three_div_two);
    // -bias
    let bias_minus_tangent = alpha_tangent * t.x - t.y;

    let new_tx = alpha_tangent.square() - t.x.double();
    let new_ty = bias_minus_tangent - alpha_tangent * new_tx;
    let (_, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();


    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&(-p.x / p.y));

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);

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

    let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
    let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());

    let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
    let hash_add_le = [0u8; 64]; // constant
    let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
    let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

    let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true); 
    let aux_hash_le = emulate_nibbles_to_limbs(hint_in.hash_le_aux); // mock     
    let hash_input = emulate_extern_hash_nibbles(vec![hash_t, hint_in.hash_le_aux]);  

    let simulate_stack_input = script!{
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
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), pdash_x)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), pdash_y)}
        // bit commits hashes
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_input)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_root_claim)}
    };
    let hint_out: HintOutDouble = HintOutDouble {
        t: G2Affine::new_unchecked(new_tx, new_ty),
        dbl_le: (dbl_le0, dbl_le1),
        hash_add_le_aux: hash_add_le,
        hash_out: hash_root_claim,
    };
    (hint_out, simulate_stack_input)
}

// POINT ADD
pub(crate) struct HintInAdd {
    t: ark_bn254::G2Affine,
    p:ark_bn254::G1Affine,
    q:ark_bn254::G2Affine,
    hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

impl HintInAdd {
    pub(crate) fn from_double(g: HintOutDouble, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq, q: ark_bn254::G2Affine) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInAdd {t: g.t, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: hash_le, q}
    }

    pub(crate) fn from_add(g: HintOutAdd, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq, q: ark_bn254::G2Affine) -> Self {
        let (add_le0, add_le1) = g.add_le;
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le0.c0, add_le0.c1], true);
        let hash_dbl_le = g.hash_dbl_le_aux;
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInAdd {t: g.t, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: hash_le, q}
    }

    pub(crate) fn from_doubleadd(g: HintOutDblAdd, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq, q: ark_bn254::G2Affine) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInAdd {t: g.t, p: G1Affine::new_unchecked(gpx, gpy), hash_le_aux: hash_le, q}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutAdd {
    t: ark_bn254::G2Affine,
    add_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    hash_dbl_le_aux: HashBytes,
    hash_out: HashBytes,
}

pub(crate) fn tap_point_add(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, ate: i8) -> Script {
    assert!(ate == 1 || ate == -1);
    assert_eq!(sec_in.len(), 7);
    let mut ate_unsigned_bit = 1;  // Q1 = pi(Q), T = T + Q1 // frob
    if ate == -1 { // Q2 = pi^2(Q), T = T - Q2 // frob_sq and negate
        ate_unsigned_bit = 0;
    }

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, _) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

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

    let hash_script = script!{
        //Altstack: [hash_out, hash_in, hash_inaux]
        //Stack: [tx, ty, Rx, Ry, le0, le1]
        //T
        {Fq2::roll(10)}
        {Fq2::roll(10)}

        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        //{pack_nibbles_to_limbs()}
        //[T, R, le]

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}

        // // [HashOut]
        // // [Rx, Ry, le0, le1]

        {Fq2::roll(6)}
        {Fq2::roll(6)}
        // [HashOut]
        // [le, R]
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // // // [HashOut, HashR]
        // // // [le]
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        // // [HashOut, HashR]
        // // [Hashle]
        for _ in 0..64 {
            {0}
        }
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        {Fq::fromaltstack()}
        // // [HashOut]
        // // [Hashle, HashR]
        {unpack_limbs_to_nibbles()}
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
    };

    let beta_12x = BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap();
    let beta_12y = BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap();
    let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_12x.clone()), ark_bn254::Fq::from(beta_12y.clone())]).unwrap();
    let beta_13x = BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap();
    let beta_13y = BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap();
    let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_13x.clone()), ark_bn254::Fq::from(beta_13y.clone())]).unwrap();

    let (beta12_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_12);
    let (beta13_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_13);
    
    let beta_22x = BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_22x.clone()), ark_bn254::Fq::from(beta_22y.clone())]).unwrap();

    let (beta22_mul, _) = Fq2::hinted_mul(2, ark_bn254::Fq2::one(), 0, beta_22);

    let precompute_script = script!{
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
            {Fq::neg(0)}
            {Fq2::toaltstack()}
            {fq2_push_not_montgomery(beta_22)} // beta_22
            {beta22_mul}
            {Fq2::fromaltstack()}
        OP_ENDIF

        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // Output: [px, py, qx0', qx1', qy0', qy1', in, out]
    };

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_root_claim
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // qdash_y1
        {Fq::toaltstack()}
        //{ate_mul_y_toaltstack.clone()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // qdash_y0
        {Fq::toaltstack()}
        //{ate_mul_y_toaltstack}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // qdash_x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} // qdash_x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} // pdash_x

        // bring back from altstack
        for _ in 0..7 {
            {Fq::fromaltstack()}
        }
        // [px, py, qx0, qx1, qy0, qy1, in, out]
    };


    let sc = script!{
        {bitcomms_script}
        {precompute_script}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

pub(crate) fn hint_point_add(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInAdd, ate: i8) -> (HintOutAdd, Script) {

    assert_eq!(sec_in.len(), 7);
    let (tt, p, q) = (hint_in.t, hint_in.p, hint_in.q);
    let mut qq = q.clone();
    // if ate == -1 {
    //     qq = q.neg();
    // }
    let mut frob_hint: Vec<Hint> = vec![];
    if ate == 1 {
        let beta_12x = BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap();
        let beta_12y = BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap();
        let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_12x.clone()), ark_bn254::Fq::from(beta_12y.clone())]).unwrap();
        let beta_13x = BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap();
        let beta_13y = BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap();
        let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_13x.clone()), ark_bn254::Fq::from(beta_13y.clone())]).unwrap();
    
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
        let beta_22x = BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap();
        let beta_22y = BigUint::from_str("0").unwrap();
        let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([ark_bn254::Fq::from(beta_22x.clone()), ark_bn254::Fq::from(beta_22y.clone())]).unwrap();
    
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
    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();

    let (_, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) = new_hinted_check_line_through_point( qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&(-p.x / p.y));

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);


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

    let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
    let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());
    let qdash_x0 = emulate_fq_to_nibbles(q.x.c0);
    let qdash_x1 = emulate_fq_to_nibbles(q.x.c1);
    let qdash_y0 = emulate_fq_to_nibbles(q.y.c0);
    let qdash_y1 = emulate_fq_to_nibbles(q.y.c1);

    let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le = [0u8; 64];
    let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
    let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
    let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

    let hash_t = emulate_extern_hash_fps(vec![tt.x.c0, tt.x.c1, tt.y.c0, tt.y.c1], true); 
    let aux_hash_le = emulate_nibbles_to_limbs(hint_in.hash_le_aux); // mock     
    let hash_input = emulate_extern_hash_nibbles(vec![hash_t, hint_in.hash_le_aux]);  

    let simulate_stack_input = script!{
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
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[6]), pdash_x)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[5]), pdash_y)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[4]), qdash_x0)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[3]), qdash_x1)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), qdash_y0)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), qdash_y1)}

        // bit commits hashes
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_input)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_root_claim)}
    };
    let hint_out = HintOutAdd {
        t: G2Affine::new_unchecked(new_tx, new_ty),
        add_le: (add_le0, add_le1),
        hash_dbl_le_aux: hash_dbl_le,
        hash_out: hash_root_claim,
    };
    (hint_out, simulate_stack_input)
}


// POINT DBL AND ADD
pub(crate) fn tap_point_ops(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, ate: i8) -> Script {
    assert!(ate == 1 || ate == -1);
    assert_eq!(sec_in.len(), 7);
    let mut ate_unsigned_bit = 1;
    if ate == -1 {
        ate_unsigned_bit = 0;
    }
    let (hinted_double_line, _) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_tangent, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_check_chord_t, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, _) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, _) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_tangent, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_ell_chord, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let bcsize = 6+3;
    let ops_script = script! {
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


    let hash_script = script!{

        //T
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 
        { Fq::toaltstack() } 

        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}

        { Fq::fromaltstack()} // inaux
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::fromaltstack()} //input_hash
        {Fq::equalverify(1, 0)}


        // Altstack: [dbl_le, R, add_le, hash_out]
        // Stack: [t]
        for i in 0..13 {
            {Fq::fromaltstack()}
        }

        // Altstack: []
        // Stack: [hash_out, add_le, R, dbl_le]

        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}
 
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_limbs_to_nibbles()} // 0
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_128b_168k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::toaltstack()}

        // Altstack: [HD, HR, HA]
        // Stack: [hash_out]
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        // Altstack: []
        // Stack: [hash_out, HA, HR, HD]
        {Fq::roll(2)}
        // Stack: [hash_out, HR, HD, HA]
        {Fq::toaltstack()}
        {unpack_limbs_to_nibbles()}
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        // Altstack: []
        // Stack: [hash_out, HR, Hle]
        {Fq::toaltstack()}
        {unpack_limbs_to_nibbles()}
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}
        {Fq::equalverify(1, 0)}
    };

    let ate_mul_y_toaltstack = script!{
        {ate_unsigned_bit}
        1 OP_NUMEQUAL
        OP_IF
            {Fq::toaltstack()}
        OP_ELSE // -1
            {Fq::neg(0)}
            {Fq::toaltstack()}
        OP_ENDIF
    };
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_root_claim
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // qdash_y1
        {ate_mul_y_toaltstack.clone()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // qdash_y0
        {ate_mul_y_toaltstack}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // qdash_x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} // qdash_x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} // pdash_y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} // pdash_x

        // bring back from altstack
        for _ in 0..7 {
            {Fq::fromaltstack()}
        }
    };



    let sc = script!{
        {bitcomms_script.clone()}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

pub(crate) struct HintInDblAdd {
    t: ark_bn254::G2Affine,
    p:ark_bn254::G1Affine,
    q:ark_bn254::G2Affine,
    hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDblAdd {
    t: ark_bn254::G2Affine,
    dbl_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    add_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    hash_out: HashBytes,
}

impl HintInDblAdd {
    pub(crate) fn from_initT4(it: HintOutInitT4, gp: ark_bn254::G1Affine, gq: ark_bn254::G2Affine) -> Self {
        HintInDblAdd {t: it.t4, p: gp, hash_le_aux: it.hash_le_aux, q: gq}
    }
    pub(crate) fn from_double(g: HintOutDouble, gp: ark_bn254::G1Affine, gq: ark_bn254::G2Affine) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInDblAdd {t: g.t, p: gp, hash_le_aux: hash_le, q: gq}
    }

    pub(crate) fn from_doubleadd(g: HintOutDblAdd, gp: ark_bn254::G1Affine, gq: ark_bn254::G2Affine) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
        HintInDblAdd {t: g.t, p: gp, hash_le_aux: hash_le, q: gq}
    }
}

pub(crate) fn hint_point_ops(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInDblAdd, ate: i8) -> (HintOutDblAdd, Script) {
    assert_eq!(sec_in.len(), 7);
    let (t, p, q) = (hint_in.t, hint_in.p, hint_in.q);

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

    let tx = alpha_tangent.square() - t.x.double();
    let ty = bias_minus_tangent - alpha_tangent * tx;
    let (_, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
    let (_, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

    let tt = G2Affine::new_unchecked(tx, ty);

    let alpha_chord = (tt.y - qq.y) / (tt.x - qq.x);
    // -bias
    let bias_minus_chord = alpha_chord * tt.x - tt.y;
    assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

    let new_tx = alpha_chord.square() - tt.x - qq.x;
    let new_ty = bias_minus_chord - alpha_chord * new_tx;
    let p_dash_x = -p.x/p.y;
    let p_dash_y = p.y.inverse().unwrap();

    let (_, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) = new_hinted_check_line_through_point( qq.x, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = new_hinted_affine_add_line(tt.x, qq.x, alpha_chord, bias_minus_chord);

    // affine mode as well
    let mut dbl_le0 = alpha_tangent;
    dbl_le0.mul_assign_by_fp(&(-p.x / p.y));

    let mut dbl_le1 = bias_minus_tangent;
    dbl_le1.mul_assign_by_fp(&(p.y.inverse().unwrap()));

    let mut add_le0 = alpha_chord;
    add_le0.mul_assign_by_fp(&(-p.x / p.y));

    let mut add_le1 = bias_minus_chord;
    add_le1.mul_assign_by_fp(&(p.y.inverse().unwrap()));


    let (_, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
    let (_, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

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

    let pdash_x = emulate_fq_to_nibbles(-p.x/p.y);
    let pdash_y = emulate_fq_to_nibbles(p.y.inverse().unwrap());
    let qdash_x0 = emulate_fq_to_nibbles(q.x.c0);
    let qdash_x1 = emulate_fq_to_nibbles(q.x.c1);
    let qdash_y0 = emulate_fq_to_nibbles(q.y.c0);
    let qdash_y1 = emulate_fq_to_nibbles(q.y.c1);

    let hash_new_t = emulate_extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true);
    let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
    let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
    let hash_le = emulate_extern_hash_nibbles(vec![hash_dbl_le, hash_add_le]);
    let hash_root_claim = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

    let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true); 
    let aux_hash_le = emulate_nibbles_to_limbs(hint_in.hash_le_aux);      
    let hash_input = emulate_extern_hash_nibbles(vec![hash_t, hint_in.hash_le_aux]);  

    let simulate_stack_input = script!{
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

        // bit commits raw
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[6]), pdash_x)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[5]), pdash_y)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[4]), qdash_x0)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[3]), qdash_x1)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), qdash_y0)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), qdash_y1)}

        // bit commits hashes
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_input)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_root_claim)}
    };

    let hint_out = HintOutDblAdd {
        t: G2Affine::new_unchecked(tx, ty),
        add_le: (add_le0, add_le1),
        dbl_le: (dbl_le0, dbl_le1),
        hash_out: hash_root_claim,
    };

    (hint_out, simulate_stack_input)
}

// DOUBLE EVAL
pub(crate) struct HintInSparseDbl {
    t2: ark_bn254::G2Affine,
    t3: G2Affine, 
    p2: G1Affine, 
    p3: G1Affine
}

impl HintInSparseDbl {
    pub(crate) fn from_groth_and_aux(p2: ark_bn254::G1Affine, p3: ark_bn254::G1Affine, aux_t2: ark_bn254::G2Affine, aux_t3: ark_bn254::G2Affine) -> Self {
        Self { t2: aux_t2, t3: aux_t3, p2, p3 }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutSparseDbl {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine, 
    f: ark_bn254::Fq12,
}
pub(crate) fn hint_double_eval_mul_for_fixed_Qs(sec_key: &str,sec_out: u32, sec_in: Vec<u32>, hint_in: HintInSparseDbl) -> (HintOutSparseDbl, Script) {
   assert_eq!(sec_in.len(), 4);
   let (t2, t3, p2, p3) = (hint_in.t2, hint_in.t3, hint_in.p2, hint_in.p3);
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

    let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], false);
    let p2dash_x = emulate_fq_to_nibbles(p2.x);
    let p2dash_y = emulate_fq_to_nibbles(p2.y);
    let p3dash_x = emulate_fq_to_nibbles(p3.x);
    let p3dash_y = emulate_fq_to_nibbles(p3.y);

    let simulate_stack_input = script!{
        for hint in hints { 
            { hint.push() }
        }
        // bit commits
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), b_hash)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[3]), p2dash_x)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), p2dash_y)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), p3dash_x)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), p3dash_y)}
    };

    let hint_out = HintOutSparseDbl {
        t2: G2Affine::new_unchecked(x2, y2),
        t3:  G2Affine::new_unchecked(x3, y3),
        f: b,
    };
    
    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_double_eval_mul_for_fixed_Qs(sec_key: &str,sec_out: u32, sec_in: Vec<u32>, t2: G2Affine, t3: G2Affine) -> (Script,G2Affine,G2Affine) {
    assert_eq!(sec_in.len(), 4);
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

    let (hinted_ell_t2,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_ell_t3,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_sparse_dense_mul,_) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let ops_scr = script!{
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

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // P3y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // P3x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // P2y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // P2x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // bhash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack: [bhash, P2x, P2y, P3x, P3y]
    };
    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_script} 
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    (sc, G2Affine::new_unchecked(x2, y2), G2Affine::new_unchecked(x3, y3))
}

// ADD EVAL
pub(crate) struct HintInSparseAdd {
    t2: ark_bn254::G2Affine,
    t3: G2Affine, 
    p2: G1Affine, 
    p3: G1Affine,
    q2: ark_bn254::G2Affine,
    q3: G2Affine, 
}

impl HintInSparseAdd {
    pub(crate) fn from_groth_and_aux(p2: ark_bn254::G1Affine, p3: ark_bn254::G1Affine, pub_q2: ark_bn254::G2Affine, pub_q3: ark_bn254::G2Affine, aux_t2: ark_bn254::G2Affine, aux_t3: ark_bn254::G2Affine) -> Self {
        Self { t2: aux_t2, t3: aux_t3, p2, p3, q2: pub_q2, q3: pub_q3 }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct HintOutSparseAdd {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine, 
    f: ark_bn254::Fq12,
}

pub(crate) fn hint_add_eval_mul_for_fixed_Qs(sec_key: &str,sec_out: u32, sec_in: Vec<u32>, hint_in: HintInSparseAdd) -> (HintOutSparseAdd, Script) {
    let (t2, t3, p2, p3, q2, q3) = (hint_in.t2, hint_in.t3, hint_in.p2, hint_in.p3, hint_in.q2, hint_in.q3);
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

    let b_hash = emulate_extern_hash_fps(vec![b.c0.c0.c0,b.c0.c0.c1, b.c0.c1.c0, b.c0.c1.c1, b.c0.c2.c0,b.c0.c2.c1, b.c1.c0.c0,b.c1.c0.c1, b.c1.c1.c0, b.c1.c1.c1, b.c1.c2.c0,b.c1.c2.c1], false);
    let p2dash_x = emulate_fq_to_nibbles(p2.x);
    let p2dash_y = emulate_fq_to_nibbles(p2.y);
    let p3dash_x = emulate_fq_to_nibbles(p3.x);
    let p3dash_y = emulate_fq_to_nibbles(p3.y);

    let simulate_stack_input = script!{
        for hint in hints { 
            { hint.push() }
        }
        // bit commits
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), b_hash)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[3]), p2dash_x)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), p2dash_y)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), p3dash_x)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), p3dash_y)}
    };

    let hint_out = HintOutSparseAdd {
        t2: G2Affine::new_unchecked(x2, y2),
        t3:  G2Affine::new_unchecked(x3, y3),
        f: b,
    };
    
    (hint_out, simulate_stack_input)
}

pub(crate) fn tap_add_eval_mul_for_fixed_Qs(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, t2: G2Affine, t3: G2Affine, q2: G2Affine, q3: G2Affine) -> (Script, G2Affine, G2Affine) {
    // First
    let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x);
    let bias_t2 = alpha_t2 * t2.x - t2.y;
    let x2 = alpha_t2.square() - t2.x - q2.x;
    let y2 = bias_t2 - alpha_t2 * x2;
    // Second
    let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x);
    let bias_t3 = alpha_t3 * t3.x - t3.y;
    let x3 = alpha_t3.square() - t3.x - q3.x;
    let y3 = bias_t3 - alpha_t3 * x3;

    let (hinted_ell_t2,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t2, bias_t2);
    let (hinted_ell_t3,_) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), alpha_t3, bias_t3);
    let (hinted_sparse_dense_mul,_) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    
    let ops_scr = script!{
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

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // P3y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // P3x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // P2y
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // P2x
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // bhash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack: [bhash, P2x, P2y, P3x, P3y]
    };
    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcomms_script}
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    (sc, G2Affine::new_unchecked(x2, y2), G2Affine::new_unchecked(x3, y3))
}


// SPARSE DENSE

pub(crate) fn tap_sparse_dense_mul(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, dbl_blk: bool) -> Script {
    assert_eq!(sec_in.len(), 2);
    let (hinted_script, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let mut add = 0;
    if dbl_blk == false {
        add = 1;
    }

    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hash_out
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hash_dense_in
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // hash_sparse_in
        {Fq::toaltstack()}
        // Stack: [...,hash_out, hash_in1, hash_in2]
    };

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
    let hash_script = script!{
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
        {Fq::equalverify(1,0)}
    };
    let scr = script!{
        {bitcomms_script}
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    scr
}

pub(crate) struct HintInSparseDenseMul {
    a: ark_bn254::Fq12,
    le0: ark_bn254::Fq2,
    le1: ark_bn254::Fq2,
    hash_other_le: HashBytes,
    hash_aux_T: HashBytes,
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutSparseDenseMul {
    f: ark_bn254::Fq12,
    hash_out: HashBytes,
}

impl HintInSparseDenseMul {
    pub(crate) fn from_double(g: HintOutDouble, sq: HintOutSquaring) -> Self {
        let t = g.t;
        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        HintInSparseDenseMul { a: sq.b, le0: g.dbl_le.0, le1: g.dbl_le.1, hash_other_le: g.hash_add_le_aux, hash_aux_T: hash_t }
    }

    pub(crate) fn from_double_add_top(g: HintOutDblAdd, sq: HintOutSquaring) -> Self {
        let t = g.t;
        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let (add_le0, add_le1) = g.add_le;
        let hash_add_le = emulate_extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        return HintInSparseDenseMul { a: sq.b, le0: g.dbl_le.0, le1: g.dbl_le.1, hash_other_le: hash_add_le, hash_aux_T: hash_t };
    }

    pub(crate) fn from_doubl_add_bottom(g: HintOutDblAdd, dmul: HintOutDenseMul1) -> Self {
        let t = g.t;
        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        return HintInSparseDenseMul { a: dmul.c, le0: g.add_le.0, le1: g.add_le.1, hash_other_le: hash_dbl_le, hash_aux_T: hash_t };
    }
    pub(crate) fn from_add(g: HintOutAdd, sq: HintOutDenseMul1) -> Self {
        let t = g.t;
        let hash_t = emulate_extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        HintInSparseDenseMul { a: sq.c, le0: g.add_le.0, le1: g.add_le.1, hash_other_le: g.hash_dbl_le_aux, hash_aux_T: hash_t }
    }
}

pub(crate) fn hints_sparse_dense_mul(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInSparseDenseMul, dbl_blk: bool) -> (HintOutSparseDenseMul, Script) {
    assert_eq!(sec_in.len(), 2);
    let (f, dbl_le0, dbl_le1) = (hint_in.a, hint_in.le0, hint_in.le1);
    let (_, hints) = Fq12::hinted_mul_by_34(f, dbl_le0, dbl_le1);
    let mut f1 = f;
    f1.mul_by_034(&ark_bn254::Fq2::ONE, &dbl_le0, &dbl_le1);

    // assumes sparse-dense after doubling block, hashing arrangement changes otherwise
    let hash_new_t = hint_in.hash_aux_T;
    let hash_cur_le = emulate_extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
    let hash_other_le = hint_in.hash_other_le;
    let mut hash_le = emulate_extern_hash_nibbles(vec![hash_cur_le, hash_other_le]);
    if !dbl_blk {
        hash_le = emulate_extern_hash_nibbles(vec![hash_other_le, hash_cur_le]);
    }
    let hash_sparse_input = emulate_extern_hash_nibbles(vec![hash_new_t, hash_le]);

    let hash_dense_input = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
    let hash_dense_output = emulate_extern_hash_fps(vec![f1.c0.c0.c0,f1.c0.c0.c1, f1.c0.c1.c0, f1.c0.c1.c1, f1.c0.c2.c0,f1.c0.c2.c1, f1.c1.c0.c0,f1.c1.c0.c1, f1.c1.c1.c0, f1.c1.c1.c1, f1.c1.c2.c0,f1.c1.c2.c1], true);
    let hash_other_le_limbs = emulate_nibbles_to_limbs(hash_other_le);
    let hash_t_limbs = emulate_nibbles_to_limbs(hash_new_t);

    // data passed to stack in runtime 
    let simulate_stack_input = script!{
        // quotients for tmul
        for hint in hints { 
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq2_push_not_montgomery(dbl_le0)}
        {fq2_push_not_montgomery(dbl_le1)}

        for i in 0..hash_other_le_limbs.len() {
            {hash_other_le_limbs[i]}
        }
        for i in 0..hash_t_limbs.len() {
            {hash_t_limbs[i]}
        }
        // aux_hashes
        // bit commit hashes
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), hash_sparse_input)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_dense_input)}
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_dense_output)}
    };

    (HintOutSparseDenseMul{f:f1, hash_out: hash_dense_output}, simulate_stack_input)
    
}

// DENSE DENSE MUL ZERO

pub(crate) fn tap_dense_dense_mul0(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, check_is_identity: bool) -> Script {
    assert_eq!(sec_in.len(), 2);
    let (hinted_mul, _) = Fq12::hinted_mul_first(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // g
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f // SD or DD output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // c // SS or c' output
        {Fq::toaltstack()}
    };

    let hash_scr = script!{
        {hash_fp6()} // c
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

        {Fq::equalverify(0, 5)}
        {Fq::equalverify(0, 3)}
        {Fq::equalverify(0, 1)}

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
    let scr = script!{
        {bitcom_scr}
        {ops_scr}
        {hash_scr}
        OP_TRUE
    };
    scr
}


pub(crate) struct HintInDenseMul0 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
}

impl HintInDenseMul0 {
    pub(crate) fn from_groth_hc(c: HintOutHashC, d: HintOutGrothC) -> Self {
        Self { a: c.c, b: d.c }
    }
    pub(crate) fn from_grothc(c: HintOutGrothC, d: HintOutGrothC) -> Self {
        Self { a: c.c, b: d.c }
    }
    pub(crate) fn from_sparse_dense_dbl(c: HintOutSparseDenseMul, d: HintOutSparseDbl) -> Self {
        Self {a: c.f, b: d.f}
    }
    pub(crate) fn from_sparse_dense_add(c: HintOutSparseDenseMul, d: HintOutSparseAdd) -> Self {
        Self {a: c.f, b: d.f}
    }
    pub(crate) fn from_dense_c(c: HintOutDenseMul1, d: HintOutGrothC) -> Self {
        Self {a: c.c, b: d.c}
    }
    pub(crate) fn from_dense_fixed_acc(c: HintOutDenseMul1, d: HintOutFixedAcc) -> Self {
        Self {a: c.c, b: d.f}
    }
    pub(crate) fn from_dense_frob(c: HintOutDenseMul1, d: HintOutFrobFp12) -> Self {
        Self {a: c.c, b: d.f}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDenseMul0 {
    c: ark_bn254::Fq12,
    hash_out: HashBytes,
}

pub(crate) fn hints_dense_dense_mul0(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInDenseMul0) -> (HintOutDenseMul0, Script) {
    assert_eq!(sec_in.len(), 2);
    let (f, g) = (hint_in.a, hint_in.b);
    let h = f * g; 

    let (_, mul_hints) = Fq12::hinted_mul_first(12, f, 0, g);


    let hash_f = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
    let hash_g = emulate_extern_hash_fps(vec![g.c0.c0.c0,g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0,g.c0.c2.c1, g.c1.c0.c0,g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0,g.c1.c2.c1], false);
    let hash_c = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1], true);

    // data passed to stack in runtime 
    let simulate_stack_input = script!{
        // quotients for tmul
        for hint in mul_hints { 
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), hash_c)} // in2: SS or c' link
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_f)} // in1: SD or DD1 link
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_g)} // out
    };

    (HintOutDenseMul0{c: h, hash_out: hash_c}, simulate_stack_input)
    
}


// DENSE DENSE MUL ONE

pub(crate) fn tap_dense_dense_mul1(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, check_is_identity: bool) -> Script {
    assert_eq!(sec_in.len(), 3);
    let mut check_id = 1;
    if !check_is_identity {
        check_id = 0;
    }
    let (hinted_mul, _) = Fq12::hinted_mul_second(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // g
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f // SD or DD output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // c // SS or c' output
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // c // SS or c' output
        {Fq::toaltstack()}
    };

    let hash_scr = script!{
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

        {Fq::equalverify(0, 5)}
        {Fq::equalverify(0, 3)}
        {Fq::equalverify(0, 1)}
        

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
    let scr = script!{
        {bitcom_scr}
        {ops_scr}
        {hash_scr}
        // OP_TRUE
    };
    scr
}

pub(crate) struct HintInDenseMul1 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
    // hash_aux_c0: HashBytes,
}

impl HintInDenseMul1 {
    pub(crate) fn from_groth_hc(c: HintOutHashC, d: HintOutGrothC) -> Self {
        Self { a: c.c, b: d.c }
    }
    pub(crate) fn from_grothc(c: HintOutGrothC, d: HintOutGrothC) -> Self {
        Self { a: c.c, b: d.c }
    }
    pub(crate) fn from_sparse_dense_dbl(c: HintOutSparseDenseMul, d: HintOutSparseDbl) -> Self {
        Self {a: c.f, b: d.f}
    }
    pub(crate) fn from_sparse_dense_add(c: HintOutSparseDenseMul, d: HintOutSparseAdd) -> Self {
        Self {a: c.f, b: d.f}
    }
    pub(crate) fn from_dense_c(c: HintOutDenseMul1, d: HintOutGrothC) -> Self {
        Self {a: c.c, b: d.c}
    }
    pub(crate) fn from_dense_fixed_acc(c: HintOutDenseMul1, d: HintOutFixedAcc) -> Self {
        Self {a: c.c, b: d.f}
    }
    pub(crate) fn from_dense_frob(c: HintOutDenseMul1, d: HintOutFrobFp12) -> Self {
        Self {a: c.c, b: d.f}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDenseMul1 {
    c: ark_bn254::Fq12,
    hash_out: HashBytes,
}
pub(crate) fn hints_dense_dense_mul1(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInDenseMul1) -> (HintOutDenseMul1, Script) {
    let (f, g) = (hint_in.a, hint_in.b);
    let (_, mul_hints) = Fq12::hinted_mul_second(12, f, 0, g);
    let h = f * g;    

    let hash_f = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
    let hash_g = emulate_extern_hash_fps(vec![g.c0.c0.c0,g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0,g.c0.c2.c1, g.c1.c0.c0,g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0,g.c1.c2.c1], false);

    let hash_c0 = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1], true);
    let hash_c = emulate_extern_hash_fps(vec![h.c0.c0.c0,h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0,h.c0.c2.c1, h.c1.c0.c0,h.c1.c0.c1, h.c1.c1.c0, h.c1.c1.c1, h.c1.c2.c0,h.c1.c2.c1], true);

    // data passed to stack in runtime 
    let simulate_stack_input = script!{
        // quotients for tmul
        for hint in mul_hints { 
            { hint.push() }
        }
        // aux_a
        {fq12_push_not_montgomery(f)}
        {fq12_push_not_montgomery(g)}

        // aux_hashes
        // bit commit hashes

        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), hash_c0)} // in3: links to DD0
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), hash_c)} // in2: SS or c' link
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hash_f)} // in1: SD or DD1 link
        { winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), hash_g)} // out
    };
    (HintOutDenseMul1{c: h, hash_out: hash_c}, simulate_stack_input)
}

// Public Params
#[derive(Debug, Clone)]
pub(crate) struct HintOutPubIdentity {
    pub(crate) idhash: HashBytes,
    pub(crate) v: ark_bn254::Fq12,
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutFixedAcc {
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) fhash: HashBytes,
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutGrothC {
    pub(crate) c: ark_bn254::Fq12,
    pub(crate) chash: HashBytes,
}

// PREMILLER

pub(crate) struct HintInHashC {
    c: ark_bn254::Fq12,
    hashc: HashBytes,
}

impl HintInHashC {
    pub(crate) fn from_groth(g: HintOutGrothC) -> Self {
        HintInHashC { c:g.c, hashc: g.chash }
    }
    pub(crate) fn from_points(gs: Vec<ark_bn254::Fq>) -> Self {
        let hash = emulate_extern_hash_fps(gs.clone(), false);
        HintInHashC { c: ark_bn254::Fq12::new(ark_bn254::Fq6::new(ark_bn254::Fq2::new(gs[11], gs[10]), ark_bn254::Fq2::new(gs[9], gs[8]), ark_bn254::Fq2::new(gs[7], gs[6])), ark_bn254::Fq6::new(ark_bn254::Fq2::new(gs[5], gs[4]), ark_bn254::Fq2::new(gs[3], gs[2]), ark_bn254::Fq2::new(gs[1], gs[0]))), hashc: hash }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutHashC {
    c: ark_bn254::Fq12,
    hash_out: HashBytes
}

// HASH_C
pub(crate) fn tap_hash_c(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    assert_eq!(sec_in.len(), 12);
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f11 MSB
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[4]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[5]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[6]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[7]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[8]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[9]))} 
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[10]))}  // f1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[11]))} // f0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // f_hash
        for _ in 0..12 {
            {Fq::fromaltstack()}
        }
        // Stack:[f_hash_claim, f0, ..,f11]
    };

    let hash_scr = script!{
        { hash_fp12_192() }
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {hash_scr}
        OP_TRUE
    };
    sc
}

pub(crate) fn hint_hash_c(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInHashC) ->  (HintOutHashC, Script) {
    let f = hint_in.c;
    let f = vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1];
    let fhash = emulate_extern_hash_fps(f.clone(), false);
    let simulate_stack_input = script!{
        // bit commits raw
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), fhash)}
        for i in 0..12 {
            {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[11-i]), emulate_fq_to_nibbles(f[i]))}
        }
    };
    (HintOutHashC{c: hint_in.c, hash_out: fhash}, simulate_stack_input)
}

// HASH_C
pub(crate) fn tap_hash_c2(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    assert_eq!(sec_in.len(), 12);
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // f11 MSB
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // f_hash
        {Fq::fromaltstack()}
        // Stack:[f_hash_claim, hash_in]
    };

    let hash_scr = script!{
        {Fq::toaltstack()}
        {Fq::toaltstack()}
        {Fq12::copy(0)}
        { hash_fp12() }
        {Fq::toaltstack()}
        {hash_fp12_192()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        {Fq::fromaltstack()}
        //[calc_192, calc_12, claim_12, inp_192]
        {Fq::equalverify(3, 0)}
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {hash_scr}
        OP_TRUE
    };
    sc
}

pub(crate) fn hint_hash_c2(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInHashC) ->  (HintOutHashC, Script) {
    let f = hint_in.c;
    let f = vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1];
    let outhash = emulate_extern_hash_fps(f.clone(), true);
    let simulate_stack_input = script!{
        // bit commits raw
        {fq12_push_not_montgomery(hint_in.c)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), outhash)} // hash
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), hint_in.hashc)} // hash192
    };
    (HintOutHashC{c: hint_in.c, hash_out: outhash}, simulate_stack_input)
}


// precompute P
pub(crate) fn tap_precompute_Px(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    let mut prng = ChaCha20Rng::seed_from_u64(0); // todo: remove prng use later, pt can be any valid mock data
    let pt = ark_bn254::G1Affine::rand(&mut prng);
    let (eval_x, _) =  new_hinted_x_from_eval_point(pt);
    
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // py
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // px
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // pyd
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // pxd

        {Fq::fromaltstack()} // pyd
        {Fq::fromaltstack()} // px
        {Fq::fromaltstack()} // py

        // Stack: [hints, pxd, pyd, px, py]
    };

    let ops_scr = script!{
        {eval_x}
        {Fq::equalverify(1,0)}
    };

    script!{
        {bitcomms_script}
        {ops_scr}
        OP_TRUE
    }
}

// precompute P
pub(crate) fn tap_precompute_Py(sec_key: &str, sec_out: u32, sec_in: Vec<u32>) -> Script {
    let mut prng = ChaCha20Rng::seed_from_u64(0); // todo: remove prng use later, pt can be any valid mock data
    let pt = ark_bn254::G1Affine::rand(&mut prng);
    let (y_eval_scr, _) =  new_hinted_y_from_eval_point(pt.y);
    let bitcomms_script = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // py
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // pyd
        {Fq::fromaltstack()} // py
        // Stack: [hints, pyd, py]
    };

    let ops_scr = script!{
        {y_eval_scr}
        {Fq::equalverify(1, 0)}
    };

    script!{
        {bitcomms_script}
        {ops_scr}
        OP_TRUE
    }
}

pub(crate) struct HintInPrecomputePy {
    p: ark_bn254::Fq,
}

impl HintInPrecomputePy {
    pub(crate) fn from_point(g: ark_bn254::Fq) -> Self {
        Self { p: g }
    }
}

pub(crate) struct HintInPrecomputePx {
    p: G1Affine,
    pdy: ark_bn254::Fq,
}

impl HintInPrecomputePx {
    pub(crate) fn from_points(v: Vec<ark_bn254::Fq>) -> Self {
        // GP3y,GP3x,P3y
        Self { p: ark_bn254::G1Affine::new_unchecked(v[1], v[0]), pdy: v[2] }
    }
}

pub(crate) fn hints_precompute_Px(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInPrecomputePx) -> (ark_bn254::Fq, Script) {
    assert_eq!(sec_in.len(), 3);
    let p = hint_in.p.clone();
    let pdx = -p.x/p.y;
    let pdy = p.y.inverse().unwrap();
    assert_eq!(pdy, hint_in.pdy);
    let (_, hints) =  {new_hinted_x_from_eval_point(p)};


    let pdash_x = emulate_fq_to_nibbles(pdx);
    let pdash_y = emulate_fq_to_nibbles(pdy);
    let p_x = emulate_fq_to_nibbles(p.x);
    let p_y = emulate_fq_to_nibbles(p.y);

    let simulate_stack_input = script!{
        for hint in hints { 
            { hint.push() }
        }
        // bit commits raw
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), pdash_x)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), pdash_y)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), p_x)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), p_y)}
    };
    (pdx, simulate_stack_input)
}

pub(crate) fn hints_precompute_Py(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInPrecomputePy) -> (ark_bn254::Fq, Script) {
    assert_eq!(sec_in.len(), 1);
    let p = hint_in.p.clone();
    let pdy = p.inverse().unwrap();

    let (_, hints) =  new_hinted_y_from_eval_point(p);
    let pdash_y = emulate_fq_to_nibbles(pdy);
    let p_y = emulate_fq_to_nibbles(p);

    let simulate_stack_input = script!{
        for hint in hints { 
            { hint.push() }
        }
        // bit commits raw
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), pdash_y)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), p_y)}
    };
    (pdy, simulate_stack_input)
}

// hash T4
pub(crate) fn tap_initT4(sec_key: &str, sec_out: u32, sec_in: Vec<u32>)-> Script {
    assert_eq!(sec_in.len(), 4);
    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // y1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[1]))} // y0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[2]))} // x1
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[3]))} // x0
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // f_hash
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }
        // Stack:[f_hash_claim, x0,x1,y0,y1]
    };
    let hash_scr = script!{
        { hash_fp4() }
        for _ in 0..64 {
            {0}
        }
        {pack_nibbles_to_limbs()}
        {hash_fp2()}
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {hash_scr}
        OP_TRUE
    };

    sc
}

pub(crate) struct HintInInitT4 {
    pub(crate) t4: ark_bn254::G2Affine,
}

impl HintInInitT4 {
    pub(crate) fn from_groth_q4(cs: Vec<ark_bn254::Fq>) -> Self {
        assert_eq!(cs.len(), 4);
        //Q4y1,Q4y0,Q4x1,Q4x0
        Self { 
            t4: ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(cs[3], cs[2]), ark_bn254::Fq2::new(cs[1], cs[0])) }
    }

}
#[derive(Debug, Clone)]
pub(crate) struct HintOutInitT4 {
    t4: ark_bn254::G2Affine,
    t4hash: [u8;64],
    hash_le_aux: HashBytes,
}

pub(crate) fn hint_init_T4(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInInitT4) -> (HintOutInitT4, Script) {
    assert_eq!(sec_in.len(), 4);
    let t4 = hint_in.t4;
    let t4hash = emulate_extern_hash_fps(vec![t4.x.c0, t4.x.c1, t4.y.c0, t4.y.c1], false);
    let t4hash = emulate_extern_hash_nibbles(vec![t4hash, [0u8;64]]);  
    let simulate_stack_input = script!{
        // bit commits raw
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), t4hash)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[3]), emulate_fq_to_nibbles(t4.x.c0))}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[2]), emulate_fq_to_nibbles(t4.x.c1))}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[1]), emulate_fq_to_nibbles(t4.y.c0))}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), emulate_fq_to_nibbles(t4.y.c1))}
    };
    let hint_out: HintOutInitT4 = HintOutInitT4 {
        t4,
        t4hash,
        hash_le_aux: [0u8; 64],
    };
    (hint_out, simulate_stack_input)
}

// POST MILLER

// FROB Fq12
pub(crate) fn tap_frob_fp12(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, power: usize) -> Script {
    let (hinted_frobenius_map, _) = Fq12::hinted_frobenius_map(power, ark_bn254::Fq12::one());

    let bitcom_scr = script!{
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_out))} // hashout
        {Fq::toaltstack()}
        {checksig_verify_fq(&format!("{}{:04X}", sec_key, sec_in[0]))} // hashin
        {Fq::toaltstack()}
        // AltStack:[sec_out,sec_in]
    };
    let ops_scr = script!{
        // [f]
        {Fq12::copy(0)}
        // [f, f]
        {hinted_frobenius_map}
        // [f, g]
    };
    let hash_scr = script!{
        {Fq12::roll(12)}
        // [g,f]
        { hash_fp12_192() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
        { hash_fp12_192() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
    };
    let sc = script!{
        {bitcom_scr}
        {ops_scr}
       {hash_scr}
        OP_TRUE
    };
    sc
}

pub(crate) struct HintInFrobFp12 {
    f: ark_bn254::Fq12
}

impl HintInFrobFp12 {
    pub(crate) fn from_groth_c(g: HintOutGrothC) -> Self {
        Self { f: g.c }
    }

}
#[derive(Debug, Clone)]
pub(crate) struct HintOutFrobFp12 {
    f: ark_bn254::Fq12,
    fhash: HashBytes,
}
pub(crate) fn hints_frob_fp12(sec_key: &str, sec_out: u32, sec_in: Vec<u32>, hint_in: HintInFrobFp12, power: usize) -> (HintOutFrobFp12, Script) {
    assert_eq!(sec_in.len(), 1);
    let f = hint_in.f;
    let (_, hints_frobenius_map) = Fq12::hinted_frobenius_map(power, f);

    let g = f.frobenius_map(power);

    let fhash = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], false);
    let ghash = emulate_extern_hash_fps(vec![g.c0.c0.c0,g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0,g.c0.c2.c1, g.c1.c0.c0,g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0,g.c1.c2.c1], false);
    
    let simulate_stack_input = script!{
        for hint in hints_frobenius_map { 
            { hint.push() }
        }
        { fq12_push_not_montgomery(f) }
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_in[0]), fhash)}
        {winternitz_compact::sign(&format!("{}{:04X}", sec_key, sec_out), ghash)}
    };
    (HintOutFrobFp12{f: g, fhash: ghash}, simulate_stack_input)
}

pub(crate) fn hint_miller_f_fixedPQ() {
    let mut prng = ChaCha20Rng::seed_from_u64(0);
    let p = ark_bn254::G1Affine::rand(&mut prng);
    let a = ark_bn254::g2::G2Affine::rand(&mut prng);
    let a_affine = a;

    let c = Bn254::multi_miller_loop_affine([p], [a_affine]).0;

}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::bn254::chunk_primitves::{emulate_extern_hash_fps, emulate_extern_hash_nibbles, emulate_fq_to_nibbles, emulate_nibbles_to_limbs};
    use crate::bn254::utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq6_push_not_montgomery};
    use ark_ff::Field;


    #[test]
    fn test_frob_fq12() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1];
        let power = 4;
        let frob_scr = tap_frob_fp12(&sec_key_for_bitcomms, 0, sec_in.clone(), power);
        
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let hint_in: HintInFrobFp12 = HintInFrobFp12 { f };
        let (_, simulate_stack_input) = hints_frob_fp12(&sec_key_for_bitcomms, 0, sec_in.clone(), hint_in, power);
        
        let tap_len = frob_scr.len();
        let script = script!{
            {simulate_stack_input}
            {frob_scr}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_hash_c() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1,2,3,4,5,6,7,8,9,10,11,12];
        let hash_c_scr = tap_hash_c(&sec_key_for_bitcomms, 0, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], false);
        let hint_in = HintInHashC { c: f, hashc: fhash };
        let (_, simulate_stack_input) = hint_hash_c(&sec_key_for_bitcomms, 0, sec_in, hint_in);

        let tap_len = hash_c_scr.len();
        let script = script!{
            {simulate_stack_input}
            {hash_c_scr}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }

    #[test]
    fn test_tap_hash_c2() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1,2,3,4,5,6,7,8,9,10,11,12];
        let hash_c_scr = tap_hash_c2(&sec_key_for_bitcomms, 0, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], false);
        let hint_in = HintInHashC { c: f, hashc: fhash };
        let (_, simulate_stack_input) = hint_hash_c2(&sec_key_for_bitcomms, 0, sec_in, hint_in);

        let tap_len = hash_c_scr.len();
        let script = script!{
            {simulate_stack_input}
            {hash_c_scr}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }


    #[test]
    fn test_tap_hash_T4() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1,2,3,4];
        let hash_c_scr = tap_initT4(&sec_key_for_bitcomms, 0, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let hint_in = HintInInitT4 {t4};
        let (_, simulate_stack_input) = hint_init_T4(&sec_key_for_bitcomms, 0, sec_in, hint_in);

        let tap_len = hash_c_scr.len();
        let script = script!{
            {simulate_stack_input}
            {hash_c_scr}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    }


    // #[test]
    // fn test_precompute_P() {
    //     // compile time
    //     let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
    //     let precompute_p = tap_precompute_P(&sec_key_for_bitcomms, vec![0,1], vec![2,3]);

    //     // runtime
    //     let mut prng = ChaCha20Rng::seed_from_u64(0);
    //     let p = ark_bn254::g1::G1Affine::rand(&mut prng);
    //     let hint_in = HintInPrecomputeP { p };
    //     let (_, simulate_stack_input) = hints_precompute_P(&sec_key_for_bitcomms, vec![0,1], vec![2,3], hint_in);


    //     let tap_len = precompute_p.len();
    //     let script = script!{
    //         {simulate_stack_input}
    //         {precompute_p}
    //     };

    //     let res = execute_script(script);
    //     assert!(res.success);
    //     for i in 0..res.final_stack.len() {
    //         println!("{i:} {:?}", res.final_stack.get(i));
    //     }
    //     println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
        
    // }

    #[test]
    fn test_hinited_sparse_dense_mul() {
        // compile time
        let dbl_blk = false;
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sparse_dense_mul_script = tap_sparse_dense_mul(&sec_key_for_bitcomms, 0, vec![1,2], dbl_blk);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let dbl_le0 = ark_bn254::Fq2::rand(&mut prng);
        let dbl_le1 = ark_bn254::Fq2::rand(&mut prng);
        let hint_in = HintInSparseDenseMul {
            a: f, 
            le0: dbl_le0, 
            le1: dbl_le1,
            hash_other_le: [2u8; 64],
            hash_aux_T: [3u8; 64],
        };
        let (_, simulate_stack_input) = hints_sparse_dense_mul(&sec_key_for_bitcomms, 0, vec![1,2], hint_in, dbl_blk);

        let tap_len = sparse_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:3} {:?}", exec_result.final_stack.get(i));
        }
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }


    #[test]
    fn test_hinited_dense_dense_mul0() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul0(&sec_key_for_bitcomms, 0, vec![1,2], true);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap(); //ark_bn254::Fq12::rand(&mut prng); // check_is_identity true
        let h = f * g; 

        let hint_in = HintInDenseMul0 {
            a: f,
            b: g,
        };
        let (_, simulate_stack_input) = hints_dense_dense_mul0(&sec_key_for_bitcomms, 0, vec![1,2], hint_in);

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }

    #[test]
    fn test_hinited_dense_dense_mul1() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul1(&sec_key_for_bitcomms,0, vec![1,2,3], false);

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = ark_bn254::Fq12::rand(&mut prng);
        let hint_in = HintInDenseMul1 {
            a: f,
            b: g,
        };
        let (_, simulate_stack_input) = hints_dense_dense_mul1(&sec_key_for_bitcomms,0, vec![1,2,3], hint_in);

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { dense_dense_mul_script }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }

    #[test]
    fn test_tap_fq12_hinted_square() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let squaring_tapscript = tap_squaring(&sec_key_for_bitcomms, 0, vec![1]);

        // run time
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let ahash = emulate_extern_hash_fps(vec![a.c0.c0.c0,a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0,a.c0.c2.c1, a.c1.c0.c0,a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0,a.c1.c2.c1], true);
        let hint_in: HintInSquaring = HintInSquaring {a, ahash: ahash};
        let (_, stack_data) = hints_squaring(&sec_key_for_bitcomms, 0, vec![1], hint_in);

        let tap_len = squaring_tapscript.len();
        let script = script! {
            { stack_data }
            { squaring_tapscript }
        };

        let exec_result = execute_script(script);

        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);
    }

    #[test]
    fn test_tap_affine_double_add_eval() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_ops(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6,7], -1);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8;64];
        let hint_in = HintInDblAdd { t, p, q, hash_le_aux };
        let (_,  simulate_stack_input) = hint_point_ops(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6,7], hint_in, -1);

        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_affine_double_eval() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_dbl(sec_key_for_bitcomms, 0, vec![1,2,3]);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8;64]; // mock
        let hint_in = HintInDouble { t, p, hash_le_aux};

        let (_, simulate_stack_input) = hint_point_dbl(sec_key_for_bitcomms, 0, vec![1,2,3], hint_in);
        
        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_affine_add_eval() {

        let ate = 1;
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_add(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6, 7], ate);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8;64];
        let hint_in = HintInAdd { t, p, q, hash_le_aux };
        let (_, simulate_stack_input) = hint_point_add(sec_key_for_bitcomms, 0, vec![1,2,3,4,5,6, 7], hint_in, ate);

        let tap_len = point_ops_tapscript.len();
        let script = script!{
            {simulate_stack_input}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        //assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_dbl_sparse_muls() {

        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
    
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let (sparse_dbl_tapscript,_,_) = tap_double_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], t2, t3);
        
        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInSparseDbl {t2, t3, p2: p2dash, p3: p3dash}; 
        let (_, simulate_stack_input) = hint_double_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], hint_in);

        let tap_len = sparse_dbl_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_dbl_tapscript }
        };

        let exec_result = execute_script(script);

        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }    


    #[test]
    fn test_tap_add_sparse_muls() {

        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
    
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let (sparse_add_tapscript, _, _) = tap_add_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], t2, t3, q2, q3);
        
        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInSparseAdd {t2, t3, p2: p2dash, p3: p3dash, q2, q3}; 
        let (_, simulate_stack_input) = hint_add_eval_mul_for_fixed_Qs(&sec_key_for_bitcomms,0, vec![1,2,3,4], hint_in);
    
        let tap_len = sparse_add_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            { sparse_add_tapscript }
        };

        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(exec_result.success);
        println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);

    }    


 }