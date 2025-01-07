use std::{collections::HashMap, ops::Neg};

use ark_bn254::{Bn254};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use bitcoin_script::script;

use crate::{chunk::{primitves::{tup_to_scr, HashBytes, Sig, SigData}, segment::*, taps_point_eval::{get_hint_for_add_with_frob}}, execute_script, groth16::g16::{Assertions, PublicKeys, Signatures, N_TAPLEAVES, N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS}, treepp};


use super::{api::nib_to_byte_array, compile::{ATE_LOOP_COUNT, NUM_PUBS, NUM_U160, NUM_U256}, hint_models::*, primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles},  wots::WOTSPubKey};



#[derive(Debug)]
pub struct Pubs {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq12,
    pub ks_vks: Vec<ark_bn254::G1Affine>,
    pub vky0: ark_bn254::G1Affine,
}


fn compare(hint_out: &Element, claimed_assertions: &mut Option<Intermediates>) -> Option<bool> {
    if claimed_assertions.is_none() {
        return None;
    }
    fn get_fq(claimed_assertions: &mut Option<Intermediates>) -> ark_bn254::Fq {
        if let Some(claimed_assertions) = claimed_assertions {
            claimed_assertions.0.pop().unwrap()
        } else {
            panic!()
        }
    }
    
    fn get_hash(claimed_assertions: &mut Option<Intermediates>) -> HashBytes {
        if let Some(claimed_assertions) = claimed_assertions {
            claimed_assertions.1.pop().unwrap()
        } else {
            panic!()
        }
    }

    let (x, is_field) = match hint_out {
        Element::G2Acc(r) => (r.out(), r.ret_type()),
        Element::Fp12(r) => (r.out(), r.ret_type()),
        Element::FieldElem(f) => (f.out(), f.ret_type()),
        Element::MSMG1(r) => (r.out(), r.ret_type()),
        Element::MSMG2(r) => (r.out(), r.ret_type()),
        Element::ScalarElem(r) => (r.out(), r.ret_type()),
        Element::SparseEval(r) => (r.out(), r.ret_type()),
        Element::HashBytes(r) => (r.out(), r.ret_type()),
    };

    let matches = if is_field {
        let r = get_fq(claimed_assertions);
        extern_fq_to_nibbles(r) == x
    }  else {
        let r = get_hash(claimed_assertions);
        r == x
    };
    return Some(matches) 
}

pub(crate) fn groth16(
    is_compile_mode: bool,
    all_output_hints: &mut Vec<Segment>,
    eval_ins: EvalIns,
    pubs: Pubs,
    claimed_assertions: &mut Option<Intermediates>
) -> bool {
    macro_rules! push_compare_or_return {
        ($seg:ident) => {{
            all_output_hints.push($seg.clone());
            let matches = compare(&$seg.output, claimed_assertions);
            if matches.is_some() && matches.unwrap() == false {
                return false;
            }
        }};
    }

    let pub_scalars: Vec<Segment> = eval_ins.ks.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        output_type: true,
        inputs: vec![],
        output: Element::ScalarElem(*f),
        hint_script: script!(),
        scr_type: ScriptType::NonDeterministic,
    }).collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = vec![
        eval_ins.p4.y, eval_ins.p4.x, eval_ins.p3.y, eval_ins.p3.x, eval_ins.p2.y, eval_ins.p2.x
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        output_type: true,
        inputs: vec![],
        output: Element::FieldElem(*f),
        hint_script: script!(),
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x, gp3y, gp3x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3], &p4vec[4], &p4vec[5]);

    let p4y = wrap_hints_precompute_py(is_compile_mode, all_output_hints.len(), &gp4y);
    push_compare_or_return!(p4y);

    let p4x = wrap_hints_precompute_px(is_compile_mode, all_output_hints.len(), &gp4y, &gp4x, &p4y);
    push_compare_or_return!(p4x);

    let p3y = wrap_hints_precompute_py(is_compile_mode, all_output_hints.len(), &gp3y);
    push_compare_or_return!(p3y);

    let p3x = wrap_hints_precompute_px(is_compile_mode, all_output_hints.len(), &gp3y, &gp3x, &p3y);
    push_compare_or_return!(p3x);

    let p2y = wrap_hints_precompute_py(is_compile_mode, all_output_hints.len(), &gp2y);
    push_compare_or_return!(p2y);

    let p2x = wrap_hints_precompute_px(is_compile_mode, all_output_hints.len(), &gp2y, &gp2x, &p2y);
    push_compare_or_return!(p2x);

    let gc: Vec<Segment> = vec![
        eval_ins.c.c0.c0.c0, eval_ins.c.c0.c0.c1, eval_ins.c.c0.c1.c0, eval_ins.c.c0.c1.c1,
        eval_ins.c.c0.c2.c0, eval_ins.c.c0.c2.c1, eval_ins.c.c1.c0.c0, eval_ins.c.c1.c0.c1,
        eval_ins.c.c1.c1.c0, eval_ins.c.c1.c1.c1, eval_ins.c.c1.c2.c0, eval_ins.c.c1.c2.c1,
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        output_type: true,
        inputs: vec![],
        output: Element::FieldElem(*f),
        hint_script: script!(),
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&gc);

    let gs: Vec<Segment> = vec![
        eval_ins.s.c0.c0.c0, eval_ins.s.c0.c0.c1, eval_ins.s.c0.c1.c0, eval_ins.s.c0.c1.c1,
        eval_ins.s.c0.c2.c0, eval_ins.s.c0.c2.c1, eval_ins.s.c1.c0.c0, eval_ins.s.c1.c0.c1,
        eval_ins.s.c1.c1.c0, eval_ins.s.c1.c1.c1, eval_ins.s.c1.c2.c0, eval_ins.s.c1.c2.c1,
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        output_type: true,
        inputs: vec![],
        output: Element::FieldElem(*f),
        hint_script: script!(),
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&gs);

    let temp_q4: Vec<Segment> = vec![
        eval_ins.q4.x.c0, eval_ins.q4.x.c1, eval_ins.q4.y.c0, eval_ins.q4.y.c1
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        output_type: true,
        inputs: vec![],
        output: Element::FieldElem(*f),
        hint_script: script!(),
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&temp_q4);
    let (q4xc0, q4xc1, q4yc0, q4yc1) = (&temp_q4[0], &temp_q4[1], &temp_q4[2], &temp_q4[3]);

    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;

    let msms = wrap_hint_msm(is_compile_mode, all_output_hints.len(), pub_scalars.clone(), vky.clone());
    for msm in &msms {
        push_compare_or_return!(msm);
    }

    let hp = wrap_hint_hash_p(is_compile_mode, all_output_hints.len(), &msms[msms.len()-1], &gp3y, &gp3x, vky0);
    push_compare_or_return!(hp);

    let c = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gc);
    push_compare_or_return!(c);

    let s = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gs);
    push_compare_or_return!(s);

    let c2 = wrap_hint_hash_c2(is_compile_mode, all_output_hints.len(), &c);
    push_compare_or_return!(c2);

    let dmul0 = wrap_inv0(is_compile_mode, all_output_hints.len(), &c2);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_inv1(is_compile_mode, all_output_hints.len(), &dmul0);
    push_compare_or_return!(dmul1);

    let gcinv = wrap_inv2(is_compile_mode, all_output_hints.len(), &dmul1, &c2);
    push_compare_or_return!(gcinv);

    let cinv2 = wrap_hint_hash_c2(is_compile_mode, all_output_hints.len(), &gcinv);
    push_compare_or_return!(cinv2);

    let mut t4 = wrap_hint_init_t4(is_compile_mode, all_output_hints.len(), &q4yc1, &q4yc0, &q4xc1, &q4xc0);
    push_compare_or_return!(t4);

    let (mut t2, mut t3) = (pubs.q2, pubs.q3);
    let mut f_acc = cinv2.clone();

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        if !is_compile_mode {
            println!("itr {:?}", j);
        }
        let ate = ATE_LOOP_COUNT[j - 1];
        let sq = wrap_hint_squaring(is_compile_mode, all_output_hints.len(), &f_acc);
        push_compare_or_return!(sq);
        f_acc = sq;

        if ate == 0 {
            let dbl = wrap_hint_point_dbl(is_compile_mode, all_output_hints.len(), &t4, &p4y, &p4x);
            push_compare_or_return!(dbl);
            t4 = dbl;
        } else {
            let dbladd = wrap_hint_point_ops(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4y, &p4x, ate);
            push_compare_or_return!(dbladd);
            t4 = dbladd;
        }

        let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, true);
        push_compare_or_return!(sdmul);
        f_acc = sdmul;

        let leval = wrap_hint_double_eval_mul_for_fixed_qs(is_compile_mode, all_output_hints.len(), &p3y, &p3x, &p2y, &p2x,  t2, t3);
        push_compare_or_return!(leval);
        (t2, t3) = ((t2 + t2).into_affine(), (t3 + t3).into_affine());


        let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;

        if ate == 0 {
            continue;
        }

        let c_or_cinv = if ate == -1 { c.clone() } else { gcinv.clone() };

        let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &c_or_cinv);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &c_or_cinv, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;

        let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
        push_compare_or_return!(sdmul);
        f_acc = sdmul;

        let leval = wrap_hint_add_eval_mul_for_fixed_qs(is_compile_mode, all_output_hints.len(), &p3y, &p3x, &p2y, &p2x,  t2, t3, pubs.q2, pubs.q3, ate);
        push_compare_or_return!(leval);
        if ate == 1 {
            (t2, t3) = ((t2 + pubs.q2).into_affine(), (t3 + pubs.q3).into_affine());
        } else {
            (t2, t3) = ((t2 - pubs.q2).into_affine(), (t3 - pubs.q3).into_affine());
        }

        let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;
    }

    let cp = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 1);
    push_compare_or_return!(cp);

    let cp2 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &c, 2);
    push_compare_or_return!(cp2);

    let cp3 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 3);
    push_compare_or_return!(cp3);

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp2);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp2, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp3);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp3, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &s);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &s, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let addf = wrap_hint_point_add_with_frob(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4y, &p4x, 1);
    push_compare_or_return!(addf);
    t4 = addf;

    let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
    push_compare_or_return!(sdmul);
    f_acc = sdmul;

    let leval = wrap_hint_add_eval_mul_for_fixed_qs_with_frob(is_compile_mode, all_output_hints.len(), &p3y, &p3x, &p2y, &p2x,  t2, t3, pubs.q2, pubs.q3, 1);
    push_compare_or_return!(leval);
    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, 1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, 1);


    let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let addf = wrap_hint_point_add_with_frob(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4y, &p4x, -1);
    push_compare_or_return!(addf);
    t4 = addf;

    let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
    push_compare_or_return!(sdmul);
    f_acc = sdmul;

    let leval = wrap_hint_add_eval_mul_for_fixed_qs_with_frob(is_compile_mode, all_output_hints.len(), &p3y, &p3x, &p2y, &p2x,  t2, t3, pubs.q2, pubs.q3, -1);
    push_compare_or_return!(leval);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, -1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, -1);

    let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0_by_constant(is_compile_mode, all_output_hints.len(), &f_acc, pubs.fixed_acc);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1_by_constant(is_compile_mode, all_output_hints.len(), &f_acc, &dmul0, pubs.fixed_acc);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let result: ElemFp12Acc = f_acc.output.try_into().unwrap();
    if result.f != ark_bn254::Fq12::ONE {
        return false;
    }
    //assert_eq!(result.f, ark_bn254::Fq12::ONE);

    println!("segments len {}", all_output_hints.len());

    true
}

pub(crate) fn hint_to_data(segments: Vec<Segment>) -> Assertions {
    let mut vs: Vec<[u8; 64]> = vec![];
    for v in segments {
        let x = match v.output {
            Element::G2Acc(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::FieldElem(f) => f.out(),
            Element::MSMG1(r) => r.out(),
            Element::MSMG2(r) => r.out(),
            Element::ScalarElem(r) => r.out(),
            Element::SparseEval(r) => r.out(),
            Element::HashBytes(r) => r.out(),
        };
        vs.push(x);
    }
    let mut batch1 = vec![];
    for i in 0..NUM_PUBS {
        let val = vs[i];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch1.push(bal);
    }
    let batch1: [[u8; 32]; NUM_PUBS] = batch1.try_into().unwrap();

    let len = batch1.len();
    let mut batch2 = vec![];
    for i in 0..NUM_U256 {
        let val = vs[i + len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch2.push(bal);
    }
    let batch2: [[u8; 32]; N_VERIFIER_FQS] = batch2.try_into().unwrap();

    let len = batch1.len() + batch2.len();
    let mut batch3 = vec![];
    for i in 0..NUM_U160 {
        let val = vs[i+len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        batch3.push(bal);
    }
    let batch3: [[u8; 20]; N_VERIFIER_HASHES] = batch3.try_into().unwrap();

    (batch1, batch2, batch3)
}

type TypedAssertions = (
    [ark_bn254::Fr; N_VERIFIER_PUBLIC_INPUTS],
    [ark_bn254::Fq; N_VERIFIER_FQS],
    [HashBytes; N_VERIFIER_HASHES],
);

fn assertions_to_nibbles(tass: TypedAssertions) -> Vec<[u8;64]> {
    let mut nibvec: Vec<[u8;64]> = vec![];
    for fq in tass.0 {
        nibvec.push(extern_fr_to_nibbles(fq));
    }
    for fq in tass.1 {
        nibvec.push(extern_fq_to_nibbles(fq));
    }
    for fq in tass.2 {
        nibvec.push(fq);
    }
    nibvec
}

type Intermediates = (
    Vec<ark_bn254::Fq>,
    Vec<HashBytes>,
);

pub(crate) fn get_proof(asserts: &TypedAssertions) -> EvalIns { // EvalIns
    let numfqs = asserts.1;
    let p4 = ark_bn254::G1Affine::new_unchecked(numfqs[1], numfqs[0]);
    let p3 = ark_bn254::G1Affine::new_unchecked(numfqs[3], numfqs[2]);
    let p2 = ark_bn254::G1Affine::new_unchecked(numfqs[5], numfqs[4]);
    let skip = 6; // px, pys -- not part of eval ins
    let next = 6;
    let step = next + skip;
    let c = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
            ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
            ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+6], numfqs[step+7]),
            ark_bn254::Fq2::new(numfqs[step+8], numfqs[step+9]),
            ark_bn254::Fq2::new(numfqs[step+10], numfqs[step+11]),
        ),
    );
    let step = step + 12;
    let s = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
            ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
            ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+6], numfqs[step+7]),
            ark_bn254::Fq2::new(numfqs[step+8], numfqs[step+9]),
            ark_bn254::Fq2::new(numfqs[step+10], numfqs[step+11]),
        ),
    );
    let cinv = asserts.2[0];

    let step = step + 12;
    let q4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(numfqs[step + 0], numfqs[step + 1]), ark_bn254::Fq2::new(numfqs[step + 2], numfqs[step + 3]));

    let eval_ins: EvalIns = EvalIns { p2, p3, p4, q4, c, s, ks: asserts.0.to_vec() };
    eval_ins
}

pub(crate) fn get_intermediates(asserts: &TypedAssertions) -> Intermediates { // Intermediates
    let mut fqs = asserts.1[6..12].to_vec();
    fqs.reverse();
    let mut hashes= asserts.2.to_vec();
    hashes.reverse();
    (fqs, hashes)
}

pub(crate) fn get_assertions(signed_asserts: Signatures) -> TypedAssertions {
    let mut ks: Vec<ark_bn254::Fr> = vec![];
    for i in 0..N_VERIFIER_PUBLIC_INPUTS {
        let sc = signed_asserts.0[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fr =  ark_bn254::Fr::from_le_bytes_mod_order(&nibs);
        ks.push(fr);
    }

    let mut numfqs: Vec<ark_bn254::Fq> = vec![];
    for i in 0..N_VERIFIER_FQS {
        let sc = signed_asserts.1[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fq =  ark_bn254::Fq::from_le_bytes_mod_order(&nibs);
        numfqs.push(fq);
    }

    let mut numhashes: Vec<HashBytes> = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let sc = signed_asserts.2[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..40].to_vec();
        nibs.reverse();
        let nibs: [u8; 40] = nibs.try_into().unwrap();
        let mut padded_nibs = [0u8; 64]; // initialize with zeros
        padded_nibs[24..64].copy_from_slice(&nibs[0..40]);
        numhashes.push(padded_nibs);
    }
    (ks.try_into().unwrap(), numfqs.try_into().unwrap(), numhashes.try_into().unwrap())
}

pub(crate) fn get_pubs(vk: &ark_groth16::VerifyingKey<Bn254>) -> Pubs {
    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );
    let fixed_acc = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;

    let pubs: Pubs = Pubs { q2, q3, fixed_acc, ks_vks: msm_gs.clone(), vky0 };
    pubs
}

pub(crate) fn script_exec(
    segments: Vec<Segment>, 
    signed_asserts: Signatures,
    inpubkeys: PublicKeys,
    disprove_scripts: &[treepp::Script; N_TAPLEAVES],
) -> Option<(usize, treepp::Script)> {
    let mut sigcache: HashMap<u32, SigData> = HashMap::new();

    assert_eq!(signed_asserts.0.len(), NUM_PUBS);

    for i in 0..NUM_PUBS {
        sigcache.insert(i as u32, SigData::Sig256(signed_asserts.0[i]));
    }

    for i in 0..N_VERIFIER_FQS {
        sigcache.insert((NUM_PUBS + i) as u32, SigData::Sig256(signed_asserts.1[i]));
    }

    for i in 0..N_VERIFIER_HASHES {
        sigcache.insert((NUM_PUBS + N_VERIFIER_FQS + i) as u32, SigData::Sig160(signed_asserts.2[i]));
    }


    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    for i in 0..NUM_PUBS {
        pubkeys.insert(i as u32, WOTSPubKey::P256(inpubkeys.0[i]));
    }
    let len = pubkeys.len();
    for i in 0..inpubkeys.1.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P256(inpubkeys.1[i]));
    }
    let len = pubkeys.len();
    for i in 0..inpubkeys.2.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P160(inpubkeys.2[i]));
    }

    let mut sig = Sig {
        cache: sigcache,
    };

    let assertions = assertions_to_nibbles(get_assertions(signed_asserts));

    // FIXME: 
    let mut bc_hints = vec![];
    for i in 0..segments.len() {
        let seg = &segments[i];
        let sec_out = ((seg.id, seg.output_type), assertions[seg.id as usize]);
        let sec_in: Vec<((u32, bool), [u8; 64])> = seg.inputs.iter().rev().map(|(k, v)| ((*k, *v), assertions[*k as usize])).collect();
        let mut tot: Vec<((u32, bool), [u8;64])> = vec![];
        tot.extend_from_slice(&sec_in);
        tot.push(sec_out);
        let (bcelems, should_validate) = tup_to_scr(&mut sig, tot);
        if should_validate == true {
            println!("index {:?} bcelems len {:?}  should_validate {}",i, bcelems.len(), should_validate);
        }
        bc_hints.push(bcelems);
    }

    let aux_hints: Vec<treepp::Script> = segments.iter().map(|f| f.hint_script.clone()).collect();

    let mut tap_script_index = 0;
    for i in 0..aux_hints.len() {
        if segments[i].scr_type == ScriptType::NonDeterministic  {
            continue;
        }
        let hint_script = script!{
            {aux_hints[i].clone()}
            {bc_hints[i].clone()}
        };
        let total_script = script!{
            {hint_script.clone()}
            {disprove_scripts[tap_script_index].clone()}
        };
        let exec_result = execute_script(total_script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
        if !exec_result.success {
            if exec_result.final_stack.len() != 1 {
                println!("final {:?}", i);
                println!("final {:?}", segments[i].scr_type);
                assert!(false);
            }
        } else {
            println!("disprove script {}: tapindex {}, {:?}",i,tap_script_index, segments[i].scr_type);
            let disprove_hint = (
                tap_script_index,
                hint_script,
            );
            return Some(disprove_hint);
        }
        tap_script_index += 1;
    }
    None
}
