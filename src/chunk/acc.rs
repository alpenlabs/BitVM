use std::{collections::HashMap, ops::Neg};

use ark_bn254::{Bn254, G1Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use bitcoin_script::script;

use crate::{bigint::add, chunk::segment::*, groth16::g16::{Assertions, PublicKeys, Signatures, N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS}};

use super::{api::nib_to_byte_array, config::{ATE_LOOP_COUNT, NUM_PUBS, NUM_U160, NUM_U256}, evaluate::{EvalIns}, hint_models::*, msm::{hint_hash_p, hint_msm}, primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles, extern_hash_fps, extern_hash_nibbles}, taps::{self, hint_add_eval_mul_for_fixed_Qs_with_frob, hint_hash_c, hint_hash_c2, hint_init_T4, hint_point_add_with_frob, hints_frob_fp12, hints_precompute_Px, hints_precompute_Py, HashBytes, Sig, SigData}, taps_mul::{self, hint_sparse_dense_mul, hints_dense_dense_mul0, hints_dense_dense_mul0_by_constant, hints_dense_dense_mul0_by_hash, hints_dense_dense_mul1, hints_dense_dense_mul1_by_constant, hints_dense_dense_mul1_by_hash}, wots::WOTSPubKey};



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
        Element::G2Acc(r) => (r.out(), false),
        Element::Fp12(r) => (r.out(), false),
        Element::FieldElem(f) => (extern_fq_to_nibbles(*f), true),
        Element::MSMG1(r) => (r.out(), false),
        Element::ScalarElem(r) => (extern_fr_to_nibbles(*r), true),
        Element::SparseEval(r) => (r.out(), false),
        Element::HashBytes(r) => (*r, false),
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

pub(crate) fn groth16(all_output_hints: &mut Vec<Segment>, eval_ins: EvalIns, pubs: Pubs, claimed_assertions: &mut Option<Intermediates>)  {

    // let mut all_output_hints: Vec<HintOut> = vec![];
    let pub_scalars: Vec<Segment> = eval_ins.ks.iter().enumerate().map(|(idx, f)| Segment { id: all_output_hints.len()+idx, output_type: true, inputs: vec![], output: Element::ScalarElem(*f), hint_script: script!(), scr_type: ScriptType::NonDeterministic}).collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = vec![eval_ins.p4.y, eval_ins.p4.x, eval_ins.p3.y, eval_ins.p3.x, eval_ins.p2.y, eval_ins.p2.x].iter().enumerate().map(|(idx, f)| Segment { id: all_output_hints.len()+idx, output_type: true, inputs: vec![], output: Element::FieldElem(*f), hint_script: script!(), scr_type: ScriptType::NonDeterministic}).collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x,gp3y, gp3x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3], &p4vec[4], &p4vec[5]);


    // PRECOMPUTE
    let p4y = wrap_hints_precompute_Py(all_output_hints.len(), &gp4y);
    compare(&p4y.output, claimed_assertions);
    all_output_hints.push(p4y.clone());
    

    let p4x = wrap_hints_precompute_Px(all_output_hints.len(), &gp4x, &gp4y);
    compare(&p4x.output, claimed_assertions);
    all_output_hints.push(p4x.clone());
    

    let p3y = wrap_hints_precompute_Py(all_output_hints.len(), &gp3y);
    compare(&p3y.output, claimed_assertions);
    all_output_hints.push(p3y.clone());
    

    let p3x = wrap_hints_precompute_Px(all_output_hints.len(), &gp3x, &gp3y);
    compare(&p3x.output, claimed_assertions);
    all_output_hints.push(p3x.clone());
    
    
    let p2y = wrap_hints_precompute_Py(all_output_hints.len(), &gp2y);
    compare(&p2y.output, claimed_assertions);
    all_output_hints.push(p2y.clone());
    

    let p2x = wrap_hints_precompute_Px(all_output_hints.len(), &gp2x, &gp2y);
    compare(&p2x.output, claimed_assertions);
    all_output_hints.push(p2x.clone());
    

    // GC AND GS AND Q4
    let gc: Vec<Segment> = vec![
        eval_ins.c.c0.c0.c0, eval_ins.c.c0.c0.c1, eval_ins.c.c0.c1.c0, eval_ins.c.c0.c1.c1, eval_ins.c.c0.c2.c0, eval_ins.c.c0.c2.c1, eval_ins.c.c1.c0.c0,
        eval_ins.c.c1.c0.c1, eval_ins.c.c1.c1.c0, eval_ins.c.c1.c1.c1, eval_ins.c.c1.c2.c0, eval_ins.c.c1.c2.c1,
    ].iter().enumerate().map(|(idx, f)| Segment { id: all_output_hints.len()+idx, output_type: true, inputs: vec![], output: Element::FieldElem(*f), hint_script: script!(), scr_type: ScriptType::NonDeterministic}).collect();
    all_output_hints.extend_from_slice(&gc);


    let gs: Vec<Segment> = vec![
        eval_ins.s.c0.c0.c0, eval_ins.s.c0.c0.c1, eval_ins.s.c0.c1.c0, eval_ins.s.c0.c1.c1, eval_ins.s.c0.c2.c0, eval_ins.s.c0.c2.c1, eval_ins.s.c1.c0.c0,
        eval_ins.s.c1.c0.c1, eval_ins.s.c1.c1.c0, eval_ins.s.c1.c1.c1, eval_ins.s.c1.c2.c0, eval_ins.s.c1.c2.c1,
    ].iter().enumerate().map(|(idx, f)| Segment { id: all_output_hints.len()+idx, output_type: true, inputs: vec![], output: Element::FieldElem(*f), hint_script: script!(), scr_type: ScriptType::NonDeterministic}).collect();
    all_output_hints.extend_from_slice(&gs);


    let temp_q4: Vec<Segment> = vec![eval_ins.q4.x.c0, eval_ins.q4.x.c1, eval_ins.q4.y.c0, eval_ins.q4.y.c1].iter().enumerate().map(|(idx, f)| Segment { id: all_output_hints.len()+idx, output_type: true, inputs: vec![], output: Element::FieldElem(*f), hint_script: script!(), scr_type: ScriptType::NonDeterministic}).collect();
    all_output_hints.extend_from_slice(&temp_q4);
    let (q4xc0, q4xc1, q4yc0, q4yc1) = (&temp_q4[0], &temp_q4[1], &temp_q4[2], &temp_q4[3]);
    

    // C inverse
    let tmp_cvinv = eval_ins.c.inverse().unwrap();
    let tmp_cvinv: ElemFp12Acc = ElemFp12Acc { f: tmp_cvinv, hash: extern_hash_fps(
        vec![
            tmp_cvinv.c0.c0.c0,
            tmp_cvinv.c0.c0.c1,
            tmp_cvinv.c0.c1.c0,
            tmp_cvinv.c0.c1.c1,
            tmp_cvinv.c0.c2.c0,
            tmp_cvinv.c0.c2.c1,
            tmp_cvinv.c1.c0.c0,
            tmp_cvinv.c1.c0.c1,
            tmp_cvinv.c1.c1.c0,
            tmp_cvinv.c1.c1.c1,
            tmp_cvinv.c1.c2.c0,
            tmp_cvinv.c1.c2.c1,
        ],
        false,
    ) }; 
    let gcinv = Segment { id: all_output_hints.len(), output_type: false, inputs: vec![], output: Element::Fp12(tmp_cvinv), hint_script: script!(), scr_type: ScriptType::NonDeterministic};
    compare(&gcinv.output, claimed_assertions);
    all_output_hints.push(gcinv.clone());
    

    // Public Params
    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;

    // MSM
    let mut msm = wrap_hint_msm(all_output_hints.len(), None, pub_scalars.clone(), 0, vky.clone());
    compare(&msm.output, claimed_assertions);
    all_output_hints.push(msm.clone());

    for i in 1..32 {
        msm = wrap_hint_msm(all_output_hints.len(), Some(msm), pub_scalars.clone(), i, vky.clone());
        compare(&msm.output, claimed_assertions);
        all_output_hints.push(msm.clone());
    }
    let hp = wrap_hint_hash_p(all_output_hints.len(), &gp3x, &gp3y, &msm, vky0);
    compare(&hp.output, claimed_assertions);
    all_output_hints.push(hp);
    
    
    // PRE MILLER CHECKS
    
    let c = wrap_hint_hash_c(all_output_hints.len(), gc);
    compare(&c.output, claimed_assertions);
    all_output_hints.push(c.clone());

    let s = wrap_hint_hash_c(all_output_hints.len(), gs);
    compare(&s.output, claimed_assertions);
    all_output_hints.push(s.clone());
    

    let c2 = wrap_hint_hash_c2(all_output_hints.len(), &c);
    compare(&c2.output, claimed_assertions);
    all_output_hints.push(c2.clone());
    
    
    let dmul0 = wrap_hints_dense_dense_mul0_by_hash(all_output_hints.len(), &c2, &gcinv);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);
    

    let dmul1 = wrap_hints_dense_dense_mul1_by_hash(all_output_hints.len(), &c2, &gcinv);
   compare(&dmul1.output, claimed_assertions);
   all_output_hints.push(dmul1);
    

    let cinv2 = wrap_hint_hash_c2(all_output_hints.len(), &gcinv);
    compare(&cinv2.output, claimed_assertions);
    all_output_hints.push(cinv2.clone());
    

    let mut t4 = wrap_hint_init_T4(all_output_hints.len(), &q4xc0, &q4xc1, &q4yc0, &q4yc1); 
    compare(&t4.output, claimed_assertions);
    all_output_hints.push(t4.clone());
    
    let (mut t2, mut t3) = (pubs.q2, pubs.q3);

    // miller loop
    let mut f_acc = cinv2.clone();

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let ate = ATE_LOOP_COUNT[j-1];
        // Sqr
        let sq = wrap_hint_squaring(all_output_hints.len(), &f_acc);
        compare(&sq.output, claimed_assertions);
        all_output_hints.push(sq.clone());
        f_acc = sq;

        // Dbl or DblAdd
        if ate == 0 {
            let dbl = wrap_hint_point_dbl(all_output_hints.len(), &t4, &p4x, &p4y);
            compare(&dbl.output, claimed_assertions);
            all_output_hints.push(dbl.clone());
            t4 = dbl;
        } else { 
            let dbladd = wrap_hint_point_ops(all_output_hints.len(), &t4,&p4x, &p4y, &q4xc0, &q4xc1, &q4yc0, &q4yc1, ate);
            compare(&dbladd.output, claimed_assertions);
            all_output_hints.push(dbladd.clone());
            t4 = dbladd;
        }
        // SD1
        let sdmul = wrap_hint_sparse_dense_mul(all_output_hints.len(), &f_acc, &t4,  true);
        compare(&sdmul.output, claimed_assertions);
        all_output_hints.push(sdmul.clone());
        f_acc = sdmul;


        // SS1
        let leval = wrap_hint_double_eval_mul_for_fixed_Qs(all_output_hints.len(),&p2x, &p2y, &p3x, &p3y, t2, t3);
        compare(&leval.output, claimed_assertions);
        all_output_hints.push(leval.clone());
        let le: ElemSparseEval = leval.output.into();
        (t2, t3) = (le.t2, le.t3);

        // DD1
        let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &leval);
        compare(&dmul0.output, claimed_assertions);
        all_output_hints.push(dmul0);

        let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &leval);
        compare(&dmul1.output, claimed_assertions);
        all_output_hints.push(dmul1.clone());
        f_acc = dmul1;

        if ate == 0 {
            continue;
        }

        // DD3
        // mul by cinv if ate == 1
        let c_or_cinv = if ate == -1 {
            c.clone()
        } else {
            gcinv.clone()
        };
        let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &c_or_cinv);
        compare(&dmul0.output, claimed_assertions);
        all_output_hints.push(dmul0);

        let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &c_or_cinv);
        compare(&dmul1.output, claimed_assertions);
        all_output_hints.push(dmul1.clone());
        f_acc = dmul1;

        // SD2
        let sdmul = wrap_hint_sparse_dense_mul(all_output_hints.len(), &f_acc, &t4,  false);
        compare(&sdmul.output, claimed_assertions);
        all_output_hints.push(sdmul.clone());
        f_acc = sdmul;

        // SS2
        let leval = wrap_hint_add_eval_mul_for_fixed_Qs(all_output_hints.len(), &p2x, &p2y, &p3x, &p3y, t2, t3, pubs.q2, pubs.q3, ate);
        compare(&leval.output, claimed_assertions);
        all_output_hints.push(leval.clone());
        let le: ElemSparseEval = leval.output.into();
        (t2, t3) = (le.t2, le.t3);

        // DD5 DD6
        let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &leval);
        compare(&dmul0.output, claimed_assertions);
        all_output_hints.push(dmul0);

        let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &leval);
        compare(&dmul1.output, claimed_assertions);
        all_output_hints.push(dmul1.clone());
        f_acc = dmul1;
    }

    // POST MILLER
    // f1 = frob1
    let cp = wrap_hints_frob_fp12(all_output_hints.len(), &gcinv, 1);
    compare(&cp.output, claimed_assertions);
    all_output_hints.push(cp.clone());

    // f2 = frob2
    let cp2 = wrap_hints_frob_fp12(all_output_hints.len(), &c, 2);
    compare(&cp2.output, claimed_assertions);
    all_output_hints.push(cp2.clone());
    
    // f3 = frob3
    let cp3 = wrap_hints_frob_fp12(all_output_hints.len(), &gcinv, 3);
    compare(&cp3.output, claimed_assertions);
    all_output_hints.push(cp3.clone());
    
    // f_acc = f_acc * f1
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &cp);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &cp);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;

    // f_acc = f_acc * f2
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &cp2);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &cp2);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;


    // f_acc = f_acc * f3
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &cp3);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &cp3);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;

    // f_acc = f_acc * s
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &s);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &s);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;

    // add op Add1
    let addf = wrap_hint_point_add_with_frob(all_output_hints.len(), &t4, &p4x, &p4y, &q4xc0, &q4xc1, &q4yc0, &q4yc1, 1);
    compare(&addf.output, claimed_assertions);
    all_output_hints.push(addf.clone());
    t4 = addf; 

    // SD
    let sdmul = wrap_hint_sparse_dense_mul(all_output_hints.len(), &f_acc, &t4, false);
    compare(&sdmul.output, claimed_assertions);
    all_output_hints.push(sdmul.clone());
    f_acc = sdmul;

    // sparse eval
    let leval = wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(all_output_hints.len(), &p2x, &p2y, &p3x, &p3y, t2, t3, pubs.q2, pubs.q3, 1);
    compare(&leval.output, claimed_assertions);
    all_output_hints.push(leval.clone());
    let le: ElemSparseEval = leval.output.into();
    (t2, t3) = (le.t2, le.t3);

    // dense_dense_mul
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &leval);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &leval);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;

    // add op Add2
    let addf = wrap_hint_point_add_with_frob(all_output_hints.len(), &t4, &p4x, &p4y, &q4xc0, &q4xc1, &q4yc0, &q4yc1, -1);
    compare(&addf.output, claimed_assertions);
    all_output_hints.push(addf.clone());
    t4 = addf; 

    // SD
    let sdmul = wrap_hint_sparse_dense_mul(all_output_hints.len(), &f_acc, &t4, false);
    compare(&sdmul.output, claimed_assertions);
    all_output_hints.push(sdmul.clone());
    f_acc = sdmul;

    // sparse eval
    let leval = wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(all_output_hints.len(), &p2x, &p2y, &p3x, &p3y, t2, t3, pubs.q2, pubs.q3, -1);
    compare(&leval.output, claimed_assertions);
    all_output_hints.push(leval.clone());
    let le: ElemSparseEval = leval.output.into();
    (t2, t3) = (le.t2, le.t3);


    // dense_dense_mul
    let dmul0 = wrap_hints_dense_dense_mul0(all_output_hints.len(), &f_acc, &leval);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(all_output_hints.len(), &f_acc, &leval);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;


    // mul0_by_const is identity
    let dmul0 = wrap_hints_dense_dense_mul0_by_constant(all_output_hints.len(), &f_acc, pubs.fixed_acc);
    compare(&dmul0.output, claimed_assertions);
    all_output_hints.push(dmul0);
    

    // mul1_by_const is identity
    let dmul1 = wrap_hints_dense_dense_mul1_by_constant(all_output_hints.len(), &f_acc, pubs.fixed_acc);
    compare(&dmul1.output, claimed_assertions);
    all_output_hints.push(dmul1.clone());
    f_acc = dmul1;
    
    let result: ElemFp12Acc = f_acc.output.into();
    assert_eq!(result.f, ark_bn254::Fq12::ONE);

    println!("segments len {}", all_output_hints.len());

}

pub(crate) fn hint_to_data(segments: Vec<Segment>) -> Assertions {
    let mut vs: Vec<[u8; 64]> = vec![];
    for v in segments {
        let x = match v.output {
            Element::G2Acc(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::FieldElem(f) => extern_fq_to_nibbles(f),
            Element::MSMG1(r) => r.out(),
            Element::ScalarElem(r) => extern_fr_to_nibbles(r),
            Element::SparseEval(r) => r.out(),
            Element::HashBytes(r) => r,
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

type Intermediates = (
    Vec<ark_bn254::Fq>,
    Vec<HashBytes>,
);

fn get_proof(asserts: &TypedAssertions) -> EvalIns { // EvalIns
    let numfqs = asserts.1;
    let p4 = ark_bn254::G1Affine::new_unchecked(numfqs[1], numfqs[0]);
    let p3 = ark_bn254::G1Affine::new_unchecked(numfqs[3], numfqs[2]);
    let p2 = ark_bn254::G1Affine::new_unchecked(numfqs[5], numfqs[4]);
    let skip = 6; // px, pys -- not part of eval ins
    let next = 6;
    let step = next + skip;
    let c = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+11], numfqs[step+10]),
            ark_bn254::Fq2::new(numfqs[step+9], numfqs[step+8]),
            ark_bn254::Fq2::new(numfqs[step+7], numfqs[step+6]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+5], numfqs[step+4]),
            ark_bn254::Fq2::new(numfqs[step+3], numfqs[step+2]),
            ark_bn254::Fq2::new(numfqs[step+1], numfqs[step+0]),
        ),
    );
    let step = step + 12;
    let s = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+11], numfqs[step+10]),
            ark_bn254::Fq2::new(numfqs[step+9], numfqs[step+8]),
            ark_bn254::Fq2::new(numfqs[step+7], numfqs[step+6]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+5], numfqs[step+4]),
            ark_bn254::Fq2::new(numfqs[step+3], numfqs[step+2]),
            ark_bn254::Fq2::new(numfqs[step+1], numfqs[step+0]),
        ),
    );

    let step = step + 12;
    let q4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(numfqs[step + 3], numfqs[step + 2]), ark_bn254::Fq2::new(numfqs[step + 1], numfqs[step + 0]));

    let eval_ins: EvalIns = EvalIns { p2, p3, p4, q4, c, s, ks: asserts.0.to_vec() };
    eval_ins
}

fn get_intermediates(asserts: &TypedAssertions) -> Intermediates { // Intermediates
    let mut fqs = asserts.1[6..12].to_vec();
    fqs.reverse();
    let mut hashes= asserts.2.to_vec();
    hashes.reverse();
    (fqs, hashes)
}

fn get_assertions(signed_asserts: Signatures) -> TypedAssertions {
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

fn get_pubs(vk: &ark_groth16::VerifyingKey<Bn254>) -> Pubs {
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

pub fn validate(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    inpubkeys: PublicKeys,
) -> Assertions {
    let mut pubkeys: Vec<WOTSPubKey> = vec![];
    for i in 0..NUM_PUBS {
        pubkeys.push(WOTSPubKey::P256(inpubkeys.0[i]));
    }
    for i in 0..inpubkeys.1.len() {
        pubkeys.push(WOTSPubKey::P256(inpubkeys.1[i]));
    }
    for i in 0..inpubkeys.2.len() {
        pubkeys.push(WOTSPubKey::P160(inpubkeys.2[i]));
    }

    let asserts = get_assertions(signed_asserts);
    let eval_ins = get_proof(&asserts);
    let intermediates = get_intermediates(&asserts);

    let mut hout: Vec<Segment> = vec![];
    groth16(&mut hout, eval_ins, get_pubs(vk), &mut Some(intermediates));
    hint_to_data(hout)
}
