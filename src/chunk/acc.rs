use std::{collections::HashMap, ops::Neg};

use ark_bn254::{Bn254, G1Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};

use crate::groth16::g16::{Assertions, PublicKeys, Signatures, N_VERIFIER_FQS, N_VERIFIER_HASHES};

use super::{api::nib_to_byte_array, config::{ATE_LOOP_COUNT, NUM_PUBS, NUM_U160, NUM_U256}, evaluate::{extract_values_from_hints, EvalIns}, hint_models::*, msm::{hint_hash_p, hint_msm, HintInMSM}, primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles, extern_hash_fps, extern_hash_nibbles}, taps::{self, hint_add_eval_mul_for_fixed_Qs_with_frob, hint_hash_c, hint_hash_c2, hint_init_T4, hint_point_add_with_frob, hints_frob_fp12, hints_precompute_Px, hints_precompute_Py, HashBytes, Sig, SigData}, taps_mul::{self, hint_sparse_dense_mul, hints_dense_dense_mul0, hints_dense_dense_mul0_by_constant, hints_dense_dense_mul0_by_hash, hints_dense_dense_mul1, hints_dense_dense_mul1_by_constant, hints_dense_dense_mul1_by_hash, HintInDenseMulByHash0, HintInDenseMulByHash1}, wots::WOTSPubKey};


fn msm(vky0: ark_bn254::G1Affine, vky: Vec<ark_bn254::G1Affine>, scalars: Vec<ark_bn254::Fr>, gp3: G1Affine) -> Vec<HintOut> {
    let mut segments = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let acc = ark_bn254::G1Affine::identity();
    let (temp, _, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: acc, scalars: scalars.clone() }, 0, vky.clone());
    let mut hout_msm = temp;
    segments.push(HintOut::MSM(hout_msm.clone()));
    for i in 1..32 {
        let (temp, _, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: hout_msm.t, scalars: scalars.clone() }, i, vky.clone());
        hout_msm = temp;
        segments.push(HintOut::MSM(hout_msm.clone()));
    }
    // send off to get signed
    let hint_in = HintInHashP { rx: gp3.x, ry: gp3.y, tx: hout_msm.t.x, qx: vky0.x, ty: hout_msm.t.y, qy: vky0.y };
    // validate gp3 = t + q
    let (h, _, _) = hint_hash_p(sig, (0, false), vec![(1, false), (2, true), (3, true)], hint_in);
    segments.push(HintOut::HashBytes(h));
    segments
}

pub struct Pubs {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq12,
    pub ks_vks: Vec<ark_bn254::G1Affine>,
    pub vky0: ark_bn254::G1Affine,
}

struct t4acc {
    t4: ark_bn254::G2Affine,
    dbl_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
    add_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
}

impl t4acc {
    fn hash_le_aux(&self) -> HashBytes {
        if self.dbl_le.is_none() && self.add_le.is_none() {
            return [0u8; 64];
        } else if self.add_le.is_none() {
            let (dbl_le0, dbl_le1) = self.dbl_le.unwrap();
            let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
            let hash_add_le = [0u8; 64];
            let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
            return hash_le;            
        } else if self.dbl_le.is_none() {
            let hash_dbl_le = [0u8; 64];
            let (add_le0, add_le1) = self.add_le.unwrap();
            let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
            let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
            return hash_le;
        }
        let (dbl_le0, dbl_le1) = self.dbl_le.unwrap();
        let hash_dbl_le =
        extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let (add_le0, add_le1) = self.add_le.unwrap();
        let hash_add_le =
        extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        return hash_le;
    }

    fn hash_t(&self) -> HashBytes {
        let (new_tx, new_ty) = (self.t4.x, self.t4.y);
        extern_hash_fps(vec![new_tx.c0, new_tx.c1, new_ty.c0, new_ty.c1], true)
    }

    fn hash_other_le(&self, dbl: bool) -> [u8; 64] {
        if (dbl && self.add_le.is_none()) || (!dbl && self.dbl_le.is_none()) {
            return [0u8; 64];
        }
        let mut le = self.dbl_le.unwrap();
        if dbl {
            le = self.add_le.unwrap();
        }
        let (le0, le1) = le;
        let le = extern_hash_fps(vec![le0.c0, le0.c1, le1.c0, le1.c1], true);
        le
    }
}

pub fn groth16(eval_ins: EvalIns, pubs: Pubs) -> Assertions {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let mut all_output_hints: Vec<HintOut> = vec![];
    for k in eval_ins.ks.iter() {
        all_output_hints.push(HintOut::ScalarElem(*k));
    }

    all_output_hints.push(HintOut::FieldElem(eval_ins.p4.y));
    all_output_hints.push(HintOut::FieldElem(eval_ins.p4.x));
    all_output_hints.push(HintOut::FieldElem(eval_ins.p3.y));
    all_output_hints.push(HintOut::FieldElem(eval_ins.p3.x));
    all_output_hints.push(HintOut::FieldElem(eval_ins.p2.y));
    all_output_hints.push(HintOut::FieldElem(eval_ins.p2.x));
    let (gp4y, gp4x) = (eval_ins.p4.y, eval_ins.p4.x);
    let (gp3x, gp3y) = (eval_ins.p3.x, eval_ins.p3.y); // 2, 3, 4
    let (gp2y, gp2x) = (eval_ins.p2.y, eval_ins.p2.x); // 2, 3, 4
    let (p4y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp4y });
    all_output_hints.push(HintOut::FieldElem(p4y));
    let (p4x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp4x, gp4y) });
    all_output_hints.push(HintOut::FieldElem(p4x));
    let (p3y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp3y });
    all_output_hints.push(HintOut::FieldElem(p3y));
    let (p3x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp3x, gp3y) });
    all_output_hints.push(HintOut::FieldElem(p3x));
    let (p2y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp2y });
    all_output_hints.push(HintOut::FieldElem(p2y));
    let (p2x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp2x, gp2y) });
    all_output_hints.push(HintOut::FieldElem(p2x));
    
    for i in vec![
        eval_ins.c.c0.c0.c0, eval_ins.c.c0.c0.c1, eval_ins.c.c0.c1.c0, eval_ins.c.c0.c1.c1, eval_ins.c.c0.c2.c0, eval_ins.c.c0.c2.c1, eval_ins.c.c1.c0.c0,
        eval_ins.c.c1.c0.c1, eval_ins.c.c1.c1.c0, eval_ins.c.c1.c1.c1, eval_ins.c.c1.c2.c0, eval_ins.c.c1.c2.c1,
    ].iter().rev() {
        all_output_hints.push(HintOut::FieldElem(*i));
    }

    for i in vec![
        eval_ins.s.c0.c0.c0, eval_ins.s.c0.c0.c1, eval_ins.s.c0.c1.c0, eval_ins.s.c0.c1.c1, eval_ins.s.c0.c2.c0, eval_ins.s.c0.c2.c1, eval_ins.s.c1.c0.c0,
        eval_ins.s.c1.c0.c1, eval_ins.s.c1.c1.c0, eval_ins.s.c1.c1.c1, eval_ins.s.c1.c2.c0, eval_ins.s.c1.c2.c1,
    ].iter().rev() {
        all_output_hints.push(HintOut::FieldElem(*i));
    }

    all_output_hints.push(HintOut::FieldElem(eval_ins.q4.y.c1));
    all_output_hints.push(HintOut::FieldElem(eval_ins.q4.y.c0));
    all_output_hints.push(HintOut::FieldElem(eval_ins.q4.x.c1));
    all_output_hints.push(HintOut::FieldElem(eval_ins.q4.x.c0));
    
    let cvinv = eval_ins.c.inverse().unwrap();
    let gcinv: HintOutGrothC = HintOutGrothC { c: cvinv, chash: extern_hash_fps(
        vec![
            cvinv.c0.c0.c0,
            cvinv.c0.c0.c1,
            cvinv.c0.c1.c0,
            cvinv.c0.c1.c1,
            cvinv.c0.c2.c0,
            cvinv.c0.c2.c1,
            cvinv.c1.c0.c0,
            cvinv.c1.c0.c1,
            cvinv.c1.c1.c0,
            cvinv.c1.c1.c1,
            cvinv.c1.c2.c0,
            cvinv.c1.c2.c1,
        ],
        false,
    ) }; 
    all_output_hints.push(HintOut::GrothC(gcinv.clone()));


    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;
    let pub_scalars = eval_ins.ks;
    // groth16 proof
    let msm_hints = msm(vky0, vky, pub_scalars, G1Affine::new_unchecked(gp3x, gp3y));
    all_output_hints.extend_from_slice(&msm_hints);
    // pre miller checks

    let gc: HintOutGrothC = HintOutGrothC { c: eval_ins.c, chash: extern_hash_fps(vec![
        eval_ins.c.c0.c0.c0, eval_ins.c.c0.c0.c1, eval_ins.c.c0.c1.c0, eval_ins.c.c0.c1.c1, eval_ins.c.c0.c2.c0, eval_ins.c.c0.c2.c1, eval_ins.c.c1.c0.c0,
        eval_ins.c.c1.c0.c1, eval_ins.c.c1.c1.c0, eval_ins.c.c1.c1.c1, eval_ins.c.c1.c2.c0, eval_ins.c.c1.c2.c1,
    ], true) };

    let gs: HintOutGrothC = HintOutGrothC { c: eval_ins.s, chash: extern_hash_fps(vec![
        eval_ins.s.c0.c0.c0, eval_ins.s.c0.c0.c1, eval_ins.s.c0.c1.c0, eval_ins.s.c0.c1.c1, eval_ins.s.c0.c2.c0, eval_ins.s.c0.c2.c1, eval_ins.s.c1.c0.c0,
        eval_ins.s.c1.c0.c1, eval_ins.s.c1.c1.c0, eval_ins.s.c1.c1.c1, eval_ins.s.c1.c2.c0, eval_ins.s.c1.c2.c1,
    ], true) };



    let q4 = eval_ins.q4;
    

    let p2 = G1Affine::new_unchecked(p2x, p2y);
    let p3 = G1Affine::new_unchecked(p3x, p3y);
    let p4 = G1Affine::new_unchecked(p4x, p4y);
    
    let (c, _, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), HintInHashC { c: gc.c, hashc: gc.chash });
    all_output_hints.push(HintOut::HashC(c.clone()));
    let (s, _, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), HintInHashC { c: gs.c, hashc: gs.chash });
    all_output_hints.push(HintOut::HashC(s.clone()));

    let (c2, _, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], HintInHashC { c: c.c, hashc: c.hash_out });
    all_output_hints.push(HintOut::HashC(c2.clone()));
    let (dmul0, _, _) = hints_dense_dense_mul0_by_hash(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMulByHash0 {a: c2.c, bhash: gcinv.chash});
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1_by_hash(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMulByHash1 {a: c2.c, bhash: gcinv.chash});
    all_output_hints.push(HintOut::DenseMul1(dmul1));

    let (cinv2, _, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], HintInHashC { c: gcinv.c, hashc: gcinv.chash });
    all_output_hints.push(HintOut::HashC(cinv2.clone()));
    let (tmpt4, _, _) = hint_init_T4(sig, (0, false), vec![(1, true), (2, true), (3, true), (4, true)], HintInInitT4 { t4: q4 }); 
    all_output_hints.push(HintOut::InitT4(tmpt4.clone()));
    let mut t4 = t4acc {t4: tmpt4.t4, dbl_le: None, add_le: None};
    let (q2, q3) = (pubs.q2, pubs.q3);
    let (mut t2, mut t3) = (q2, q3);

    // miller loop
    let mut f_acc = (cinv2.c, cinv2.hash_out);

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let ate = ATE_LOOP_COUNT[j-1];
        // Sqr
        let (sq, _, _) = taps_mul::hint_squaring(sig, (0, false), vec![(1, false)], HintInSquaring { a: f_acc.0, ahash: f_acc.1 });
        all_output_hints.push(HintOut::Squaring(sq.clone()));
        f_acc = (sq.b, sq.bhash);

        // Dbl or DblAdd
        if ate == 0 {
            let (dbl, _, _) = taps::hint_point_dbl(sig, (0, false), vec![(1, true), (2, true), (3, true)], HintInDouble { t: t4.t4, p: p4, hash_le_aux: t4.hash_le_aux() });
            all_output_hints.push(HintOut::Double(dbl.clone()));
            t4 = t4acc {t4: dbl.t, dbl_le: Some(dbl.dbl_le), add_le: None}; 

        } else { 
            let (dbladd, _, _) = taps::hint_point_ops(sig, (0, false), (0..7).map(|i| (i+1, true)).collect(), HintInDblAdd { t: t4.t4, p: p4, q: q4, hash_le_aux: t4.hash_le_aux() }, ate);
            all_output_hints.push(HintOut::DblAdd(dbladd.clone()));
            t4 = t4acc {t4: dbladd.t, dbl_le: Some(dbladd.dbl_le), add_le: Some(dbladd.add_le)}; 
        }
        // SD1
        let (tmp, _, _) = taps_mul::hint_sparse_dense_mul(sig, (0, false), vec![(1, false), (2, false)], HintInSparseDenseMul { a: f_acc.0, le0: t4.dbl_le.unwrap().0, le1: t4.dbl_le.unwrap().1,hash_other_le: t4.hash_other_le(true), hash_aux_T: t4.hash_t() },  true);
        all_output_hints.push(HintOut::SparseDenseMul(tmp.clone()));
        f_acc = (tmp.f, tmp.hash_out);


        // SS1
        let (leval, _, _) = taps::hint_double_eval_mul_for_fixed_Qs(sig, (0, false), (0..4).map(|i| (i+1, true)).collect(), HintInSparseDbl { t2, t3, p2, p3 });
        all_output_hints.push(HintOut::SparseDbl(leval.clone()));
        (t2, t3) = (leval.t2, leval.t3);
        // DD1
        let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b: leval.f });
        all_output_hints.push(HintOut::DenseMul0(dmul0));
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b: leval.f });
        all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
        f_acc = (dmul1.c, dmul1.hash_out);

        if ate == 0 {
            continue;
        }

        // DD3
        // mul by cinv if ate == 1
        // let multiplier = c or c inv if ate == -1 or 1
        let ctemp = if ate == -1 {
            c.c
        } else {
            cvinv
        };
        let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b: ctemp });
        all_output_hints.push(HintOut::DenseMul0(dmul0));
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b: ctemp });
        all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
        f_acc = (dmul1.c, dmul1.hash_out);

        // SD2
        let (temp, _, _) = taps_mul::hint_sparse_dense_mul(sig, (0, false), vec![(1, false), (2, false)], HintInSparseDenseMul { a: f_acc.0, le0: t4.add_le.unwrap().0, le1: t4.add_le.unwrap().1,hash_other_le: t4.hash_other_le(false), hash_aux_T: t4.hash_t() },  false);
        all_output_hints.push(HintOut::SparseDenseMul(temp.clone()));
        f_acc = (temp.f, temp.hash_out);

        // SS2
        let (leval, _, _) = taps::hint_add_eval_mul_for_fixed_Qs(sig, (0, false), (0..4).map(|i| (i+1, true)).collect(), HintInSparseAdd { t2, t3, p2, p3, q2, q3 }, ate);
        all_output_hints.push(HintOut::SparseAdd(leval.clone()));
        (t2, t3) = (leval.t2, leval.t3);

        // DD5
        let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b: leval.f });
        all_output_hints.push(HintOut::DenseMul0(dmul0));
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b: leval.f });
        all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
        f_acc = (dmul1.c, dmul1.hash_out);
    }

    // post miller
    // f1 = frob1
    let (cp, _, _) = hints_frob_fp12(sig, (0, false), vec![(1, false)], HintInFrobFp12 { f: gcinv.c }, 1);
    all_output_hints.push(HintOut::FrobFp12(cp.clone()));
    // f2 = frob2
    let (cp2, _, _) = hints_frob_fp12(sig, (0, false), vec![(1, false)], HintInFrobFp12 { f: c.c }, 2);
    all_output_hints.push(HintOut::FrobFp12(cp2.clone()));
    
    // f3 = frob3
    let (cp3, _, _) = hints_frob_fp12(sig, (0, false), vec![(1, false)], HintInFrobFp12 { f: gcinv.c }, 3);
    all_output_hints.push(HintOut::FrobFp12(cp3.clone()));


    // f_acc = f_acc * f1
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b:  cp.f});
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b:  cp.f});
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * f2
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b:  cp2.f});
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b:  cp2.f});
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * f3
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b:  cp3.f});
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b:  cp3.f});
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * s
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b:  s.c});
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b:  s.c});
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // add op Add1
    let (temp, _, _) = hint_point_add_with_frob(sig, (0, false), (0..7).map(|i| (i+1, true)).collect(), HintInAdd { t: t4.t4, p: p4, q: q4, hash_le_aux: t4.hash_le_aux() }, 1);
    all_output_hints.push(HintOut::Add(temp.clone()));
    t4 = t4acc {t4: temp.t, dbl_le: None, add_le: Some(temp.add_le)}; 

    // SD
    let (temp, _, _) = hint_sparse_dense_mul(sig, (0, false), vec![(1, false), (2, false)], HintInSparseDenseMul {  a: f_acc.0, le0: t4.add_le.unwrap().0, le1: t4.add_le.unwrap().1, hash_other_le: t4.hash_other_le(false), hash_aux_T: t4.hash_t() }, false);
    all_output_hints.push(HintOut::SparseDenseMul(temp.clone()));
    f_acc = (temp.f, temp.hash_out);

    // sparse eval
    let (le, _, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(sig, (0, false), (0..4).map(|i| (i+1, true)).collect(), HintInSparseAdd { t2, t3, p2, p3, q2, q3 }, 1);
    all_output_hints.push(HintOut::SparseAdd(le.clone()));
    (t2, t3) = (le.t2, le.t3);
    // dense_dense_mul
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b: le.f });
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b: le.f });
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // add op Add2
    let (temp, _, _) = hint_point_add_with_frob(sig, (0, false), (0..7).map(|i| (i+1, true)).collect(), HintInAdd { t: t4.t4, p: p4, q: q4, hash_le_aux: t4.hash_le_aux() }, -1);
    all_output_hints.push(HintOut::Add(temp.clone()));
    t4 = t4acc {t4: temp.t, dbl_le: None, add_le: Some(temp.add_le)}; 

    // SD
    let (temp, _, _) = hint_sparse_dense_mul(sig, (0, false), vec![(1, false), (2, false)], HintInSparseDenseMul {  a: f_acc.0, le0: t4.add_le.unwrap().0, le1: t4.add_le.unwrap().1, hash_other_le: t4.hash_other_le(false), hash_aux_T: t4.hash_t() }, false);
    all_output_hints.push(HintOut::SparseDenseMul(temp.clone()));
    f_acc = (temp.f, temp.hash_out);

    // sparse eval
    let (le, _, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(sig, (0, false), (0..4).map(|i| (i+1, true)).collect(), HintInSparseAdd { t2, t3, p2, p3, q2, q3 }, -1);
    all_output_hints.push(HintOut::SparseAdd(le.clone()));
    (t2, t3) = (le.t2, le.t3);
    // dense_dense_mul
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul0 { a: f_acc.0, b: le.f });
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMul1 { a: f_acc.0, b: le.f });
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    f_acc = (dmul1.c, dmul1.hash_out);

    // mul0_by_const is identity
    let (dmul0, _, _) = hints_dense_dense_mul0_by_constant(sig, (0, false), vec![(1, false)], HintInDenseMul0 { a: f_acc.0, b: pubs.fixed_acc });
    all_output_hints.push(HintOut::DenseMul0(dmul0));
    // mul1_by_const is identity
    let (dmul1, _, _) = hints_dense_dense_mul1_by_constant(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMul1 { a: f_acc.0, b: pubs.fixed_acc });
    all_output_hints.push(HintOut::DenseMul1(dmul1.clone()));
    assert_eq!(dmul1.c, ark_bn254::Fq12::ONE);

    println!("segments len {}", all_output_hints.len());

    hint_to_data(all_output_hints)
}

fn hint_to_data(segments: Vec<HintOut>) -> Assertions {
    let mut vs: Vec<[u8; 64]> = vec![];
    for v in segments {
        let x = match v {
            HintOut::Add(r) => r.out(),
            HintOut::DblAdd(r) => r.out(),
            HintOut::DenseMul0(r) => r.out(),
            HintOut::DenseMul1(r) => r.out(),
            HintOut::Double(r) => r.out(),
            HintOut::FieldElem(f) => extern_fq_to_nibbles(f),
            HintOut::FrobFp12(f) => f.out(),
            HintOut::GrothC(r) => r.out(),
            HintOut::HashC(r) => r.out(),
            HintOut::InitT4(r) => r.out(),
            HintOut::MSM(r) => r.out(),
            HintOut::ScalarElem(r) => extern_fr_to_nibbles(r),
            HintOut::SparseAdd(r) => r.out(),
            HintOut::SparseDbl(r) => r.out(),
            HintOut::SparseDenseMul(r) => r.out(),
            HintOut::Squaring(r) => r.out(),
            HintOut::HashBytes(r) => r,
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


pub fn validate(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    inpubkeys: PublicKeys,
) -> Assertions {
    let mut sigcache: Vec<SigData> = vec![];
    for i in 0..NUM_PUBS {
        sigcache.push(SigData::Sig256(signed_asserts.0[i]));
    }
    for i in 0..N_VERIFIER_FQS {
        sigcache.push(SigData::Sig256(signed_asserts.1[i]));
    }
    for i in 0..N_VERIFIER_HASHES {
        sigcache.push(SigData::Sig160(signed_asserts.2[i]));
    }

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
    
    // let mut eval_ins: EvalIns = EvalIns { p2: (), p3: (), p4: (), q4: (), c: (), s: (), ks: () };
    
    let mut ks: Vec<ark_bn254::Fr> = vec![];
    for sc in sigcache[0..NUM_PUBS].to_vec() {
        if let SigData::Sig256(sc) = sc {
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
    }

    let mut numfqs: Vec<ark_bn254::Fq> = vec![];
    for sc in sigcache[NUM_PUBS..NUM_PUBS+NUM_U256].to_vec() {
        if let SigData::Sig256(sc) = sc {
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
    }

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

    let eval_ins: EvalIns = EvalIns { p2, p3, p4, q4, c, s, ks };

    groth16(eval_ins, pubs)
}
