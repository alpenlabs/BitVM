use std::collections::HashMap;

use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field};

use super::{config::ATE_LOOP_COUNT, evaluate::EvalIns, hint_models::*, msm::{hint_hash_p, hint_msm, HintInMSM}, primitves::{extern_hash_fps, extern_hash_nibbles}, taps::{self, hint_add_eval_mul_for_fixed_Qs_with_frob, hint_hash_c, hint_hash_c2, hint_init_T4, hint_point_add_with_frob, hints_frob_fp12, hints_precompute_Px, hints_precompute_Py, HashBytes, Sig}, taps_mul::{self, hint_sparse_dense_mul, hints_dense_dense_mul0, hints_dense_dense_mul0_by_constant, hints_dense_dense_mul0_by_hash, hints_dense_dense_mul1, hints_dense_dense_mul1_by_constant, hints_dense_dense_mul1_by_hash, HintInDenseMulByHash0, HintInDenseMulByHash1}};


fn msm(vky0: ark_bn254::G1Affine, vky: Vec<ark_bn254::G1Affine>, scalars: Vec<ark_bn254::Fr>, gp3: G1Affine)  {
    let mut segments = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let acc = ark_bn254::G1Affine::identity();
    let (temp, _, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: acc, scalars: scalars.clone() }, 0, vky.clone());
    let mut hout_msm = temp;
    segments.push(hout_msm.clone());
    for i in 1..32 {
        let (temp, _, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: hout_msm.t, scalars: scalars.clone() }, i, vky.clone());
        hout_msm = temp;
        segments.push(hout_msm.clone());
    }
    // send off to get signed
    let hint_in = HintInHashP { rx: gp3.x, ry: gp3.y, tx: hout_msm.t.x, qx: vky0.x, ty: hout_msm.t.y, qy: vky0.y };
    // validate gp3 = t + q
    let (h, _, _) = hint_hash_p(sig, (0, false), vec![(1, false), (2, true), (3, true)], hint_in);
}

struct Pubs {
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    fixed_acc: ark_bn254::Fq12,
    ks_vks: Vec<ark_bn254::G1Affine>,
    vky0: ark_bn254::G1Affine,
}


fn groth16(eval_ins: EvalIns, pubs: Pubs) {
    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;
    let pub_scalars = eval_ins.ks;

    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    // groth16 proof

    let (gp3x, gp3y) = (eval_ins.p3.x, eval_ins.p3.y); // 2, 3, 4
    msm(vky0, vky, pub_scalars, G1Affine::new_unchecked(gp3x, gp3y));

    // pre miller checks

    let gc: HintOutGrothC = HintOutGrothC { c: eval_ins.c, chash: extern_hash_fps(vec![
        eval_ins.c.c0.c0.c0, eval_ins.c.c0.c0.c1, eval_ins.c.c0.c1.c0, eval_ins.c.c0.c1.c1, eval_ins.c.c0.c2.c0, eval_ins.c.c0.c2.c1, eval_ins.c.c1.c0.c0,
        eval_ins.c.c1.c0.c1, eval_ins.c.c1.c1.c0, eval_ins.c.c1.c1.c1, eval_ins.c.c1.c2.c0, eval_ins.c.c1.c2.c1,
    ], true) };

    let gs: HintOutGrothC = HintOutGrothC { c: eval_ins.s, chash: extern_hash_fps(vec![
        eval_ins.s.c0.c0.c0, eval_ins.s.c0.c0.c1, eval_ins.s.c0.c1.c0, eval_ins.s.c0.c1.c1, eval_ins.s.c0.c2.c0, eval_ins.s.c0.c2.c1, eval_ins.s.c1.c0.c0,
        eval_ins.s.c1.c0.c1, eval_ins.s.c1.c1.c0, eval_ins.s.c1.c1.c1, eval_ins.s.c1.c2.c0, eval_ins.s.c1.c2.c1,
    ], true) };

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

    let (gp4y, gp4x) = (eval_ins.p4.y, eval_ins.p4.x);
    let (gp2x, gp2y) = (eval_ins.p2.y, eval_ins.p2.x); // 2, 3, 4
    let q4 = eval_ins.q4;
    
    let (p4y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp4y });
    let (p4x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp4x, gp4y) });
    let (p3y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp3y });
    let (p3x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp3x, gp3y) });
    let (p2y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp2y });
    let (p2x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: G1Affine::new_unchecked(gp2x, gp2y) });
    let p2 = G1Affine::new_unchecked(p2x, p2y);
    let p3 = G1Affine::new_unchecked(p3x, p3y);
    let p4 = G1Affine::new_unchecked(p4x, p4y);
    
    let (c, _, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), HintInHashC { c: gc.c, hashc: gc.chash });
    let (s, _, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), HintInHashC { c: gs.c, hashc: gs.chash });

    let (c2, _, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], HintInHashC { c: c.c, hashc: c.hash_out });
    let _ = hints_dense_dense_mul0_by_hash(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMulByHash0 {a: c2.c, bhash: gcinv.chash});
    let _ = hints_dense_dense_mul1_by_hash(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMulByHash1 {a: c2.c, bhash: gcinv.chash});

    let (cinv2, _, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], HintInHashC { c: gcinv.c, hashc: gcinv.chash });
    let (tmpt4, _, _) = hint_init_T4(sig, (0, false), vec![(1, true), (2, true), (3, true), (4, true)], HintInInitT4 { t4: q4 }); 
    let mut t4 = (tmpt4.t4, (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO), (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // FIXME: hint_init_T4 and its preimage here donot match
    let (q2, q3) = (pubs.q2, pubs.q3);
    let (mut t2, mut t3) = (q2, q3);

    // miller loop
    let mut f_acc = (cinv2.c, cinv2.hash_out);

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let ate = ATE_LOOP_COUNT[j-1];
        // Sqr
        let (sq, _, _) = taps_mul::hint_squaring(sig, (0, false), vec![(1, false)], HintInSquaring { a: f_acc.0, ahash: f_acc.1 });
        f_acc = (sq.b, sq.bhash);

        // Dbl, SD1
        if ate == 0 {
            let (dbl, _, _) = taps::hint_point_dbl(sig, (0, false), vec![], HintInDouble { t: t4.0, p: p4, hash_le_aux: extern_hash_fps(vec![t4.2.0.c0, t4.2.0.c1, t4.2.1.c0, t4.2.1.c1], true) });
            t4 = (dbl.t, dbl.dbl_le, t4.2);

            let (tmp, _, _) = taps_mul::hint_sparse_dense_mul(sig, (0, false), vec![], HintInSparseDenseMul { a: f_acc.0, le0: t4.1.0, le1: t4.1.1, hash_other_le: extern_hash_fps(vec![t4.2.0.c0, t4.2.0.c1, t4.2.1.c0, t4.2.1.c1], true), hash_aux_T: extern_hash_fps(vec![t4.0.x.c0, t4.0.x.c1, t4.0.y.c0, t4.0.y.c1], true) },  ate == 0);
            f_acc = (tmp.f, tmp.hash_out);
        } else { 
            let (dbladd, _, _) = taps::hint_point_ops(sig, (0, false), vec![], HintInDblAdd { t: t4.0, p: p4, q: q4, hash_le_aux: todo!() }, ate);
            t4 = (dbladd.t, dbladd.dbl_le, dbladd.add_le);

            let (tmp, _, _) = taps_mul::hint_sparse_dense_mul(sig, (0, false), vec![], HintInSparseDenseMul { a: f_acc.0, le0: t4.2.0, le1: t4.2.1, hash_other_le: todo!(), hash_aux_T: todo!() },  ate == 0);
            f_acc = (tmp.f, tmp.hash_out);
        }

        // SS1
        let (leval, _, _) = taps::hint_double_eval_mul_for_fixed_Qs(sig, (0, false), vec![], HintInSparseDbl { t2, t3, p2, p3 });
        (t2, t3) = (leval.t2, leval.t3);
        // DD1
        let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: leval.f });
        // DD2
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: leval.f });
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
        let (_, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: ctemp });
        // DD4
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: ctemp });
        f_acc = (dmul1.c, dmul1.hash_out);

        // SD2
        let (temp, _, _) = taps_mul::hint_sparse_dense_mul(sig, (0, false), vec![], HintInSparseDenseMul { a: f_acc.0, le0: t4.2.0, le1: t4.2.1, hash_other_le: todo!(), hash_aux_T: todo!() },  ate == 0);
        f_acc = (temp.f, temp.hash_out);

        // SS2
        let (leval, _, _) = taps::hint_add_eval_mul_for_fixed_Qs(sig, (0, false), vec![], HintInSparseAdd { t2, t3, p2, p3, q2, q3 }, ate);
        // DD5
        let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: leval.f });
        // DD6
        let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: leval.f });
        f_acc = (dmul1.c, dmul1.hash_out);
    }

    // post miller
    // f1 = frob1
    let (cp, _, _) = hints_frob_fp12(sig, (0, false), vec![], HintInFrobFp12 { f: gcinv.c }, 1);
    // f2 = frob2
    let (cp2, _, _) = hints_frob_fp12(sig, (0, false), vec![], HintInFrobFp12 { f: c.c }, 2);
    // f3 = frob3
    let (cp3, _, _) = hints_frob_fp12(sig, (0, false), vec![], HintInFrobFp12 { f: gcinv.c }, 3);


    // f_acc = f_acc * f1
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b:  cp.f});
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b:  cp.f});
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * f2
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b:  cp2.f});
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b:  cp2.f});
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * f3
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b:  cp3.f});
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b:  cp3.f});
    f_acc = (dmul1.c, dmul1.hash_out);

    // f_acc = f_acc * s
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b:  s.c});
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b:  s.c});
    f_acc = (dmul1.c, dmul1.hash_out);

    // add op Add1
    let (temp, _, _) = hint_point_add_with_frob(sig, (0, false), vec![], HintInAdd { t: t4.0, p: p4, q: q4, hash_le_aux: todo!() }, 1);
    t4 = (temp.t, t4.1, temp.add_le);
    // SD
    let (temp, _, _) = hint_sparse_dense_mul(sig, (0, false), vec![], HintInSparseDenseMul {  a: f_acc.0, le0: t4.2.0, le1: t4.2.1, hash_other_le: todo!(), hash_aux_T: todo!() }, false);
    f_acc = (temp.f, temp.hash_out);

    // sparse eval
    let (le, _, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(sig, (0, false), vec![], HintInSparseAdd { t2, t3, p2, p3, q2, q3 }, 1);
    // dense_dense_mul
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: le.f });
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: le.f });
    f_acc = (dmul1.c, dmul1.hash_out);

    // add op Add2
    let (temp, _, _) = hint_point_add_with_frob(sig, (0, false), vec![], HintInAdd { t: t4.0, p: p4, q: q4, hash_le_aux: todo!() }, -1);
    t4 = (temp.t, t4.1, temp.add_le);
    // SD
    let (temp, _, _) = hint_sparse_dense_mul(sig, (0, false), vec![], HintInSparseDenseMul {  a: f_acc.0, le0: t4.2.0, le1: t4.2.1, hash_other_le: todo!(), hash_aux_T: todo!() }, false);
    f_acc = (temp.f, temp.hash_out);

    // sparse eval
    let (le, _, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(sig, (0, false), vec![], todo!(), -1);
    // dense_dense_mul
    let (dmul0, _, _) = hints_dense_dense_mul0(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: le.f });
    let (dmul1, _, _) = hints_dense_dense_mul1(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: le.f });
    f_acc = (dmul1.c, dmul1.hash_out);

    // mul0_by_const is identity
    hints_dense_dense_mul0_by_constant(sig, (0, false), vec![], HintInDenseMul0 { a: f_acc.0, b: le.f });
    // mul1_by_const is identity
    hints_dense_dense_mul1_by_constant(sig, (0, false), vec![], HintInDenseMul1 { a: f_acc.0, b: le.f });
}

// name;ID;Deps
// Sqr;S1;f;
// Dbl;S2;P4,Q4,T4;
// SD1;S3;S1,S2;
// SS1;S4;P3,P2;
// DD1;S5;S3,S4;
// DD2;S6;S3,S4,S5;
// DD3;S7;S6,c;
// DD4;S8;S6,c,S7;
// SD2;S9;S8,S2;
// SS2;S10;P3,P2;
// DD5;S11;S9,S10;
// DD6;S12;S9,S10,S11;