
use crate::treepp;

use super::{hint_models::Element};

pub type SegmentID = usize;
pub type SegmentOutputType = bool;

#[derive(Debug, Clone)]
pub struct Segment {
    pub id: SegmentID,
    pub output_type: SegmentOutputType, // is field
    pub inputs: Vec<(SegmentID, SegmentOutputType)>,   
    pub output: Element,
    pub hint_script: treepp::Script,
    pub scr_type: ScriptType,
}

#[derive(Debug, Clone, Copy)]
pub enum ScriptType {
    MSM,

    PreMillerInitT4,
    PreMillerPrecomputePy,
    PreMillerPrecomputePx,
    PreMillerHashC,
    PreMillerHashC2,
    PreMillerDenseDenseMulByHash0,
    PreMillerDenseDenseMulByHash1,
    PreMillerHashP,

    MillerSquaring,
    MillerDoubleAdd(i8),
    MillerDouble,
    MillerSparseDenseMul,
    MillerSparseSparseDbl((ark_bn254::G2Affine, ark_bn254::G2Affine)),
    MillerDenseDenseMul0(),
    MillerDenseDenseMul1(),
    MillerSparseSparseAdd(([ark_bn254::G2Affine; 4], i8)),

    PostMillerFrobFp12(u8),
    PostMillerDenseDenseMul0(bool),
    PostMillerDenseDenseMul1(bool),
    PostMillerAddWithFrob(i8),
    PostMillerSparseDenseMul,
    PostMillerSparseAddWithFrob(([ark_bn254::G2Affine;4], i8)),
    PostMillerDenseDenseMulByConst0((bool, ark_bn254::Fq12)),
    PostMillerDenseDenseMulByConst1((bool, ark_bn254::Fq12)),
}


use std::collections::HashMap;

use ark_ff::{AdditiveGroup, Field};

use super::{hint_models::*, msm::{hint_hash_p, hint_msm}, primitves::extern_hash_fps,  taps::*, taps_mul::*};


fn wrap_hint_msm(
    segment_id: usize,
    prev_msm: Option<Segment>,
    scalars: Vec<Segment>,
    msm_chain_index: usize,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];

    let mut acc = ark_bn254::G1Affine::identity();
    if prev_msm.is_some() {
        let prev_msm = prev_msm.unwrap();
        acc = prev_msm.output.into();
        input_segment_info.push((prev_msm.id, prev_msm.output_type));
    }

    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .map(|f| {
        input_segment_info.push((f.id, f.output_type));
        f.output.into()
    })
    .collect();

    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let (hout_msm, hint_script, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], acc, hint_scalars, msm_chain_index, pub_vky);

    Segment { id: segment_id, output_type: false, inputs: input_segment_info, output: Element::MSMG1(hout_msm), hint_script, scr_type: ScriptType::MSM }

}

fn wrap_hint_hash_p(
    segment_id: usize,
    hint_in_rx: Segment, hint_in_ry: Segment, hint_in_tx: Segment, hint_in_ty: Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {

    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    input_segment_info.push((hint_in_rx.id, hint_in_rx.output_type));
    input_segment_info.push((hint_in_ry.id, hint_in_ry.output_type));
    input_segment_info.push((hint_in_tx.id, hint_in_tx.output_type));
    input_segment_info.push((hint_in_ty.id, hint_in_ty.output_type));

    let (h, hint_script, _) = hint_hash_p(sig, (0, false), vec![(1, false), (2, true), (3, true)], hint_in_rx.output.into(), hint_in_ry.output.into(), hint_in_tx.output.into(), hint_in_ty.output.into(), pub_vky0);
    Segment { id: segment_id, output_type: false, inputs: input_segment_info, output: Element::HashBytes(h), hint_script, scr_type: ScriptType::PreMillerHashP }
}

fn wrap_hint_hash_c(    
    segment_id: usize,
    hint_in_c: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_c.id, hint_in_c.output_type));
    let (c, hint_script, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), hint_in_c.output.into());
    Segment { id:  segment_id, output_type: false, inputs: input_segment_info, output: Element::Fp12(c), hint_script, scr_type: ScriptType::PreMillerHashC }
}



fn wrap_hints_precompute_Px(
    segment_id: usize,
    hint_in_px: Segment, hint_in_py: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_px.id, hint_in_px.output_type));
    input_segment_info.push((hint_in_py.id, hint_in_py.output_type));

    let (p4x, hint_script, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], hint_in_px.output.into(), hint_in_py.output.into());
    Segment { id:  segment_id, output_type: true, inputs: input_segment_info, output: Element::FieldElem(p4x), hint_script, scr_type: ScriptType::PreMillerPrecomputePx }
}

fn wrap_hints_precompute_Py(
    segment_id: usize,
    hint_in_p: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_p.id, hint_in_p.output_type));

    let (p3y, hint_script, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], hint_in_p.output.into());
    Segment { id:  segment_id, output_type: true, inputs: input_segment_info, output: Element::FieldElem(p3y), hint_script, scr_type: ScriptType::PreMillerPrecomputePy }
}

fn wrap_hint_hash_c2(
    segment_id: usize,
    hint_in_c: Segment
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_c.id, hint_in_c.output_type));
    let (c2, hint_script, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], hint_in_c.output.into());
    Segment { id:  segment_id, output_type: false, inputs: input_segment_info, output: Element::Fp12(c2), hint_script, scr_type: ScriptType::PreMillerHashC2 }
}

fn wrap_hints_dense_dense_mul0_by_hash(
    segment_id: usize,
    hint_in_a: Segment, hint_in_bhash: Segment
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));
    input_segment_info.push((hint_in_bhash.id, hint_in_bhash.output_type));

    let (dmul0, hint_script, _) = hints_dense_dense_mul0_by_hash(sig, (0, false), vec![(1, false), (2, false)], hint_in_a.output.into(), hint_in_bhash.output.into());
    Segment { id:  segment_id, output_type: false, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerDenseDenseMulByHash0 }
}

fn wrap_hints_dense_dense_mul1_by_hash(
    segment_id: usize,
    hint_in_a: Segment, hint_in_bhash: Segment
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));
    input_segment_info.push((hint_in_bhash.id, hint_in_bhash.output_type));

    let (dmul1, hint_script, _) = hints_dense_dense_mul1_by_hash(sig, (0, false), vec![(1, false), (2, false)], hint_in_a.output.into(), hint_in_bhash.output.into());
    Segment { id:  segment_id, output_type: false, inputs: input_segment_info, output: Element::Fp12(dmul1), hint_script, scr_type: ScriptType::PreMillerDenseDenseMulByHash1 }
}

fn wrap_hint_init_T4(
    segment_id: usize,
    hint_in_q4_x_c0: Segment,
    hint_in_q4_x_c1: Segment,
    hint_in_q4_y_c0: Segment,
    hint_in_q4_y_c1: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
    ];

    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (tmpt4, hint_script, _) = hint_init_T4(
        sig,
        (0, false),
        vec![(1, true), (2, true), (3, true), (4, true)],
        q4_x_c0,
        q4_x_c1,
        q4_y_c0,
        q4_y_c1,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::G2Acc(tmpt4),
        hint_script,
        scr_type: ScriptType::PreMillerInitT4,
    }
}

fn wrap_hint_squaring(
    segment_id: usize,
    hint_in_a: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![(hint_in_a.id, hint_in_a.output_type)];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();

    let (sq, hint_script, _) = hint_squaring(
        sig,
        (0, false),
        vec![(1, false)],
        f_acc,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(sq),
        hint_script,
        scr_type: ScriptType::MillerSquaring,
    }
}

fn wrap_hint_point_dbl(
    segment_id: usize,
    hint_in_t4: Segment,
    hint_in_p4x: Segment,
    hint_in_p4y: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();

    let (dbl, hint_script, _) = hint_point_dbl(
        sig,
        (0, false),
        vec![(1, true), (2, true), (3, true)],
        t4,
        p4x,
        p4y,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::G2Acc(dbl),
        hint_script,
        scr_type: ScriptType::MillerDouble,
    }
}


fn wrap_hint_point_ops(
    segment_id: usize,
    hint_in_t4: Segment,
    hint_in_p4x: Segment,
    hint_in_p4y: Segment,
    hint_in_q4_x_c0: Segment,
    hint_in_q4_x_c1: Segment,
    hint_in_q4_y_c0: Segment,
    hint_in_q4_y_c1: Segment,
    ate: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),

        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();
    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (dbladd, hint_script, _) = hint_point_ops(
        sig,
        (0, false),
        (0..7).map(|i| (i + 1, true)).collect(),
        t4,
        p4x,
        p4y,
        q4_x_c0,
        q4_x_c1,
        q4_y_c0,
        q4_y_c1,
        ate,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::G2Acc(dbladd),
        hint_script,
        scr_type: ScriptType::MillerDoubleAdd(ate),
    }
}

fn wrap_hint_sparse_dense_mul(
    segment_id: usize,
    hint_in_a: Segment,
    hint_in_g: Segment,
    is_dbl_blk: bool,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_g.id, hint_in_g.output_type),
    ];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();
    let t4: ElemG2PointAcc = hint_in_g.output.into();

    let (temp, hint_script, _) = hint_sparse_dense_mul(
        sig,
        (0, false),
        vec![(1, false), (2, false)],
        f_acc,
        t4,
        is_dbl_blk,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(temp),
        hint_script,
        scr_type: ScriptType::MillerSparseDenseMul,
    }
}

fn wrap_hint_double_eval_mul_for_fixed_Qs(
    segment_id: usize,
    hint_in_p2x: Segment,
    hint_in_p2y: Segment,
    hint_in_p3x: Segment,
    hint_in_p3y: Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_p2x.id, hint_in_p2x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p3y.id, hint_in_p3y.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_double_eval_mul_for_fixed_Qs(
        sig,
        (0, false),
        (0..4).map(|i| (i + 1, true)).collect(),
        p2x,
        p2y,
        p3x,
        p3y,
        hint_in_t2,
        hint_in_t3,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::MillerSparseSparseDbl((hint_in_t2, hint_in_t3)),
    }
}

fn wrap_hints_dense_dense_mul0(
    segment_id: usize,
    hint_in_a: Segment,
    hint_in_b: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();

    let (dmul0, hint_script, _) = hints_dense_dense_mul0(
        sig,
        (0, false),
        vec![(1, false), (2, false)],
        a.clone(),
        b.clone(),
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(dmul0),
        hint_script,
        scr_type: ScriptType::MillerDenseDenseMul0(),
    }
}

fn wrap_hints_dense_dense_mul1(
    segment_id: usize,
    hint_in_a: Segment,
    hint_in_b: Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();

    let (dmul1, hint_script, _) = hints_dense_dense_mul1(
        sig,
        (0, false),
        vec![(1, false), (2, false), (3, false)],
        a.clone(),
        b.clone(),
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::MillerDenseDenseMul1(),
    }
}


fn wrap_hint_add_eval_mul_for_fixed_Qs(
    segment_id: usize,
    hint_in_p2x: Segment,
    hint_in_p2y: Segment,
    hint_in_p3x: Segment,
    hint_in_p3y: Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_p2x.id, hint_in_p2x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p3y.id, hint_in_p3y.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_add_eval_mul_for_fixed_Qs(
        sig,
        (0, false),
        (0..4).map(|i| (i + 1, true)).collect(),
        p2x,
        p2y,
        p3x,
        p3y,
        hint_in_t2,
        hint_in_t3,
        pub_q2,
        pub_q3,
        ate,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::MillerSparseSparseAdd(([hint_in_t2, hint_in_t3, pub_q2, pub_q3], ate)),
    }
}

fn wrap_hints_frob_fp12(
    segment_id: usize,
    hint_in_f: Segment,
    power: usize,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![(hint_in_f.id, hint_in_f.output_type)];

    let f = hint_in_f.output.into();

    let (cp, hint_script, _) = hints_frob_fp12(
        sig,
        (0, false),
        vec![(1, false)],
        f,
        power,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(cp),
        hint_script,
        scr_type: ScriptType::PostMillerFrobFp12(power as u8),
    }
}

fn wrap_hint_point_add_with_frob(
    segment_id: usize,
    hint_in_t4: Segment,
    hint_in_p4x: Segment,
    hint_in_p4y: Segment,
    hint_in_q4_x_c0: Segment,
    hint_in_q4_x_c1: Segment,
    hint_in_q4_y_c0: Segment,
    hint_in_q4_y_c1: Segment,
    power: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();
    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (temp, hint_script, _) = hint_point_add_with_frob(
        sig,
        (0, false),
        (0..7).map(|i| (i + 1, true)).collect(),
        t4,
        p4x,
        p4y,
        q4_x_c0,
        q4_x_c1,
        q4_y_c0,
        q4_y_c1,
        power,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::G2Acc(temp),
        hint_script,
        scr_type: ScriptType::PostMillerAddWithFrob(power),
    }
}

fn wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(
    segment_id: usize,
    hint_in_p2x: Segment,
    hint_in_p2y: Segment,
    hint_in_p3x: Segment,
    hint_in_p3y: Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    power: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut input_segment_info = vec![
        (hint_in_p2x.id, hint_in_p2x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p3y.id, hint_in_p3y.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(
        sig,
        (0, false),
        (0..4).map(|i| (i + 1, true)).collect(),
        p2x,
        p2y,
        p3x,
        p3y,
        hint_in_t2,
        hint_in_t3,
        pub_q2,
        pub_q3,
        power,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([hint_in_t2, hint_in_t3, pub_q2, pub_q3], power)),
    }
}


fn wrap_hints_dense_dense_mul0_by_constant(
    segment_id: usize,
    hint_in_a: Segment,
    is_identity: bool,
    constant: ark_bn254::Fq12,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![(hint_in_a.id, hint_in_a.output_type)];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let fixedacc = ElemFp12Acc {
        f: constant,
        hash: extern_hash_fps(
            vec![
                constant.c0.c0.c0,
                constant.c0.c0.c1,
                constant.c0.c1.c0,
                constant.c0.c1.c1,
                constant.c0.c2.c0,
                constant.c0.c2.c1,
                constant.c1.c0.c0,
                constant.c1.c0.c1,
                constant.c1.c1.c0,
                constant.c1.c1.c1,
                constant.c1.c2.c0,
                constant.c1.c2.c1,
            ],
            false,
        ),
    };

    let (dmul0, hint_script, _) = hints_dense_dense_mul0_by_constant(
        sig,
        (0, false),
        vec![(1, false)],
        a.clone(),
        fixedacc,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(dmul0),
        hint_script,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst0((is_identity, constant)),
    }
}

fn wrap_hints_dense_dense_mul1_by_constant(
    segment_id: usize,
    hint_in_a: Segment,
    is_identity: bool,
    constant: ark_bn254::Fq12,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![(hint_in_a.id, hint_in_a.output_type)];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let fixedacc = ElemFp12Acc {
        f: constant,
        hash: extern_hash_fps(
            vec![
                constant.c0.c0.c0,
                constant.c0.c0.c1,
                constant.c0.c1.c0,
                constant.c0.c1.c1,
                constant.c0.c2.c0,
                constant.c0.c2.c1,
                constant.c1.c0.c0,
                constant.c1.c0.c1,
                constant.c1.c1.c0,
                constant.c1.c1.c1,
                constant.c1.c2.c0,
                constant.c1.c2.c1,
            ],
            false,
        ),
    };

    let (dmul1, hint_script, _) = hints_dense_dense_mul1_by_constant(
        sig,
        (0, false),
        vec![(1, false), (2, false)],
        a.clone(),
        fixedacc,
    );

    Segment {
        id: segment_id,
        output_type: false,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst1((is_identity, constant)),
    }
}