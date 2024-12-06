
use crate::treepp;

use super::{hint_models::Element, msm::{bitcom_hash_p, bitcom_msm, tap_hash_p, tap_msm}, wots::WOTSPubKey};

pub type SegmentID = u32;
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


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    NonDeterministic,
    MSM((usize, Vec<ark_bn254::G1Affine>)),

    PreMillerInitT4,
    PreMillerPrecomputePy,
    PreMillerPrecomputePx,
    PreMillerHashC,
    PreMillerHashC2,
    PreMillerDenseDenseMulByHash0,
    PreMillerDenseDenseMulByHash1,
    PreMillerHashP(ark_bn254::G1Affine),

    MillerSquaring,
    MillerDoubleAdd(i8),
    MillerDouble,
    SparseDenseMul(bool),
    MillerSparseSparseDbl((ark_bn254::G2Affine, ark_bn254::G2Affine)),
    DenseDenseMul0(),
    DenseDenseMul1(),
    MillerSparseSparseAdd(([ark_bn254::G2Affine; 4], i8)),

    PostMillerFrobFp12(u8),
    PostMillerAddWithFrob(i8),
    PostMillerSparseAddWithFrob(([ark_bn254::G2Affine;4], i8)),
    PostMillerDenseDenseMulByConst0(ark_bn254::Fq12),
    PostMillerDenseDenseMulByConst1(ark_bn254::Fq12),
}


use std::collections::HashMap;

use ark_ff::{AdditiveGroup, Field};
use bitcoin_script::script;

use super::{hint_models::*, msm::{hint_hash_p, hint_msm}, primitves::extern_hash_fps,  taps::*, taps_mul::*};


pub(crate) fn wrap_hint_msm(
    segment_id: usize,
    prev_msm: Option<Segment>,
    scalars: Vec<Segment>,
    msm_chain_index: usize,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;

    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .map(|f| {
        input_segment_info.push((f.id, f.output_type));
        f.output.into()
    })
    .collect();

    let mut acc = ark_bn254::G1Affine::identity();
    if prev_msm.is_some() {
        let prev_msm = prev_msm.unwrap();
        acc = prev_msm.output.into();
        input_segment_info.push((prev_msm.id, prev_msm.output_type));
    }

    let (hout_msm, hint_script, _) = hint_msm(sig, (segment_id as u32, output_type), input_segment_info.clone(), acc, hint_scalars, msm_chain_index, pub_vky.clone());
    input_segment_info.reverse();
    Segment { id: segment_id as u32 as u32, output_type, inputs: input_segment_info, output: Element::MSMG1(hout_msm), hint_script, scr_type: ScriptType::MSM((msm_chain_index, pub_vky)) }

}

pub(crate) fn wrap_hint_hash_p(
    segment_id: usize,
    hint_in_rx: &Segment, hint_in_ry: &Segment, hint_in_t: &Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {

    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    input_segment_info.push((hint_in_t.id, hint_in_t.output_type));
    input_segment_info.push((hint_in_ry.id, hint_in_ry.output_type));
    input_segment_info.push((hint_in_rx.id, hint_in_rx.output_type));

    let (h, hint_script, _) = hint_hash_p(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_rx.output.into(), hint_in_ry.output.into(), hint_in_t.output.into(), pub_vky0.clone());
    input_segment_info.reverse();
    Segment { id: segment_id as u32, output_type, inputs: input_segment_info, output: Element::HashBytes(h), hint_script, scr_type: ScriptType::PreMillerHashP(pub_vky0) }
}

pub(crate) fn wrap_hint_hash_c(    
    segment_id: usize,
    hint_in_c: Vec<Segment>,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let fqvec: Vec<ElemFq> = hint_in_c
    .iter()
    .map(|f| {
        f.output.into()
    })
    .collect();

    hint_in_c
    .iter()
    .rev()
    .for_each(|f| {
        input_segment_info.push((f.id, f.output_type));
    });

    let (c, hint_script, _) = hint_hash_c(sig, (segment_id as u32, output_type), input_segment_info.clone(), fqvec);
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c), hint_script, scr_type: ScriptType::PreMillerHashC }
}



pub(crate) fn wrap_hints_precompute_Px(
    segment_id: usize,
    hint_in_px: &Segment, hint_in_py: &Segment, hint_in_pdy: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = true;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_py.id, hint_in_py.output_type));
    input_segment_info.push((hint_in_px.id, hint_in_px.output_type));
    input_segment_info.push((hint_in_pdy.id, hint_in_pdy.output_type));

    let (p4x, hint_script, _) = hints_precompute_Px(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_px.output.into(), hint_in_py.output.into(), hint_in_pdy.output.into());
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p4x), hint_script, scr_type: ScriptType::PreMillerPrecomputePx }
}

pub(crate) fn wrap_hints_precompute_Py(
    segment_id: usize,
    hint_in_p: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = true;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_p.id, hint_in_p.output_type));

    let (p3y, hint_script, _) = hints_precompute_Py(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_p.output.into());
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p3y), hint_script, scr_type: ScriptType::PreMillerPrecomputePy }
}

pub(crate) fn wrap_hint_hash_c2(
    segment_id: usize,
    hint_in_c: &Segment
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_c.id, hint_in_c.output_type));

    let (c2, hint_script, _) = hint_hash_c2(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_c.output.into());
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c2), hint_script, scr_type: ScriptType::PreMillerHashC2 }
}

pub(crate) fn wrap_hints_dense_dense_mul0_by_hash(
    segment_id: usize,
    hint_in_a: &Segment, hint_in_bhash: &Segment
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));
    input_segment_info.push((hint_in_bhash.id, hint_in_bhash.output_type));

    let (dmul0, hint_script, _) = hints_dense_dense_mul0_by_hash(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_a.output.into(), hint_in_bhash.output.into());
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerDenseDenseMulByHash0 }
}

pub(crate) fn wrap_hints_dense_dense_mul1_by_hash(
    segment_id: usize,
    hint_in_a: &Segment, hint_in_bhash: &Segment, hint_in_c0: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));
    input_segment_info.push((hint_in_bhash.id, hint_in_bhash.output_type));
    input_segment_info.push((hint_in_c0.id, hint_in_c0.output_type));

    let (dmul1, hint_script, _) = hints_dense_dense_mul1_by_hash(sig, (segment_id as u32, output_type), input_segment_info.clone(), hint_in_a.output.into(), hint_in_bhash.output.into(), hint_in_c0.output.into());
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul1), hint_script, scr_type: ScriptType::PreMillerDenseDenseMulByHash1 }
}

pub(crate) fn wrap_hint_init_T4(
    segment_id: usize,
    hint_in_q4_x_c0: &Segment,
    hint_in_q4_x_c1: &Segment,
    hint_in_q4_y_c0: &Segment,
    hint_in_q4_y_c1: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
    ];

    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (tmpt4, hint_script, _) = hint_init_T4(
        sig,
        (segment_id as u32, output_type),
        input_segment_info.clone(),
        q4_x_c0,
        q4_x_c1,
        q4_y_c0,
        q4_y_c1,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::G2Acc(tmpt4),
        hint_script,
        scr_type: ScriptType::PreMillerInitT4,
    }
}

pub(crate) fn wrap_hint_squaring(
    segment_id: usize,
    hint_in_a: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![(hint_in_a.id, hint_in_a.output_type)];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();

    let (sq, hint_script, _) = hint_squaring(
        sig, 
        (segment_id as u32, output_type),
        input_segment_info.clone(),
        f_acc,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(sq),
        hint_script,
        scr_type: ScriptType::MillerSquaring,
    }
}

pub(crate) fn wrap_hint_point_dbl(
    segment_id: usize,
    hint_in_t4: &Segment,
    hint_in_p4x: &Segment,
    hint_in_p4y: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();

    let (dbl, hint_script, _) = hint_point_dbl(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        t4,
        p4x,
        p4y,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::G2Acc(dbl),
        hint_script,
        scr_type: ScriptType::MillerDouble,
    }
}


pub(crate) fn wrap_hint_point_ops(
    segment_id: usize,
    hint_in_t4: &Segment,
    hint_in_p4x: &Segment,
    hint_in_p4y: &Segment,
    hint_in_q4_x_c0: &Segment,
    hint_in_q4_x_c1: &Segment,
    hint_in_q4_y_c0: &Segment,
    hint_in_q4_y_c1: &Segment,
    ate: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();
    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (dbladd, hint_script, _) = hint_point_ops(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
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
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::G2Acc(dbladd),
        hint_script,
        scr_type: ScriptType::MillerDoubleAdd(ate),
    }
}

pub(crate) fn wrap_hint_sparse_dense_mul(
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_g: &Segment,
    is_dbl_blk: bool,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_g.id, hint_in_g.output_type),
    ];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();
    let t4: ElemG2PointAcc = hint_in_g.output.into();

    let (temp, hint_script, _) = hint_sparse_dense_mul(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        f_acc,
        t4,
        is_dbl_blk,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(temp),
        hint_script,
        scr_type: ScriptType::SparseDenseMul(is_dbl_blk),
    }
}

pub(crate) fn wrap_hint_double_eval_mul_for_fixed_Qs(
    segment_id: usize,
    hint_in_p2x: &Segment,
    hint_in_p2y: &Segment,
    hint_in_p3x: &Segment,
    hint_in_p3y: &Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_p3y.id, hint_in_p3y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p2x.id, hint_in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_double_eval_mul_for_fixed_Qs(
        sig,(segment_id as u32, output_type),
        input_segment_info.clone(),
        p2x,
        p2y,
        p3x,
        p3y,
        hint_in_t2,
        hint_in_t3,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::MillerSparseSparseDbl((hint_in_t2, hint_in_t3)),
    }
}

pub(crate) fn wrap_hints_dense_dense_mul0(
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();

    let output_type = false;
    let (dmul0, hint_script, _) = hints_dense_dense_mul0(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        b.clone(),
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul0),
        hint_script,
        scr_type: ScriptType::DenseDenseMul0(),
    }
}

pub(crate) fn wrap_hints_dense_dense_mul1(
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
    hint_in_c: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
        (hint_in_c.id, hint_in_c.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();
    let c: ElemFp12Acc = hint_in_c.output.into();

    let output_type = false;

    let (dmul1, hint_script, _) = hints_dense_dense_mul1(
        sig,
        (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        b.clone(),
        c.clone(),
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::DenseDenseMul1(),
    }
}


pub(crate) fn wrap_hints_dense_le_mul0(
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemSparseEval = hint_in_b.output.into();

    let output_type = false;

    let (dmul0, hint_script, _) = hints_dense_dense_mul0(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        b.f.clone(),
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul0),
        hint_script,
        scr_type: ScriptType::DenseDenseMul0(),
    }
}

pub(crate) fn wrap_hints_dense_le_mul1(
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
    hint_in_c: &Segment,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
        (hint_in_c.id, hint_in_c.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemSparseEval = hint_in_b.output.into();
    let c: ElemFp12Acc = hint_in_c.output.into();

    let output_type = false;

    let (dmul1, hint_script, _) = hints_dense_dense_mul1(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        b.f.clone(),
        c.clone(),
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::DenseDenseMul1(),
    }
}



pub(crate) fn wrap_hint_add_eval_mul_for_fixed_Qs(
    segment_id: usize,
    hint_in_p2x: &Segment,
    hint_in_p2y: &Segment,
    hint_in_p3x: &Segment,
    hint_in_p3y: &Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_p3y.id, hint_in_p3y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p2x.id, hint_in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_add_eval_mul_for_fixed_Qs(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
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
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::MillerSparseSparseAdd(([hint_in_t2, hint_in_t3, pub_q2, pub_q3], ate)),
    }
}

pub(crate) fn wrap_hints_frob_fp12(
    segment_id: usize,
    hint_in_f: &Segment,
    power: usize,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![(hint_in_f.id, hint_in_f.output_type)];

    let f = hint_in_f.output.into();

    let output_type = false;

    let (cp, hint_script, _) = hints_frob_fp12(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        f,
        power,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(cp),
        hint_script,
        scr_type: ScriptType::PostMillerFrobFp12(power as u8),
    }
}

pub(crate) fn wrap_hint_point_add_with_frob(
    segment_id: usize,
    hint_in_t4: &Segment,
    hint_in_p4x: &Segment,
    hint_in_p4y: &Segment,
    hint_in_q4_x_c0: &Segment,
    hint_in_q4_x_c1: &Segment,
    hint_in_q4_y_c0: &Segment,
    hint_in_q4_y_c1: &Segment,
    power: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_q4_y_c1.id, hint_in_q4_y_c1.output_type),
        (hint_in_q4_y_c0.id, hint_in_q4_y_c0.output_type),
        (hint_in_q4_x_c1.id, hint_in_q4_x_c1.output_type),
        (hint_in_q4_x_c0.id, hint_in_q4_x_c0.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();
    let q4_x_c0: ark_bn254::Fq = hint_in_q4_x_c0.output.into();
    let q4_x_c1: ark_bn254::Fq = hint_in_q4_x_c1.output.into();
    let q4_y_c0: ark_bn254::Fq = hint_in_q4_y_c0.output.into();
    let q4_y_c1: ark_bn254::Fq = hint_in_q4_y_c1.output.into();

    let (temp, hint_script, _) = hint_point_add_with_frob(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
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
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::G2Acc(temp),
        hint_script,
        scr_type: ScriptType::PostMillerAddWithFrob(power),
    }
}

pub(crate) fn wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(
    segment_id: usize,
    hint_in_p2x: &Segment,
    hint_in_p2y: &Segment,
    hint_in_p3x: &Segment,
    hint_in_p3y: &Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    power: i8,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_p3y.id, hint_in_p3y.output_type),
        (hint_in_p3x.id, hint_in_p3x.output_type),
        (hint_in_p2y.id, hint_in_p2y.output_type),
        (hint_in_p2x.id, hint_in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = hint_in_p2x.output.into();
    let p2y: ark_bn254::Fq = hint_in_p2y.output.into();
    let p3x: ark_bn254::Fq = hint_in_p3x.output.into();
    let p3y: ark_bn254::Fq = hint_in_p3y.output.into();

    let (leval, hint_script, _) = hint_add_eval_mul_for_fixed_Qs_with_frob(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
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
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([hint_in_t2, hint_in_t3, pub_q2, pub_q3], power)),
    }
}


pub(crate) fn wrap_hints_dense_dense_mul0_by_constant(
    segment_id: usize,
    hint_in_a: &Segment,
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

    let output_type = false;


    let (dmul0, hint_script, _) = hints_dense_dense_mul0_by_constant(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        fixedacc,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul0),
        hint_script,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst0(constant),
    }
}

pub(crate) fn wrap_hints_dense_dense_mul1_by_constant(
    segment_id: usize,
    hint_in_a: &Segment, hint_in_c0: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_c0.id, hint_in_c0.output_type)
    ];

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

    let output_type = false;


    let (dmul1, hint_script, _) = hints_dense_dense_mul1_by_constant(
        sig, (segment_id as u32, output_type),
        input_segment_info.clone(),
        a.clone(),
        hint_in_c0.output.into(),
        fixedacc,
    );

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst1(constant),
    }
}

fn cached<F, T, R>(fun: F) -> impl FnMut(T) -> R
where
    F: Fn(T) -> R + 'static,
    R: Clone + 'static,
    T: Eq + std::hash::Hash + 'static + Clone,
{
    let mut cache: HashMap<T, R> = HashMap::new();
    let f = move |a| {
        let ret = if let Some(v) = cache.get(&a) {
            v.clone()
        } else {
            let ret = fun(a.clone());
            cache.insert(a, ret.clone());
            ret
        };
        ret
    };
    f
}
pub(crate) fn op_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {

    let mut tap_point_ops = cached(tap_point_ops);
    let mut tap_sparse_dense_mul = cached(tap_sparse_dense_mul);
    let mut tap_dense_dense_mul0_by_constant = cached(tap_dense_dense_mul0_by_constant);
    let mut tap_dense_dense_mul1_by_constant = cached(tap_dense_dense_mul1_by_constant);
    let mut tap_frob_fp12 = cached(tap_frob_fp12);
    let mut tap_point_add_with_frob = cached(tap_point_add_with_frob);
    let mut tap_hash_p = cached(tap_hash_p);
    let mut tap_msm = cached(|(a, b, c)| tap_msm(a, b, c ));
    let mut tap_double_eval_mul_for_fixed_Qs = cached(|(a, b)| tap_double_eval_mul_for_fixed_Qs(a, b));
    let mut tap_add_eval_mul_for_fixed_Qs = cached(|(a, b, c, d, e)| tap_add_eval_mul_for_fixed_Qs(a, b, c, d, e));
    let mut tap_add_eval_mul_for_fixed_Qs_with_frob = cached(|(a, b, c, d, e)| tap_add_eval_mul_for_fixed_Qs_with_frob(a, b, c, d, e));
    let tap_initT4 = tap_initT4();
    let tap_precompute_Py = tap_precompute_Py();
    let tap_precompute_Px = tap_precompute_Px();
    let tap_hash_c = tap_hash_c();
    let tap_hash_c2 = tap_hash_c2();
    let tap_dense_dense_mul0_by_hash = tap_dense_dense_mul0_by_hash();
    let tap_dense_dense_mul1_by_hash = tap_dense_dense_mul1_by_hash();
    let tap_squaring = tap_squaring();
    let tap_point_dbl = tap_point_dbl();
    let tap_dense_dense_mul0 = tap_dense_dense_mul0();
    let tap_dense_dense_mul1 = tap_dense_dense_mul1();

    let msm_window = 8;
    let mut op_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let scr_type = seg.scr_type.clone();

        match scr_type {
            ScriptType::NonDeterministic => {
                op_scripts.push(script!());
            },
            ScriptType::PreMillerInitT4 => {
                op_scripts.push(tap_initT4.clone());
            }
            ScriptType::PreMillerPrecomputePy => {
                op_scripts.push(tap_precompute_Py.clone());
            },
            ScriptType::PreMillerPrecomputePx => {
                op_scripts.push(tap_precompute_Px.clone());
            },
            ScriptType::PreMillerHashC => {
                op_scripts.push(tap_hash_c.clone());
            },
            ScriptType::PreMillerHashC2 => {
                op_scripts.push(tap_hash_c2.clone());
            },
            ScriptType::PreMillerDenseDenseMulByHash0 => {
                op_scripts.push(tap_dense_dense_mul0_by_hash.clone());
            },
            ScriptType::PreMillerDenseDenseMulByHash1 => {
                op_scripts.push(tap_dense_dense_mul1_by_hash.clone());
            },
            ScriptType::MillerSquaring => {
                op_scripts.push(tap_squaring.clone());
            },
            ScriptType::MillerDoubleAdd(a) => {
                op_scripts.push(tap_point_ops(a));
            },
            ScriptType::MillerDouble => {
                op_scripts.push(tap_point_dbl.clone());
            },
            ScriptType::SparseDenseMul(dbl_blk) => {
                op_scripts.push(tap_sparse_dense_mul(dbl_blk));
            },
            ScriptType::DenseDenseMul0() => {
                op_scripts.push(tap_dense_dense_mul0.clone());
            },
            ScriptType::DenseDenseMul1() => {
                op_scripts.push(tap_dense_dense_mul1.clone());
            },
            ScriptType::PostMillerDenseDenseMulByConst0(inp) => {
                op_scripts.push(tap_dense_dense_mul0_by_constant(inp));
            },
            ScriptType::PostMillerDenseDenseMulByConst1(inp) => {
                op_scripts.push(tap_dense_dense_mul1_by_constant(inp));
            },

            ScriptType::MSM(inp) => {
                op_scripts.push(tap_msm((msm_window, inp.0, inp.1 )));
            },
            ScriptType::PostMillerFrobFp12(power) => {
                op_scripts.push(tap_frob_fp12(power as usize));
            },
            ScriptType::PostMillerAddWithFrob(ate) => {
                op_scripts.push(tap_point_add_with_frob(ate));
            },
            ScriptType::PreMillerHashP(inp) => {
                op_scripts.push(tap_hash_p(inp));
            },
            ScriptType::MillerSparseSparseDbl(inp) => {
                op_scripts.push(tap_double_eval_mul_for_fixed_Qs((inp.0, inp.1)).0);
            },
            ScriptType::MillerSparseSparseAdd(inp) => {
                op_scripts.push(tap_add_eval_mul_for_fixed_Qs((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).0);
            },
            ScriptType::PostMillerSparseAddWithFrob(inp) => {
                op_scripts.push(tap_add_eval_mul_for_fixed_Qs_with_frob((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).0);
            },
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys: Vec<WOTSPubKey>) -> Vec<treepp::Script> {
    let pubkeys_map: HashMap<u32, WOTSPubKey> = pubkeys
        .into_iter()
        .enumerate()
        .map(|(i, pk)| (i as u32, pk))
        .collect();
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let sec_out = (seg.id as u32, seg.output_type);
        let mut sec_in: Vec<(u32, bool)> = seg.inputs.iter().map(|f| (f.0 as u32, f.1)).collect();
        match seg.scr_type {
            ScriptType::NonDeterministic => {
                bitcom_scripts.push(script!());
            },
            ScriptType::MSM(_) => {
                sec_in.reverse();
                bitcom_scripts.push(bitcom_msm(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerInitT4 => {
                bitcom_scripts.push(bitcom_initT4(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerPrecomputePy => {
                bitcom_scripts.push(bitcom_precompute_Py(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerPrecomputePx => {
                bitcom_scripts.push(bitcom_precompute_Px(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerHashC => {
                bitcom_scripts.push(bitcom_hash_c(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerHashC2 => {
                bitcom_scripts.push(bitcom_hash_c2(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerDenseDenseMulByHash0 => {
                bitcom_scripts.push(bitcom_dense_dense_mul0_by_hash(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerDenseDenseMulByHash1 => {
                bitcom_scripts.push(bitcom_dense_dense_mul1_by_hash(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PreMillerHashP(_) => {
                sec_in.reverse();
                bitcom_scripts.push(bitcom_hash_p(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::MillerSquaring => {
                bitcom_scripts.push(bitcom_squaring(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::MillerDoubleAdd(ate) => {
                bitcom_scripts.push(bitcom_point_ops(&pubkeys_map, sec_out, sec_in, ate));
            },
            ScriptType::MillerDouble => {
                bitcom_scripts.push(bitcom_point_dbl(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::SparseDenseMul(_) => {
                bitcom_scripts.push(bitcom_sparse_dense_mul(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::DenseDenseMul0() => {
                bitcom_scripts.push(bitcom_dense_dense_mul0(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::DenseDenseMul1() => {
                bitcom_scripts.push(bitcom_dense_dense_mul1(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PostMillerFrobFp12(_) => {
                bitcom_scripts.push(bitcom_frob_fp12(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PostMillerAddWithFrob(_) => {
                bitcom_scripts.push(bitcom_point_add_with_frob(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PostMillerDenseDenseMulByConst0(_) => {
                bitcom_scripts.push(bitcom_dense_dense_mul0_by_constant(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PostMillerDenseDenseMulByConst1(_) => {
                bitcom_scripts.push(bitcom_dense_dense_mul1_by_constant(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::MillerSparseSparseDbl(_) => {
                bitcom_scripts.push(bitcom_double_eval_mul_for_fixed_Qs(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::MillerSparseSparseAdd(_) => {
                bitcom_scripts.push(bitcom_add_eval_mul_for_fixed_Qs(&pubkeys_map, sec_out, sec_in));
            },
            ScriptType::PostMillerSparseAddWithFrob(_) => {
                bitcom_scripts.push(bitcom_add_eval_mul_for_fixed_Qs_with_frob(&pubkeys_map, sec_out, sec_in));
            },
        }
    }
    bitcom_scripts
}

