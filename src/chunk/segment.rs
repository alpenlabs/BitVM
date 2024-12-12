
use crate::treepp;

use super::{hint_models::Element};

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
    PreMillerInv0,
    PreMillerInv1,
    PreMillerInv2,
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
    skip: bool,
    segment_id: usize,
    prev_msm: Option<Segment>,
    scalars: Vec<Segment>,
    msm_chain_index: usize,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
   // let sig = &mut Sig { msk: None, cache: HashMap::new() };
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
    input_segment_info.reverse();

    let (mut hout_msm, mut hint_script) = (ElemG1Point::mock(), script!());
    if !skip {
        (hout_msm, hint_script) = hint_msm(
            // sig, (segment_id as u32, output_type), input_segment_info.clone(), 
            acc, hint_scalars, msm_chain_index, pub_vky.clone());
    }
    Segment { id: segment_id as u32 as u32, output_type, inputs: input_segment_info, output: Element::MSMG1(hout_msm), hint_script, scr_type: ScriptType::MSM((msm_chain_index, pub_vky)) }

}

pub(crate) fn wrap_hint_hash_p(
    skip: bool,
    segment_id: usize,
    hint_in_rx: &Segment, hint_in_ry: &Segment, hint_in_t: &Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {

    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    //let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let output_type = false;
    input_segment_info.push((hint_in_t.id, hint_in_t.output_type));
    input_segment_info.push((hint_in_ry.id, hint_in_ry.output_type));
    input_segment_info.push((hint_in_rx.id, hint_in_rx.output_type));
    input_segment_info.reverse();

    let (mut h, mut hint_script) = ([0u8;64], script!());
    if !skip {
        (h, hint_script) = hint_hash_p(
             hint_in_rx.output.into(), hint_in_ry.output.into(), hint_in_t.output.into(), pub_vky0.clone());
    }
    Segment { id: segment_id as u32, output_type, inputs: input_segment_info, output: Element::HashBytes(h), hint_script, scr_type: ScriptType::PreMillerHashP(pub_vky0) }
}

pub(crate) fn wrap_hint_hash_c(  
    skip: bool,  
    segment_id: usize,
    hint_in_c: Vec<Segment>,
) -> Segment {
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

    let (mut c, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (c, hint_script) = hint_hash_c(
            // sig, (segment_id as u32, output_type), input_segment_info.clone(),
             fqvec);
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c), hint_script, scr_type: ScriptType::PreMillerHashC }
}



pub(crate) fn wrap_hints_precompute_Px(
    skip: bool,
    segment_id: usize,
    hint_in_px: &Segment, hint_in_py: &Segment, hint_in_pdy: &Segment,
) -> Segment {
    let output_type = true;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_py.id, hint_in_py.output_type));
    input_segment_info.push((hint_in_px.id, hint_in_px.output_type));
    input_segment_info.push((hint_in_pdy.id, hint_in_pdy.output_type));

    let (mut p4x, mut hint_script) = (ElemFq::mock(), script!());
    if !skip {
        (p4x, hint_script) = hints_precompute_Px(
            // sig, (segment_id as u32, output_type), input_segment_info.clone(), 
            hint_in_px.output.into(), hint_in_py.output.into(), hint_in_pdy.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p4x), hint_script, scr_type: ScriptType::PreMillerPrecomputePx }
}

pub(crate) fn wrap_hints_precompute_Py(
    skip: bool,
    segment_id: usize,
    hint_in_p: &Segment,
) -> Segment {
    let output_type = true;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_p.id, hint_in_p.output_type));

    let (mut p3y, mut hint_script) = (ElemFq::mock(), script!());
    if !skip {
        (p3y, hint_script) = hints_precompute_Py(
            // sig, (segment_id as u32, output_type), input_segment_info.clone(), 
            hint_in_p.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p3y), hint_script, scr_type: ScriptType::PreMillerPrecomputePy }
}

pub(crate) fn wrap_hint_hash_c2(
    skip: bool,
    segment_id: usize,
    hint_in_c: &Segment
) -> Segment {
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_c.id, hint_in_c.output_type));

    let (mut c2, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (c2, hint_script) = hint_hash_c2(hint_in_c.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c2), hint_script, scr_type: ScriptType::PreMillerHashC2 }
}

pub(crate) fn wrap_inv0(
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
) -> Segment {
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hint_inv0(hint_in_a.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv0 }
}

pub(crate) fn wrap_inv1(
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
) -> Segment {
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hint_inv1(hint_in_a.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv1 }
}

pub(crate) fn wrap_inv2(
    skip: bool,
    segment_id: usize,
    hint_in_t1: &Segment,
    hint_in_a: &Segment,
) -> Segment {
    let output_type = false;
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((hint_in_t1.id, hint_in_t1.output_type));
    input_segment_info.push((hint_in_a.id, hint_in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hint_inv2(hint_in_t1.output.into(), hint_in_a.output.into());
    }
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv2 }
}


pub(crate) fn wrap_hint_init_T4(
    skip: bool,
    segment_id: usize,
    hint_in_q4_x_c0: &Segment,
    hint_in_q4_x_c1: &Segment,
    hint_in_q4_y_c0: &Segment,
    hint_in_q4_y_c1: &Segment,
) -> Segment {
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

    let (mut tmpt4, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (tmpt4, hint_script) = hint_init_T4(
            q4_x_c0,
            q4_x_c1,
            q4_y_c0,
            q4_y_c1,
        );
    }
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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
) -> Segment {
    let output_type = false;
    let input_segment_info = vec![(hint_in_a.id, hint_in_a.output_type)];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();

    let (mut sq, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (sq, hint_script) = hint_squaring(
            // sig, 
            // (segment_id as u32, output_type),
            // input_segment_info.clone(),
            f_acc,
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_t4: &Segment,
    hint_in_p4x: &Segment,
    hint_in_p4y: &Segment,
) -> Segment {
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_t4.id, hint_in_t4.output_type),
        (hint_in_p4y.id, hint_in_p4y.output_type),
        (hint_in_p4x.id, hint_in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = hint_in_t4.output.into();
    let p4x: ark_bn254::Fq = hint_in_p4x.output.into();
    let p4y: ark_bn254::Fq = hint_in_p4y.output.into();

    let (mut dbl, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (dbl, hint_script) = hint_point_dbl(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            t4,
            p4x,
            p4y,
        );
    }


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
    skip: bool,
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

    let (mut dbladd, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (dbladd, hint_script) = hint_point_ops(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            t4,
            p4x,
            p4y,
            q4_x_c0,
            q4_x_c1,
            q4_y_c0,
            q4_y_c1,
            ate,
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_g: &Segment,
    is_dbl_blk: bool,
) -> Segment {
    let output_type = false;
    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_g.id, hint_in_g.output_type),
    ];

    let f_acc: ElemFp12Acc = hint_in_a.output.into();
    let t4: ElemG2PointAcc = hint_in_g.output.into();

    let (mut temp, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (temp, hint_script) = hint_sparse_dense_mul(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            f_acc,
            t4,
            is_dbl_blk,
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_p2x: &Segment,
    hint_in_p2y: &Segment,
    hint_in_p3x: &Segment,
    hint_in_p3y: &Segment,
    hint_in_t2: ark_bn254::G2Affine,
    hint_in_t3: ark_bn254::G2Affine,
) -> Segment {
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

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval, hint_script) = hint_double_eval_mul_for_fixed_Qs(
            // sig,(segment_id as u32, output_type),
            // input_segment_info.clone(),
            p2x,
            p2y,
            p3x,
            p3y,
            hint_in_t2,
            hint_in_t3,
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();

    let output_type = false;
    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hints_dense_dense_mul0(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            a.clone(),
            b.clone(),
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
    hint_in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
        (hint_in_c.id, hint_in_c.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemFp12Acc = hint_in_b.output.into();
    let c: ElemFp12Acc = hint_in_c.output.into();

    let output_type = false;

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1, hint_script) = hints_dense_dense_mul1(
            // sig,
            // (segment_id as u32, output_type),
            // input_segment_info.clone(),
            a.clone(),
            b.clone(),
            c.clone(),
        );
    }


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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemSparseEval = hint_in_b.output.into();

    let output_type = false;

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hints_dense_dense_mul0(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            a.clone(),
            b.f.clone(),
        );
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    hint_in_b: &Segment,
    hint_in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (hint_in_a.id, hint_in_a.output_type),
        (hint_in_b.id, hint_in_b.output_type),
        (hint_in_c.id, hint_in_c.output_type),
    ];

    let a: ElemFp12Acc = hint_in_a.output.into();
    let b: ElemSparseEval = hint_in_b.output.into();
    let c: ElemFp12Acc = hint_in_c.output.into();

    let output_type = false;

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1, hint_script) = hints_dense_dense_mul1(
            a.clone(),
            b.f.clone(),
            c.clone(),
        );
    }

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
    skip: bool,
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

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval, hint_script) = hint_add_eval_mul_for_fixed_Qs(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
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
    }

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
    skip: bool,
    segment_id: usize,
    hint_in_f: &Segment,
    power: usize,
) -> Segment {

    let input_segment_info = vec![(hint_in_f.id, hint_in_f.output_type)];

    let f = hint_in_f.output.into();

    let output_type = false;

    let (mut cp, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (cp, hint_script) = hints_frob_fp12(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            f,
            power,
        );
    }

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
    skip: bool,
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

    let (mut temp, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (temp, hint_script) = hint_point_add_with_frob(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            t4,
            p4x,
            p4y,
            q4_x_c0,
            q4_x_c1,
            q4_y_c0,
            q4_y_c1,
            power,
        );
    }

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
    skip: bool,
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

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval, hint_script) = hint_add_eval_mul_for_fixed_Qs_with_frob(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
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
    }

    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([hint_in_t2, hint_in_t3, pub_q2, pub_q3], ate)),
    }
}


pub(crate) fn wrap_hints_dense_dense_mul0_by_constant(
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

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


    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0, hint_script) = hints_dense_dense_mul0_by_constant(

            a.clone(),
            fixedacc,
        );
    }


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
    skip: bool,
    segment_id: usize,
    hint_in_a: &Segment, hint_in_c0: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

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

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1, hint_script) = hints_dense_dense_mul1_by_constant(
            a.clone(),
            hint_in_c0.output.into(),
            fixedacc,
        );
    }


    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst1(constant),
    }
}

#[cfg(test)]
mod test {
    use bitcoin_script::script;

    use crate::chunk::primitves::fp12_to_vec;

    use super::*;


    #[test]
    fn test_wrap_cinv() {
        let f = ark_bn254::Fq12::ONE + ark_bn254::Fq12::ONE +  ark_bn254::Fq12::ONE;
        let hash = extern_hash_fps(fp12_to_vec(f), true);
        let c = ElemFp12Acc {f, hash};
        let seg = Segment {
            id: 0,
            output_type: false,
            inputs: vec![],
            output: Element::Fp12(c),
            hint_script: script!(),
            scr_type: ScriptType::NonDeterministic,
        };

        let inv0 = wrap_inv0(false, 1, &seg);
        let inv1 = wrap_inv1(false, 1, &inv0);
        let inv2 = wrap_inv2(false, 1, &inv1, &seg);

        let out: ElemFp12Acc = inv2.output.into();
        println!("match {}", out.f == f.inverse().unwrap());
    }
}