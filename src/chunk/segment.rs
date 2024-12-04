
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
    MillerDoubleAdd(u8),
    MillerDouble,
    MillerSparseDenseMul,
    MillerSparseSparseDbl((ark_bn254::G2Affine, ark_bn254::G2Affine)),
    MillerDenseDenseMul0(bool),
    MillerDenseDenseMul1(bool),
    MillerSparseSparseAdd(([ark_bn254::G2Affine;4], i8)),

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

use super::{hint_models::*, msm::{hint_hash_p, hint_msm, HintInMSM}, primitves::extern_hash_fps,  taps::*, taps_mul::*};


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
        if let Element::MSM(hmsm) = prev_msm.output {
            acc = hmsm.t;
            input_segment_info.push((prev_msm.id, prev_msm.output_type));
        }
    }

    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .filter_map(|f| {
        if let Element::ScalarElem(hsc) = f.output {
            input_segment_info.push((f.id, f.output_type));
            Some(hsc)
        } else {
            None
        }
    })
    .collect();

    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let (hout_msm, hint_script, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: acc, scalars: hint_scalars }, msm_chain_index, pub_vky);

    Segment { id: segment_id, output_type: false, inputs: input_segment_info, output: Element::MSM(hout_msm), hint_script, scr_type: ScriptType::MSM }

}

fn wrap_hint_hash_p(inputs: Vec<(usize, Element)>, vky0: ark_bn254::G1Affine) {

}

fn wrap_hint_hash_c(inputs: Vec<(usize, Element)>) {

}



fn wrap_hints_precompute_Px(inputs: Vec<(usize, Element)>) {

}

fn wrap_hints_precompute_Py(inputs: Vec<(usize, Element)>) {
}

fn wrap_hint_hash_c2(inputs: Vec<(usize, Element)>) {

}

fn wrap_hints_dense_dense_mul0_by_hash(inputs: Vec<(usize, Element)>) {
 
}

fn wrap_hints_dense_dense_mul1_by_hash(inputs: Vec<(usize, Element)>) {

}

fn wrap_hint_init_T4(inputs: Vec<(usize, Element)>) {

}

fn wrap_hint_squaring(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

}

fn wrap_hint_point_dbl(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_point_ops(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_sparse_dense_mul(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_double_eval_mul_for_fixed_Qs(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul0(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wraphints_dense_dense_mul1(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_add_eval_mul_for_fixed_Qs(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_frob_fp12(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_point_add_with_frob(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul0_by_constant(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul1_by_constant(inputs: Vec<(usize, Element)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    
}