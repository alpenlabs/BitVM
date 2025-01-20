

use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr, utils::{Hint}}, chunk::taps_msm::{chunk_msm}, execute_script, treepp};

use super::{element::Element, taps_msm::chunk_hash_p, taps_point_eval::*, taps_premiller::*};

pub type SegmentID = u32;
pub type SegmentOutputType = bool;

#[derive(Debug, Clone)]
pub(crate) struct Segment {
    pub id: SegmentID,
    pub parameter_ids: Vec<SegmentID>,   
    pub result: Element,
    pub hints: Vec<Hint>,
    pub scr_type: ScriptType,
}


/// After the returned `script` and `witness` are executed together, only `OP_FALSE` left on the stack.
/// If operator gives a wrong intermediate value, `OP_TRUE` will left on the stack and challenger will finish the slash.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    NonDeterministic,
    MSM((usize, Vec<ark_bn254::G1Affine>)),

    PreMillerInitT4,
    PreMillerPrecomputeP,
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
}



use ark_ff::{AdditiveGroup, Field};

use super::{element::*, primitves::extern_hash_fps,  taps_point_ops::*, taps_mul::*};

pub(crate) fn wrap_hint_msm(
    skip: bool,
    segment_id: usize,
    scalars: Vec<Segment>,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Vec<Segment> {
    let mut scalar_input_segment_info: Vec<SegmentID> = vec![];
    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .map(|f| {
        scalar_input_segment_info.push(f.id);
        f.result.try_into().unwrap() 
    })
    .collect();

    let mut window = 7;
    if hint_scalars.len() == 2 {
        window = 5;
    }

    let num_chunks = (Fr::N_BITS + 2 * window - 1)/(2 * window);
    let mut segments = vec![];
    let mut prev_input = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO);
    if !skip {
        let houts = chunk_msm(window as usize, hint_scalars, pub_vky.clone());
        assert_eq!(houts.len() as u32, num_chunks);
        for (msm_chunk_index, (hout_msm, _, mut op_hints)) in houts.into_iter().enumerate() {
            let mut input_segment_info: Vec<SegmentID> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = (segment_id + msm_chunk_index -1) as u32;
                input_segment_info.push(prev_msm_id);
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            if msm_chunk_index > 0 {
                op_hints.extend_from_slice(&Element::MSMG1(prev_input).get_hash_preimage_as_hints());
            }
            prev_input = hout_msm.clone();

            segments.push(Segment { 
                id: (segment_id + msm_chunk_index) as u32, 
                parameter_ids: input_segment_info, 
                result: Element::MSMG1(hout_msm), 
                hints: op_hints, scr_type: ScriptType::MSM((msm_chunk_index, pub_vky.clone())),
            });
        }
    } else {
        let hout_msm: ElemG1Point = ElemG1Point::mock();
        for msm_chunk_index in 0..num_chunks {
            let mut input_segment_info: Vec<SegmentID> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = segment_id as u32 + msm_chunk_index -1;
                input_segment_info.push(prev_msm_id);
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            segments.push(Segment { 
                id: (segment_id as u32 + msm_chunk_index), 
                parameter_ids: input_segment_info, 
                result: Element::MSMG1(hout_msm), 
                hints: vec![], scr_type: ScriptType::MSM((msm_chunk_index as usize, pub_vky.clone())),
            });
        }
    }
    segments
}


pub(crate) fn wrap_hint_hash_p(
    skip: bool,
    segment_id: usize,
    in_t: &Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_t.id);

    let t = in_t.result.try_into().unwrap();
    let (mut p3, mut op_hints) = (ElemG1Point::mock(), vec![]);
    if !skip {
        (p3, _, op_hints) = chunk_hash_p(
            t,
            pub_vky0.clone(),
        );
        op_hints.extend_from_slice(&Element::MSMG1(t).get_hash_preimage_as_hints());
    }
    Segment { id: segment_id as u32, parameter_ids: input_segment_info, result: Element::MSMG1(p3), hints: op_hints, scr_type: ScriptType::PreMillerHashP(pub_vky0) }
}

pub(crate) fn wrap_hint_hash_c(  
    skip: bool,  
    segment_id: usize,
    in_c: Vec<Segment>,
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    let fqvec: Vec<ElemFq> = in_c
    .iter()
    .map(|f| {
        input_segment_info.push(f.id);
        f.result.try_into().unwrap()
    })
    .collect();

    let (mut c, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (c,_, op_hints) = chunk_hash_c(
             fqvec
            );
        // field elements do not have preimage
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::Fp12v1(c), hints: op_hints, scr_type: ScriptType::PreMillerHashC }
}

pub(crate) fn wrap_hints_precompute_p(
    skip: bool,
    segment_id: usize,
    in_py: &Segment,
    in_px: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_py.id);
    input_segment_info.push(in_px.id);

    let (mut p3d, mut op_hints) = (ElemG1Point::mock(), vec![]);
    if !skip {
        let in_py = in_py.result.try_into().unwrap();
        let in_px = in_px.result.try_into().unwrap();
        (p3d, _, op_hints) = chunk_precompute_p(in_py, in_px);
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::MSMG1(p3d), hints: op_hints, scr_type: ScriptType::PreMillerPrecomputeP }
}

pub(crate) fn wrap_hint_hash_c2(
    skip: bool,
    segment_id: usize,
    in_c: &Segment
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_c.id);

    let (mut c2, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        let in_c = in_c.result.try_into().unwrap();
        (c2, _, op_hints) = chunk_hash_c2(in_c);
        op_hints.extend_from_slice(&Element::Fp12v1(in_c).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::Fp12v0(c2), hints: op_hints, scr_type: ScriptType::PreMillerHashC2 }
}

pub(crate) fn wrap_inv0(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_a.id);

    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv0(in_a);
        op_hints.extend_from_slice(&Element::Fp12v0(in_a).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::Fp6(dmul0), hints: op_hints, scr_type: ScriptType::PreMillerInv0 }
}

pub(crate) fn wrap_inv1(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_a.id);

    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv1(in_a);
        op_hints.extend_from_slice(&Element::Fp6(in_a).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::Fp6(dmul0), hints: op_hints, scr_type: ScriptType::PreMillerInv1 }
}

pub(crate) fn wrap_inv2(
    skip: bool,
    segment_id: usize,
    in_t1: &Segment,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<SegmentID> = vec![];
    input_segment_info.push(in_t1.id);
    input_segment_info.push(in_a.id);

    let (mut dmul0, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.try_into().unwrap();
        let in_t1 = in_t1.result.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv2(in_t1, in_a);
        op_hints.extend_from_slice(&Element::Fp12v0(in_a).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::Fp6(in_t1).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, parameter_ids: input_segment_info, result: Element::Fp12v0(dmul0), hints: op_hints, scr_type: ScriptType::PreMillerInv2 }
}


pub(crate) fn wrap_hint_init_t4(
    skip: bool,
    segment_id: usize,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
) -> Segment {
    
    let input_segment_info = vec![
        in_q4yc1.id,
        in_q4yc0.id,
        in_q4xc1.id,
        in_q4xc0.id,
    ];

    let q4xc0: ark_bn254::Fq = in_q4xc0.result.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.try_into().unwrap();

    let (mut tmpt4, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (tmpt4,_, op_hints) = chunk_init_t4(
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
        );
        // felts have no preimage
    }
    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::G2T(tmpt4),
        hints: op_hints,
        scr_type: ScriptType::PreMillerInitT4,
    }
}

pub(crate) fn wrap_hint_squaring(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let input_segment_info = vec![in_a.id];

    let f_acc: ElemFp12Acc = in_a.result.try_into().unwrap();

    let (mut sq, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (sq,_, op_hints) = chunk_squaring(
            f_acc,
        );
        let f_acc_preimage_hints = Element::Fp12v1(f_acc).get_hash_preimage_as_hints();
        op_hints.extend_from_slice(&f_acc_preimage_hints);
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(sq),
        hints: op_hints,
        scr_type: ScriptType::MillerSquaring,
    }
}

pub(crate) fn wrap_hint_point_dbl(
    skip: bool,
    segment_id: usize,
    in_t4: &Segment,
    in_p4: &Segment,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p4.id),
        (in_t4.id),
    ];

    let t4: ElemG2PointAcc = in_t4.result.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.try_into().unwrap();

    let (mut dbl, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (dbl, _, op_hints) = chunk_point_dbl(t4, p4);

        op_hints.extend_from_slice(&Element::G2DblEval(t4).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::MSMG1(p4).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::G2DblEval(dbl),
        hints: op_hints,
        scr_type: ScriptType::MillerDouble,
    }
}


pub(crate) fn wrap_hint_point_ops(
    skip: bool,
    segment_id: usize,
    in_t4: &Segment,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
    in_p4: &Segment,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p4.id),
        (in_t4.id),
        (in_q4yc1.id),
        (in_q4yc0.id),
        (in_q4xc1.id),
        (in_q4xc0.id),
    ];

    let t4: ElemG2PointAcc = in_t4.result.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.result.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.try_into().unwrap();

    let (mut dbladd, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (dbladd,_, op_hints) = chunk_point_ops(
            t4,
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
            p4,
            ate,
        );
        op_hints.extend_from_slice(&Element::G2DblAddEval(t4).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::MSMG1(p4).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::G2DblAddEval(dbladd),
        hints: op_hints,
        scr_type: ScriptType::MillerDoubleAdd(ate),
    }
}

pub(crate) fn wrap_hint_sparse_dense_mul(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_g: &Segment,
    is_dbl_blk: bool,
) -> Segment {
    
    let input_segment_info = vec![
        (in_a.id),
        (in_g.id),
    ];

    let f_acc: ElemFp12Acc = in_a.result.try_into().unwrap();
    let t4: ElemG2PointAcc = in_g.result.try_into().unwrap();

    let (mut temp, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (temp, _, op_hints) = chunk_sparse_dense_mul(
            f_acc,
            t4,
            is_dbl_blk,
        );
    }
    Segment {
        id: segment_id as u32,
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(temp),
        hints: op_hints,
        scr_type: ScriptType::SparseDenseMul(is_dbl_blk),
    }
}

pub(crate) fn wrap_hint_multiply_point_evals_on_tangent_for_fixed_g2(
    skip: bool,
    segment_id: usize,
    in_p3: &Segment,
    in_p2: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3.id),
        (in_p2.id),
    ];

    let p2: ElemG1Point = in_p2.result.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemSparseEval::mock(), vec![]);
    if !skip {
        (leval, _, op_hints) = chunk_multiply_point_evals_on_tangent_for_fixed_g2(
            // sig),
            // input_segment_info.clone(),
            p3,
            p2,
            in_t2,
            in_t3,
        );
        op_hints.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);
        // skip because felts
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::SparseEval(leval),
        hints: op_hints,
        scr_type: ScriptType::MillerSparseSparseDbl((in_t2, in_t3)),
    }
}

pub(crate) fn wrap_hints_dense_dense_mul0(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_b.id),
        (in_a.id),
    ];

    let a: ElemFp12Acc = in_a.result.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.try_into().unwrap();

    
    let (mut dmul0, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_dense_dense_mul0(
            a.clone(),
            b.clone(),
        );
        op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::Fp12v1(b).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(dmul0),
        hints: op_hints,
        scr_type: ScriptType::DenseDenseMul0(),
    }
}

pub(crate) fn wrap_hints_dense_dense_mul1(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
    in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_c.id),
        (in_b.id),
        (in_a.id),
    ];

    let a: ElemFp12Acc = in_a.result.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.try_into().unwrap();
    let c: ElemFp12Acc = in_c.result.try_into().unwrap();

    

    let (mut dmul1, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul1, _, op_hints) = chunk_dense_dense_mul1(
            a.clone(),
            b.clone(),
            c.clone(),
        );

        let a_preimage_hints = Element::Fp12v0(a).get_hash_preimage_as_hints();
        let b_preimage_hints = Element::Fp12v1(b).get_hash_preimage_as_hints();
        let c0_preimage_hints = Element::HashBytes(c.hash).get_hash_preimage_as_hints();
        op_hints.extend_from_slice(&a_preimage_hints);
        op_hints.extend_from_slice(&b_preimage_hints);
        op_hints.extend_from_slice(&c0_preimage_hints);
        op_hints.extend_from_slice(&c0_preimage_hints);
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(dmul1),
        hints: op_hints,
        scr_type: ScriptType::DenseDenseMul1(),
    }
}


pub(crate) fn wrap_hints_dense_le_mul0(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_b.id),
        (in_a.id),
    ];

    let a: ElemFp12Acc = in_a.result.try_into().unwrap();
    let b: ElemSparseEval = in_b.result.try_into().unwrap();

    

    let (mut dmul0, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_dense_dense_mul0(
            a.clone(),
            b.f.clone(),
        );
        let a_preimage_hints = Element::Fp12v0(a).get_hash_preimage_as_hints();
        let b_preimage_hints = Element::Fp12v1(b.f).get_hash_preimage_as_hints();
        op_hints.extend_from_slice(&a_preimage_hints); 
        op_hints.extend_from_slice(&b_preimage_hints); 
    }
    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(dmul0), // todo: fp12->fp6
        hints: op_hints,
        scr_type: ScriptType::DenseDenseMul0(),
    }
}

pub(crate) fn wrap_hints_dense_le_mul1(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
    in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_c.id),
        (in_b.id),
        (in_a.id),
    ];

    let a: ElemFp12Acc = in_a.result.try_into().unwrap();
    let b: ElemSparseEval = in_b.result.try_into().unwrap();
    let c: ElemFp12Acc = in_c.result.try_into().unwrap();

    

    let (mut dmul1, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul1, _, op_hints) = chunk_dense_dense_mul1(
            a.clone(),
            b.f.clone(),
            c.clone(),
        );
        op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::Fp12v1(b.f).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::HashBytes(c.hash).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::HashBytes(c.hash).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v1(dmul1),
        hints: op_hints,
        scr_type: ScriptType::DenseDenseMul1(),
    }
}

pub(crate) fn wrap_hint_multiply_point_evals_on_chord_for_fixed_g2(
    skip: bool,
    segment_id: usize,
    in_p3: &Segment,
    in_p2: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3.id),
        (in_p2.id),
    ];

    let p2: ElemG1Point = in_p2.result.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemSparseEval::mock(), vec![]);
    if !skip {
        (leval,_, op_hints) = chunk_multiply_point_evals_on_chord_for_fixed_g2(
            p3,
            p2,
            in_t2,
            in_t3,
            pub_q2,
            pub_q3,
            ate,
        );
        op_hints.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::SparseEval(leval),
        hints: op_hints,
        scr_type: ScriptType::MillerSparseSparseAdd(([in_t2, in_t3, pub_q2, pub_q3], ate)),
    }
}

pub(crate) fn wrap_hints_frob_fp12(
    skip: bool,
    segment_id: usize,
    in_f: &Segment,
    power: usize,
) -> Segment {

    let input_segment_info = vec![(in_f.id)];
    let f = in_f.result.try_into().unwrap();

    let (mut cp, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (cp,_, op_hints) = chunk_frob_fp12(f, power);
        let f_acc_preimage_hints = Element::Fp12v1(f).get_hash_preimage_as_hints();
        op_hints.extend_from_slice(&f_acc_preimage_hints);
    }
    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(cp),
        hints: op_hints,
        scr_type: ScriptType::PostMillerFrobFp12(power as u8),
    }
}

pub(crate) fn wrap_hint_point_add_with_frob(
    skip: bool,
    segment_id: usize,
    in_t4: &Segment,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
    in_p4: &Segment,
    power: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p4.id),
        (in_t4.id),
        (in_q4yc1.id),
        (in_q4yc0.id),
        (in_q4xc1.id),
        (in_q4xc0.id),
    ];

    let t4: ElemG2PointAcc = in_t4.result.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.result.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.try_into().unwrap();

    let (mut temp, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (temp, _, op_hints) = chunk_point_add_with_frob(
            t4,
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
            p4,
            power,
        );
        op_hints.extend_from_slice(&Element::G2AddEval(t4).get_hash_preimage_as_hints());
        op_hints.extend_from_slice(&Element::MSMG1(p4).get_hash_preimage_as_hints());
    }

    Segment {
        id: segment_id as u32,
        parameter_ids: input_segment_info,
        result: Element::G2AddEval(temp),
        hints: op_hints,
        scr_type: ScriptType::PostMillerAddWithFrob(power),
    }
}

pub(crate) fn wrap_multiply_point_evals_on_chord_for_fixed_g2_with_frob(
    skip: bool,
    segment_id: usize,
    in_p3: &Segment,
    in_p2: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3.id),
        (in_p2.id),
    ];

    let p2: ElemG1Point = in_p2.result.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemSparseEval::mock(), vec![]);
    if !skip {
        (leval, _, op_hints) = chunk_multiply_point_evals_on_chord_for_fixed_g2_with_frob(
            p3,
            p2,
            in_t2,
            in_t3,
            pub_q2,
            pub_q3,
            ate,
        );
        op_hints.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);
    }
    
    Segment {
        id: segment_id as u32,
        parameter_ids: input_segment_info,
        result: Element::SparseEval(leval),
        hints: op_hints,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([in_t2, in_t3, pub_q2, pub_q3], ate)),
    }
}


pub(crate) fn wrap_hints_final_verify(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

    let input_segment_info = vec![(in_a.id)];

    let a: ElemFp12Acc = in_a.result.try_into().unwrap();
    let fixedacc = ElemFp12Acc {
        f: constant,
        hash: extern_hash_fps(
            constant.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            false,
        ),
    };

    let (mut dmul0, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_final_verify(
            a.clone(),
            fixedacc,
        );
    }

    
    Segment {
        id: segment_id as u32,
        
        parameter_ids: input_segment_info,
        result: Element::Fp12v0(dmul0),
        hints: op_hints,
        scr_type: ScriptType::PostMillerDenseDenseMulByConst0(constant),
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_ff::{Field};


    #[test]
    fn test_wrap_cinv() {
        let f = ark_bn254::Fq12::ONE + ark_bn254::Fq12::ONE +  ark_bn254::Fq12::ONE;
        let hash = extern_hash_fps(f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(), true);
        let c = ElemFp12Acc {f, hash};
        
        let seg = Segment {
            id: 0,
            
            parameter_ids: vec![],
            result: Element::Fp12v0(c),
            hints: vec![],
            scr_type: ScriptType::NonDeterministic,
        };

        let inv0 = wrap_inv0(false, 1, &seg);
        let inv1 = wrap_inv1(false, 1, &inv0);
        let inv2 = wrap_inv2(false, 1, &inv1, &seg);

        let out: ElemFp12Acc = inv2.result.try_into().unwrap();
        println!("match {}", out.f == f.inverse().unwrap());
    }
}