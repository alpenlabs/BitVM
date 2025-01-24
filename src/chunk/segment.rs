

use crate::{bn254::{curves::G1Affine, fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fr::Fr, utils::{fq_push_not_montgomery, Hint}}, chunk::taps_msm::chunk_msm, execute_script, treepp};

use super::{blake3compiled::hash_messages, element::Element, primitves::extern_nibbles_to_limbs, taps_msm::chunk_hash_p, taps_point_eval::*, taps_premiller::*};

pub type SegmentID = u32;
pub type SegmentOutputType = bool;

#[derive(Debug, Clone)]
pub(crate) struct Segment {
    pub id: SegmentID,
    pub is_validation: bool,
    pub parameter_ids: Vec<(SegmentID, ElementType)>,   
    pub result: (Element, ElementType),
    pub hints: Vec<Hint>,
    pub scr_type: ScriptType,
}


/// After the returned `script` and `witness` are executed together, only `OP_FALSE` left on the stack.
/// If operator gives a wrong intermediate value, `OP_TRUE` will left on the stack and challenger will finish the slash.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    NonDeterministic,
    MSM((usize, Vec<ark_bn254::G1Affine>)),
    ValidateG1IsOnCurve,
    ValidateG1HashIsOnCurve,
    ValidateG2IsOnCurve,
    ValidateFq12OnField,

    PreMillerInitT4,
    PreMillerPrecomputeP,
    PreMillerPrecomputePFromHash,
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
    PostMillerFinalVerify(ark_bn254::Fq12),
}



use ark_ff::{AdditiveGroup, Field};
use bitcoin_script::script;

use super::{element::*, primitves::extern_hash_fps,  taps_point_ops::*, taps_mul::*};

pub(crate) fn wrap_hint_msm(
    skip: bool,
    segment_id: usize,
    scalars: Vec<Segment>,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Vec<Segment> {
    let mut scalar_input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .map(|f| {
        scalar_input_segment_info.push((f.id, ElementType::ScalarElem));
        f.result.0.try_into().unwrap() 
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
            let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = (segment_id + msm_chunk_index -1) as u32;
                input_segment_info.push((prev_msm_id, ElementType::G1));
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            // if msm_chunk_index > 0 {
                // op_hints.extend_from_slice(&Element::G1(prev_input).get_hash_preimage_as_hints());
            // }
            prev_input = hout_msm.clone();

            segments.push(Segment { 
                id: (segment_id + msm_chunk_index) as u32, 
                is_validation: false,
                parameter_ids: input_segment_info, 
                result: (Element::G1(hout_msm), ElementType::G1), 
                hints: op_hints, scr_type: ScriptType::MSM((msm_chunk_index, pub_vky.clone())),
            });
        }
    } else {
        let hout_msm: ElemG1Point = ElemG1Point::mock();
        for msm_chunk_index in 0..num_chunks {
            let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = segment_id as u32 + msm_chunk_index -1;
                input_segment_info.push((prev_msm_id, ElementType::G1));
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            segments.push(Segment { 
                id: (segment_id as u32 + msm_chunk_index), 
                is_validation: false,
                parameter_ids: input_segment_info, 
                result: (Element::G1(hout_msm), ElementType::G1), 
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
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_t.id, ElementType::G1));

    let t = in_t.result.0.try_into().unwrap();
    let (mut p3, mut op_hints) = (ElemG1Point::mock(), vec![]);
    if !skip {
        (p3, _, op_hints) = chunk_hash_p(
            t,
            pub_vky0.clone(),
        );
        // op_hints.extend_from_slice(&Element::G1(t).get_hash_preimage_as_hints());
    }
    Segment { id: segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::G1(p3), ElementType::G1), hints: op_hints, scr_type: ScriptType::PreMillerHashP(pub_vky0) }
}

pub(crate) fn wrap_hint_hash_c(  
    skip: bool,  
    segment_id: usize,
    in_c: Vec<Segment>,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    let fqvec: Vec<ElemFq> = in_c
    .iter()
    .map(|f| {
        f.result.0.try_into().unwrap()
    })
    .collect();

    in_c
    .iter()
    .rev()
    .for_each(|f| {
        input_segment_info.push((f.id, ElementType::FieldElem));
    });

    let (mut c, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (c,_, op_hints) = chunk_hash_c(fqvec);
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::Fp12(c), ElementType::Fp12v0), hints: op_hints, scr_type: ScriptType::PreMillerHashC }
}

pub(crate) fn wrap_hints_precompute_p(
    skip: bool,
    segment_id: usize,
    in_py: &Segment,
    in_px: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_py.id, ElementType::FieldElem));
    input_segment_info.push((in_px.id, ElementType::FieldElem));

    let (mut p3d, mut op_hints) = (ElemG1Point::mock(), vec![]);
    // let mut tap_prex = script!();
    if !skip {
        let in_py = in_py.result.0.try_into().unwrap();
        let in_px = in_px.result.0.try_into().unwrap();
        (p3d, _, op_hints) = chunk_precompute_p(in_py, in_px);
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::G1(p3d), ElementType::G1), hints: op_hints, scr_type: ScriptType::PreMillerPrecomputeP }
}

pub(crate) fn wrap_hints_precompute_p_from_hash(
    skip: bool,
    segment_id: usize,
    in_p: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_p.id, ElementType::G1));

    let (mut p3d, mut op_hints) = (ElemG1Point::mock(), vec![]);
    if !skip {
        let in_p = in_p.result.0.try_into().unwrap();
        (p3d, _, op_hints) = chunk_precompute_p_from_hash(in_p);
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::G1(p3d), ElementType::G1), hints: op_hints, scr_type: ScriptType::PreMillerPrecomputePFromHash }
}

pub(crate) fn wrap_hint_hash_c2(
    skip: bool,
    segment_id: usize,
    in_c: &Segment
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_c.id, ElementType::Fp12v0));

    let (mut c2, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        let in_c = in_c.result.0.try_into().unwrap();
        (c2, _, op_hints) = chunk_hash_c2(in_c);
        // op_hints.extend_from_slice(&Element::Fp12v1(in_c).get_hash_preimage_as_hints());

    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::Fp12(c2), ElementType::Fp12v0), hints: op_hints, scr_type: ScriptType::PreMillerHashC2 }
}

pub(crate) fn wrap_inv0(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_a.id, ElementType::Fp12v0));

    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.0.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv0(in_a);
        // op_hints.extend_from_slice(&Element::Fp12v0(in_a).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::Fp6(dmul0), ElementType::Fp6), hints: op_hints, scr_type: ScriptType::PreMillerInv0 }
}

pub(crate) fn wrap_inv1(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_a.id, ElementType::Fp6));

    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.0.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv1(in_a);
        // op_hints.extend_from_slice(&Element::Fp6(in_a).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::Fp6(dmul0), ElementType::Fp6), hints: op_hints, scr_type: ScriptType::PreMillerInv1 }
}

pub(crate) fn wrap_inv2(
    skip: bool,
    segment_id: usize,
    in_t1: &Segment,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    input_segment_info.push((in_t1.id, ElementType::Fp6));
    input_segment_info.push((in_a.id, ElementType::Fp12v0));

    let (mut dmul0, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        let in_a = in_a.result.0.try_into().unwrap();
        let in_t1 = in_t1.result.0.try_into().unwrap();
        (dmul0,_, op_hints) = chunk_inv2(in_t1, in_a);
        // op_hints.extend_from_slice(&Element::Fp12v0(in_a).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp6(in_t1).get_hash_preimage_as_hints());
    }
    
    Segment { id:  segment_id as u32, is_validation: false, parameter_ids: input_segment_info, result: (Element::Fp12(dmul0), ElementType::Fp12v0), hints: op_hints, scr_type: ScriptType::PreMillerInv2 }
}


pub(crate) fn wrap_hint_init_t4(
    skip: bool,
    segment_id: usize,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
) -> Segment {
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_q4yc1.id, ElementType::FieldElem),
        (in_q4yc0.id, ElementType::FieldElem),
        (in_q4xc1.id, ElementType::FieldElem),
        (in_q4xc0.id, ElementType::FieldElem),
    ];

    let q4xc0: ark_bn254::Fq = in_q4xc0.result.0.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.0.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.0.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.0.try_into().unwrap();

    let (mut tmpt4, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (tmpt4,_, op_hints) = chunk_init_t4(
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
        );
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Acc(tmpt4), ElementType::G2T),
        hints: op_hints,
        scr_type: ScriptType::PreMillerInitT4,
    }
}

pub(crate) fn wrap_hint_squaring(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_a.id, ElementType::Fp12v0)];

    let f_acc: ElemFp12Acc = in_a.result.0.try_into().unwrap();

    let (mut sq, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (sq,_, op_hints) = chunk_squaring(
            f_acc,
        );
        // let f_acc_preimage_hints = Element::Fp12v0(f_acc).get_hash_preimage_as_hints();
        // op_hints.extend_from_slice(&f_acc_preimage_hints);
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(sq), ElementType::Fp12v0),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p4.id, ElementType::G1),
        (in_t4.id, ElementType::G2DblEval),
    ];

    let t4: ElemG2PointAcc = in_t4.result.0.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.0.try_into().unwrap();

    let (mut dbl, mut op_hints) = (ElemG2PointAcc::mock(), vec![]);
    if !skip {
        (dbl, _, op_hints) = chunk_point_dbl(t4, p4);
        // op_hints.extend_from_slice(&Element::G2DblEval(t4).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::G1(p4).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Acc(dbl), ElementType::G2DblAddEval),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p4.id, ElementType::G1),
        (in_t4.id, ElementType::G2AddEval),
        (in_q4yc1.id, ElementType::FieldElem),
        (in_q4yc0.id, ElementType::FieldElem),
        (in_q4xc1.id, ElementType::FieldElem),
        (in_q4xc0.id, ElementType::FieldElem),
    ];

    let t4: ElemG2PointAcc = in_t4.result.0.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.0.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.result.0.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.0.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.0.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.0.try_into().unwrap();

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
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Acc(dbladd), ElementType::G2DblAddEval),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = if is_dbl_blk {
        vec![(in_a.id, ElementType::Fp12v0),(in_g.id, ElementType::G2DblEvalMul)]   
    } else {
        vec![(in_a.id, ElementType::Fp12v0), (in_g.id, ElementType::G2AddEvalMul)]
    };

    let f_acc: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let t4: ElemG2PointAcc = in_g.result.0.try_into().unwrap();

    let (mut temp, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (temp, _, op_hints) = chunk_sparse_dense_mul(
            f_acc,
            t4,
            is_dbl_blk,
        );
        // if is_dbl_blk {
            // op_hints.extend_from_slice(&Element::G2DblEvalMul(t4).get_hash_preimage_as_hints())
        // } else {
            // op_hints.extend_from_slice(&Element::G2AddEvalMul(t4).get_hash_preimage_as_hints())
        // }
        // op_hints.extend_from_slice(&Element::Fp12v0(f_acc).get_hash_preimage_as_hints());

    }
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(temp), ElementType::Fp12v0),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p3.id, ElementType::G1),
        (in_p2.id, ElementType::G1),
    ];

    let p2: ElemG1Point = in_p2.result.0.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.0.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (leval, _, op_hints) = chunk_multiply_point_evals_on_tangent_for_fixed_g2(
            p3,
            p2,
            in_t2,
            in_t3,
        );
        // op_hints.extend_from_slice(&Element::G1(p2).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::G1(p3).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(leval), ElementType::Fp12v0),
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

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_b.id, ElementType::Fp12v0),
        (in_a.id, ElementType::Fp12v0),
    ];

    let a: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.0.try_into().unwrap();

    
    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_dense_dense_mul0(
            a.clone(),
            b.clone(),
        );
        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp12v1(b).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp6(dmul0), ElementType::Fp6),
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

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_c.id, ElementType::Fp6Hash),
        (in_b.id, ElementType::Fp12v0),
        (in_a.id, ElementType::Fp12v0),
    ];

    let a: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.0.try_into().unwrap();
    let c: ElemFp6 = in_c.result.0.try_into().unwrap();

    

    let (mut dmul1, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul1, _, op_hints) = chunk_dense_dense_mul1(
            a.clone(),
            b.clone(),
            c.clone(),
        );

        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp12v1(b).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp6Hash(c).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(dmul1), ElementType::Fp12v2),
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

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_b.id, ElementType::Fp12v0),
        (in_a.id, ElementType::Fp12v0),
    ];

    let a: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.0.try_into().unwrap();

    

    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_dense_dense_mul0(
            a.clone(),
            b.clone(),
        );
        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp12v1(b).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp6(dmul0), ElementType::Fp6), // todo: fp12->fp6
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

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_c.id, ElementType::Fp6Hash),
        (in_b.id, ElementType::Fp12v0),
        (in_a.id, ElementType::Fp12v0),
    ];

    let a: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let b: ElemFp12Acc = in_b.result.0.try_into().unwrap();
    let c: ElemFp6 = in_c.result.0.try_into().unwrap();

    

    let (mut dmul1, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (dmul1, _, op_hints) = chunk_dense_dense_mul1(
            a.clone(),
            b.clone(),
            c.clone(),
        );
        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp12v1(b.f).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::Fp6Hash(c).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(dmul1), ElementType::Fp12v2),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p3.id, ElementType::G1),
        (in_p2.id, ElementType::G1),
    ];

    let p2: ElemG1Point = in_p2.result.0.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.0.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
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
        // op_hints.extend_from_slice(&Element::G1(p2).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::G1(p3).get_hash_preimage_as_hints());
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(leval), ElementType::Fp12v0),
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

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_f.id, ElementType::Fp12v0)];
    let f = in_f.result.0.try_into().unwrap();

    let (mut cp, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
    if !skip {
        (cp,_, op_hints) = chunk_frob_fp12(f, power);
        // op_hints.extend_from_slice(&Element::Fp12v0(f).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(cp), ElementType::Fp12v0),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p4.id, ElementType::G1),
        (in_t4.id, ElementType::G2AddEval),
        (in_q4yc1.id, ElementType::FieldElem),
        (in_q4yc0.id, ElementType::FieldElem),
        (in_q4xc1.id, ElementType::FieldElem),
        (in_q4xc0.id, ElementType::FieldElem),
    ];

    let t4: ElemG2PointAcc = in_t4.result.0.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.0.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.result.0.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.result.0.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.result.0.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.result.0.try_into().unwrap();

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
        // op_hints.extend_from_slice(&Element::G2AddEval(t4).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::G1(p4).get_hash_preimage_as_hints());
    }

    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Acc(temp), ElementType::G2DblAddEval),
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
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p3.id, ElementType::G1),
        (in_p2.id, ElementType::G1),
    ];

    let p2: ElemG1Point = in_p2.result.0.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.0.try_into().unwrap();

    let (mut leval, mut op_hints) = (ElemFp12Acc::mock(), vec![]);
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
        // op_hints.extend_from_slice(&Element::G1(p2).get_hash_preimage_as_hints());
        // op_hints.extend_from_slice(&Element::G1(p3).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp12(leval), ElementType::Fp12v0),
        hints: op_hints,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([in_t2, in_t3, pub_q2, pub_q3], ate)),
    }
}


pub(crate) fn wrap_verify_fp12_is_unity(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_a.id, ElementType::Fp12v0)];

    let a: ElemFp12Acc = in_a.result.0.try_into().unwrap();
    let fixedacc = ElemFp12Acc {
        f: constant,
        hash: extern_hash_fps(
            constant.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        ),
    };

    let (mut is_valid, mut op_hints) = (true, vec![]);
    if !skip {
        (is_valid,_, op_hints) = chunk_verify_fp12_is_unity(
            a.clone(),
            fixedacc,
        );

        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
    }
    let is_valid_fq = if is_valid {
        ark_bn254::Fq::ONE
    } else {
        ark_bn254::Fq::ZERO
    };

    
    Segment {
        id: segment_id as u32,
        is_validation: true,
        parameter_ids: input_segment_info,
        result: (Element::FieldElem(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::PostMillerFinalVerify(constant),
    }
}

// verify g1 is on curve - 2 (p2, p4)
pub(crate) fn wrap_verify_g1_is_on_curve(
    skip: bool,
    segment_id: usize,
    in_py: &Segment,
    in_px: &Segment,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_py.id, ElementType::FieldElem), (in_px.id, ElementType::FieldElem)];
    let (mut is_valid, mut op_hints) = (true, vec![]);
    if !skip {
        let in_py = in_py.result.0.try_into().unwrap();
        let in_px = in_px.result.0.try_into().unwrap();
        // let mut tap_prex = script!();

        (is_valid, _, op_hints) = chunk_verify_g1_is_on_curve(in_py, in_px);
        // let bitcom_scr = script!{
        //     {fq_push_not_montgomery(in_py)}
        //     {Fq::toaltstack()}     
        //     {fq_push_not_montgomery(in_py)}
        //     {Fq::toaltstack()}     
        // };
        // println!("seg id {} is valid {}", segment_id, is_valid);

        // let script = script! {
        //     for h in &op_hints {
        //         { h.push() }
        //     }
        //     {bitcom_scr}
        //     {tap_prex}
        // };
        // let res = execute_script(script);
        // for i in 0..res.final_stack.len() {
        //     println!("{i:} {:?}", res.final_stack.get(i));
        // }
        // assert!(!res.success);
        // assert!(res.final_stack.len() == 1);

    }
    let is_valid_fq = if is_valid {
        ark_bn254::Fq::ONE
    } else {
        ark_bn254::Fq::ZERO
    };

    
    Segment {
        id: segment_id as u32,
        is_validation: true,
        parameter_ids: input_segment_info,
        result: (Element::FieldElem(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::ValidateG1IsOnCurve,
    }
}

// verify g1 hash is on curve - 1 (p3)
pub(crate) fn wrap_verify_g1_hash_is_on_curve(
    skip: bool,
    segment_id: usize,
    in_p: &Segment,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_p.id, ElementType::G1)];
    let (mut is_valid, mut op_hints) = (true, vec![]);
    if !skip {
        let in_p = in_p.result.0.try_into().unwrap();
        (is_valid, _, op_hints) = chunk_verify_g1_hash_is_on_curve(in_p);
    }
    let is_valid_fq = if is_valid {
        ark_bn254::Fq::ONE
    } else {
        ark_bn254::Fq::ZERO
    };
    Segment {
        id: segment_id as u32,
        is_validation: true,
        parameter_ids: input_segment_info,
        result: (Element::FieldElem(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::ValidateG1HashIsOnCurve,
    }
}

// verify g2 is on curve - 1 (q4)
pub(crate) fn wrap_verify_g2_is_on_curve(
    skip: bool,
    segment_id: usize,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_q4yc1.id, ElementType::FieldElem),
        (in_q4yc0.id, ElementType::FieldElem),
        (in_q4xc1.id, ElementType::FieldElem),
        (in_q4xc0.id, ElementType::FieldElem),
    ];
    let (mut is_valid, mut op_hints) = (true, vec![]);
    if !skip {
        let q4xc0: ark_bn254::Fq = in_q4xc0.result.0.try_into().unwrap();
        let q4xc1: ark_bn254::Fq = in_q4xc1.result.0.try_into().unwrap();
        let q4yc0: ark_bn254::Fq = in_q4yc0.result.0.try_into().unwrap();
        let q4yc1: ark_bn254::Fq = in_q4yc1.result.0.try_into().unwrap();
        (is_valid,_, op_hints) = chunk_verify_g2_on_curve(
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
        );
    }
    let is_valid_fq = if is_valid {
        ark_bn254::Fq::ONE
    } else {
        ark_bn254::Fq::ZERO
    };
    Segment {
        id: segment_id as u32,
        is_validation: true,
        parameter_ids: input_segment_info,
        result: (Element::FieldElem(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::ValidateG2IsOnCurve,
    }
}

// verify fq12 is on field - 2 (c, s)
pub(crate) fn wrap_verify_fq12_is_on_field(
    skip: bool,
    segment_id: usize,
    in_c: Vec<Segment>,
) -> Segment {

    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    in_c
    .iter()
    .rev()
    .for_each(|f| {
        input_segment_info.push((f.id, ElementType::FieldElem));
    });

    let (mut is_valid, mut op_hints) = (true, vec![]);
    if !skip {
        let fqvec: Vec<ElemFq> = in_c.iter().map(|f| {f.result.0.try_into().unwrap()}).collect();
        (is_valid,_, op_hints) = chunk_verify_fq12_is_on_field(fqvec);
    }
    let is_valid_fq = if is_valid {
        ark_bn254::Fq::ONE
    } else {
        ark_bn254::Fq::ZERO
    };
    Segment {
        id: segment_id as u32,
        is_validation: true,
        parameter_ids: input_segment_info,
        result: (Element::FieldElem(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::ValidateFq12OnField,
    }
}