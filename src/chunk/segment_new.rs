use ark_ff::AdditiveGroup;

use crate::{bn254::{fp254impl::Fp254Impl, fr::Fr, utils::Hint}, chunk::taps_msm::chunk_msm};

use super::{element::{ElemFp6, ElemG1Point, ElemG2Eval, ElemTraitExt, ElemU256, Element, ElementType}, norm_fp12::{chunk_complete_point_eval_and_mul, chunk_dense_dense_mul, chunk_frob_fp12, chunk_hinted_square, chunk_init_t4, chunk_point_ops_and_mul}, segment::{ScriptType, Segment, SegmentID}, taps_msm::chunk_hash_p, taps_point_eval::*, taps_premiller::*};


// final verify
// sq
pub(crate) fn wrap_hint_squaring(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_a.id, ElementType::Fp6)];

    let f_acc: ElemFp6 = in_a.result.0.try_into().unwrap();

    let (mut sq, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (sq,_, op_hints) = chunk_hinted_square(f_acc);
    }

    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp6(sq), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::MillerSquaring,
    }
}

// init_t4
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

    let q4xc0: ElemU256 =  in_q4xc0.result.0.try_into().unwrap();
    let q4xc1: ElemU256 =  in_q4xc1.result.0.try_into().unwrap();
    let q4yc0: ElemU256 =  in_q4yc0.result.0.try_into().unwrap();
    let q4yc1: ElemU256 =  in_q4yc1.result.0.try_into().unwrap();

    let (mut tmpt4, mut op_hints) = (ElemG2Eval::mock(), vec![]);
    if !skip {
        (tmpt4,_, op_hints) = chunk_init_t4(
            [q4xc0.into(), q4xc1.into(), q4yc0.into(), q4yc1.into()],
        );
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Eval(tmpt4), ElementType::G2EvalPoint),
        hints: op_hints,
        scr_type: ScriptType::PreMillerInitT4,
    }
}

// dmul
pub(crate) fn wrap_hints_dense_dense_mul(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_b.id, ElementType::Fp6),
        (in_a.id, ElementType::Fp6),
    ];

    let a: ElemFp6 = in_a.result.0.try_into().unwrap();
    let b: ElemFp6 = in_b.result.0.try_into().unwrap();

    
    let (mut dmul0, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (dmul0,_, op_hints) = chunk_dense_dense_mul(a.clone(), b.clone());
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

// frob
pub(crate) fn wrap_hints_frob_fp12(
    skip: bool,
    segment_id: usize,
    in_f: &Segment,
    power: usize,
) -> Segment {

    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_f.id, ElementType::Fp6)];
    let f = in_f.result.0.try_into().unwrap();

    let (mut cp, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (cp,_, op_hints) = chunk_frob_fp12(f, power);
        // op_hints.extend_from_slice(&Element::Fp12v0(f).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp6(cp), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::PostMillerFrobFp12(power as u8),
    }
}


// ops
pub(crate) fn wrap_hint_point_ops(
    skip: bool,
    segment_id: usize,
    is_dbl: bool, is_frob: Option<bool>, ate_bit: Option<i8>,
    in_t4: &Segment, in_p4: &Segment, 
    in_q4: Option<Vec<Segment>>,
    in_p3: &Segment,
    t3: ark_bn254::G2Affine, q3: Option<ark_bn254::G2Affine>,
    in_p2: &Segment,
    t2: ark_bn254::G2Affine, q2: Option<ark_bn254::G2Affine>,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_t4.id, ElementType::G2EvalPoint),
        (in_p4.id, ElementType::G1),
        (in_p3.id, ElementType::G1),
        (in_p2.id, ElementType::G1),
    ];

    let t4: ElemG2Eval = in_t4.result.0.try_into().unwrap();
    let p4: ElemG1Point = in_p4.result.0.try_into().unwrap();
    let p3: ElemG1Point = in_p3.result.0.try_into().unwrap();
    let p2: ElemG1Point = in_p2.result.0.try_into().unwrap();
    let mut q4: Option<ark_bn254::G2Affine> = None;

    if !is_dbl {
        let in_q4 = in_q4.unwrap();
        for v in &in_q4 {
            input_segment_info.push((v.id, ElementType::FieldElem))
        }

        let q4xc0: ElemU256 =  in_q4[0].result.0.try_into().unwrap();
        let q4xc1: ElemU256 =  in_q4[1].result.0.try_into().unwrap();
        let q4yc0: ElemU256 =  in_q4[2].result.0.try_into().unwrap();
        let q4yc1: ElemU256 =  in_q4[3].result.0.try_into().unwrap();
        q4 = Some(ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(q4xc0.into(), q4xc1.into()), ark_bn254::Fq2::new(q4yc0.into(), q4yc1.into())));
    }

    let (mut dbladd, mut op_hints) = (ElemG2Eval::mock(), vec![]);
    if !skip {
        (dbladd,_, op_hints) = chunk_point_ops_and_mul(
            is_dbl, is_frob, ate_bit,
            t4, p4, q4,
            p3, t3, q3,
            p2, t2, q2
        );
    }

    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::G2Eval(dbladd), ElementType::G2Eval),
        hints: op_hints,
        scr_type: if is_dbl {
            ScriptType::MillerDouble
        } else {
            ScriptType::MillerDoubleAdd(ate_bit.unwrap())
        } ,
    }
}

// complete
fn wrap_complete_point_eval_and_mul(
    skip: bool,
    segment_id: usize,
    in_f: Segment
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_f.id, ElementType::G2EvalMul),
    ];

    let f = in_f.result.0.try_into().unwrap();

    let (mut cp, mut op_hints) = (ElemFp6::mock(), vec![]);
    if !skip {
        (cp,_, op_hints) = chunk_complete_point_eval_and_mul(f);
        // op_hints.extend_from_slice(&Element::Fp12v0(f).get_hash_preimage_as_hints());
    }
    
    Segment {
        id: segment_id as u32,
        is_validation: false,
        parameter_ids: input_segment_info,
        result: (Element::Fp6(cp), ElementType::Fp6),
        hints: op_hints,
        scr_type: todo!()
    }
}