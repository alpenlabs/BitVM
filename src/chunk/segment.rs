

use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr, utils::fq_push_not_montgomery}, chunk::taps_msm::{chunk_msm, chunk_hash_p}, execute_script, treepp};

use super::{hint_models::Element, primitves::extern_nibbles_to_limbs, taps_point_eval::*, taps_premiller::*};

pub type SegmentID = u32;
pub type SegmentOutputType = bool;

#[derive(Debug, Clone)]
pub(crate) struct Segment {
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



use bitcoin_script::script;

use super::{hint_models::*, primitves::extern_hash_fps,  taps_point_ops::*, taps_mul::*};

pub(crate) fn wrap_hint_msm(
    skip: bool,
    segment_id: usize,
    scalars: Vec<Segment>,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Vec<Segment> {
    let mut scalar_input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let hint_scalars: Vec<ark_bn254::Fr> = scalars
    .iter()
    .map(|f| {
        scalar_input_segment_info.push((f.id, f.output_type));
        f.output.try_into().unwrap() 
    })
    .collect();

    let mut window = 7;
    if hint_scalars.len() == 2 {
        window = 5;
    }

    let num_chunks = (Fr::N_BITS + 2 * window - 1)/(2 * window);
    let mut segments = vec![];
    if !skip {
        let houts = chunk_msm(window as usize, hint_scalars, pub_vky.clone());
        assert_eq!(houts.len() as u32, num_chunks);
        for (msm_chunk_index, (hout_msm, _, hint_script)) in houts.into_iter().enumerate() {
            let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = (segment_id + msm_chunk_index -1) as u32;
                input_segment_info.push((prev_msm_id, hout_msm.ret_type()));
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            segments.push(Segment { 
                id: (segment_id + msm_chunk_index) as u32, 
                output_type: hout_msm.ret_type(), inputs: input_segment_info, 
                output: Element::MSMG1(hout_msm), 
                hint_script, scr_type: ScriptType::MSM((msm_chunk_index, pub_vky.clone())),
            });
        }
    } else {
        let hout_msm: ElemG1Point = ElemG1Point::mock();
        for msm_chunk_index in 0..num_chunks {
            let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = segment_id as u32 + msm_chunk_index -1;
                input_segment_info.push((prev_msm_id, hout_msm.ret_type()));
            }
            input_segment_info.extend_from_slice(&scalar_input_segment_info);

            segments.push(Segment { 
                id: (segment_id as u32 + msm_chunk_index), 
                output_type: hout_msm.ret_type(), inputs: input_segment_info, 
                output: Element::MSMG1(hout_msm), 
                hint_script: script!(), scr_type: ScriptType::MSM((msm_chunk_index as usize, pub_vky.clone())),
            });
        }
    }
    segments
}


pub(crate) fn wrap_hint_hash_p(
    skip: bool,
    segment_id: usize,
    in_t: &Segment,
    in_ry: &Segment, 
    in_rx: &Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {

    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    //let sig = &mut Sig { msk: None, cache: HashMap::new() };
    
    input_segment_info.push((in_t.id, in_t.output_type));
    input_segment_info.push((in_ry.id, in_ry.output_type));
    input_segment_info.push((in_rx.id, in_rx.output_type));

    let t = in_t.output.try_into().unwrap();
    let ry = in_ry.output.try_into().unwrap();
    let rx = in_rx.output.try_into().unwrap();
    let (mut h, mut hint_script) = ([0u8;64], script!());
    if !skip {
        (h, _, hint_script) = chunk_hash_p(
            t,
            ry,
            rx,
            pub_vky0.clone(),
        );
    }
    let output_type = h.ret_type();

    Segment { id: segment_id as u32, output_type, inputs: input_segment_info, output: Element::HashBytes(h), hint_script, scr_type: ScriptType::PreMillerHashP(pub_vky0) }
}

pub(crate) fn wrap_hint_hash_c(  
    skip: bool,  
    segment_id: usize,
    in_c: Vec<Segment>,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    let fqvec: Vec<ElemFq> = in_c
    .iter()
    .map(|f| {
        input_segment_info.push((f.id, f.output_type));
        f.output.try_into().unwrap()
    })
    .collect();

    let (mut c, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (c,_, hint_script) = chunk_hash_c(
             fqvec
            );
    }
    let output_type = c.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c), hint_script, scr_type: ScriptType::PreMillerHashC }
}



pub(crate) fn wrap_hints_precompute_px(
    skip: bool,
    segment_id: usize,
    in_py: &Segment,
    in_px: &Segment , in_pdy: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_py.id, in_py.output_type));
    input_segment_info.push((in_px.id, in_px.output_type));
    input_segment_info.push((in_pdy.id, in_pdy.output_type));

    let (mut p4x, mut hint_script) = (ElemFq::mock(), script!());
    if !skip {
        (p4x,_, hint_script) = chunk_precompute_px(
            in_py.output.try_into().unwrap(),
            in_px.output.try_into().unwrap(),
            in_pdy.output.try_into().unwrap());
    }
    let output_type = p4x.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p4x), hint_script, scr_type: ScriptType::PreMillerPrecomputePx }
}

pub(crate) fn wrap_hints_precompute_py(
    skip: bool,
    segment_id: usize,
    in_p: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_p.id, in_p.output_type));

    let (mut p3y, mut hint_script) = (ElemFq::mock(), script!());
    if !skip {
        (p3y, _, hint_script) = chunk_precompute_py(
            in_p.output.try_into().unwrap());
    }
    let output_type = p3y.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::FieldElem(p3y), hint_script, scr_type: ScriptType::PreMillerPrecomputePy }
}

pub(crate) fn wrap_hint_hash_c2(
    skip: bool,
    segment_id: usize,
    in_c: &Segment
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_c.id, in_c.output_type));

    let (mut c2, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (c2, _, hint_script) = chunk_hash_c2(in_c.output.try_into().unwrap());
    }
    let output_type = c2.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(c2), hint_script, scr_type: ScriptType::PreMillerHashC2 }
}

pub(crate) fn wrap_inv0(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_a.id, in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_inv0(in_a.output.try_into().unwrap());
    }
    let output_type = dmul0.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv0 }
}

pub(crate) fn wrap_inv1(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_a.id, in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_inv1(in_a.output.try_into().unwrap());
    }
    let output_type = dmul0.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv1 }
}

pub(crate) fn wrap_inv2(
    skip: bool,
    segment_id: usize,
    in_t1: &Segment,
    in_a: &Segment,
) -> Segment {
    
    let mut input_segment_info: Vec<(SegmentID, SegmentOutputType)> = vec![];
    input_segment_info.push((in_t1.id, in_t1.output_type));
    input_segment_info.push((in_a.id, in_a.output_type));

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_inv2(in_t1.output.try_into().unwrap(), in_a.output.try_into().unwrap());
    }
    let output_type = dmul0.ret_type();
    Segment { id:  segment_id as u32, output_type, inputs: input_segment_info, output: Element::Fp12(dmul0), hint_script, scr_type: ScriptType::PreMillerInv2 }
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
        (in_q4yc1.id, in_q4yc1.output_type),
        (in_q4yc0.id, in_q4yc0.output_type),
        (in_q4xc1.id, in_q4xc1.output_type),
        (in_q4xc0.id, in_q4xc0.output_type),
    ];

    let q4xc0: ark_bn254::Fq = in_q4xc0.output.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.output.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.output.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.output.try_into().unwrap();

    let (mut tmpt4, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (tmpt4,_, hint_script) = chunk_init_t4(
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
        );
    }
    let output_type = tmpt4.ret_type();
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
    in_a: &Segment,
) -> Segment {
    
    let input_segment_info = vec![(in_a.id, in_a.output_type)];

    let f_acc: ElemFp12Acc = in_a.output.try_into().unwrap();

    let (mut sq, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (sq,_, hint_script) = chunk_squaring(
            f_acc,
        );
    }

    let output_type = sq.ret_type();
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
    in_t4: &Segment,
    in_p4y: &Segment,
    in_p4x: &Segment,
) -> Segment {
    
    let input_segment_info = vec![
        (in_t4.id, in_t4.output_type),
        (in_p4y.id, in_p4y.output_type),
        (in_p4x.id, in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = in_t4.output.try_into().unwrap();
    let p4x: ark_bn254::Fq = in_p4x.output.try_into().unwrap();
    let p4y: ark_bn254::Fq = in_p4y.output.try_into().unwrap();

    let (mut dbl, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (dbl, _, hint_script) = chunk_point_dbl(
            t4,
            p4y,
            p4x,
        );
    }

    let output_type = dbl.ret_type();
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
    in_t4: &Segment,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,

    in_p4y: &Segment,
    in_p4x: &Segment,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_t4.id, in_t4.output_type),
        (in_q4yc1.id, in_q4yc1.output_type),
        (in_q4yc0.id, in_q4yc0.output_type),
        (in_q4xc1.id, in_q4xc1.output_type),
        (in_q4xc0.id, in_q4xc0.output_type),
        (in_p4y.id, in_p4y.output_type),
        (in_p4x.id, in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = in_t4.output.try_into().unwrap();
    let p4x: ark_bn254::Fq = in_p4x.output.try_into().unwrap();
    let p4y: ark_bn254::Fq = in_p4y.output.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.output.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.output.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.output.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.output.try_into().unwrap();

    let (mut dbladd, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (dbladd,_, hint_script) = chunk_point_ops(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            t4,
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
            p4y,
            p4x,
            ate,
        );
    }

    let output_type = dbladd.ret_type();
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
    in_a: &Segment,
    in_g: &Segment,
    is_dbl_blk: bool,
) -> Segment {
    
    let input_segment_info = vec![
        (in_a.id, in_a.output_type),
        (in_g.id, in_g.output_type),
    ];

    let f_acc: ElemFp12Acc = in_a.output.try_into().unwrap();
    let t4: ElemG2PointAcc = in_g.output.try_into().unwrap();

    let (mut temp, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (temp, _, hint_script) = chunk_sparse_dense_mul(
            f_acc,
            t4,
            is_dbl_blk,
        );
    }

    let output_type = temp.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(temp),
        hint_script,
        scr_type: ScriptType::SparseDenseMul(is_dbl_blk),
    }
}

pub(crate) fn wrap_hint_double_eval_mul_for_fixed_qs(
    skip: bool,
    segment_id: usize,
    in_p3y: &Segment,
    in_p3x: &Segment,
    in_p2y: &Segment,
    in_p2x: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3y.id, in_p3y.output_type),
        (in_p3x.id, in_p3x.output_type),
        (in_p2y.id, in_p2y.output_type),
        (in_p2x.id, in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = in_p2x.output.try_into().unwrap();
    let p2y: ark_bn254::Fq = in_p2y.output.try_into().unwrap();
    let p3x: ark_bn254::Fq = in_p3x.output.try_into().unwrap();
    let p3y: ark_bn254::Fq = in_p3y.output.try_into().unwrap();

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval, _, hint_script) = chunk_double_eval_mul_for_fixed_qs(
            // sig,(segment_id as u32, output_type),
            // input_segment_info.clone(),
            p3y,
            p3x,
            p2y,
            p2x,
            in_t2,
            in_t3,
        );
    }

    let output_type = leval.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
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
        (in_a.id, in_a.output_type),
        (in_b.id, in_b.output_type),
    ];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
    let b: ElemFp12Acc = in_b.output.try_into().unwrap();

    
    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_dense_dense_mul0(
            a.clone(),
            b.clone(),
        );
    }
    let output_type = dmul0.ret_type();
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
    in_a: &Segment,
    in_b: &Segment,
    in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_a.id, in_a.output_type),
        (in_b.id, in_b.output_type),
        (in_c.id, in_c.output_type),
    ];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
    let b: ElemFp12Acc = in_b.output.try_into().unwrap();
    let c: ElemFp12Acc = in_c.output.try_into().unwrap();

    

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1, _, hint_script) = chunk_dense_dense_mul1(
            a.clone(),
            b.clone(),
            c.clone(),
        );
    }

    let output_type = dmul1.ret_type();
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
    in_a: &Segment,
    in_b: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_a.id, in_a.output_type),
        (in_b.id, in_b.output_type),
    ];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
    let b: ElemSparseEval = in_b.output.try_into().unwrap();

    

    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_dense_dense_mul0(
            a.clone(),
            b.f.clone(),
        );
    }
    let output_type = dmul0.ret_type();
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
    in_a: &Segment,
    in_b: &Segment,
    in_c: &Segment,
) -> Segment {

    let input_segment_info = vec![
        (in_a.id, in_a.output_type),
        (in_b.id, in_b.output_type),
        (in_c.id, in_c.output_type),
    ];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
    let b: ElemSparseEval = in_b.output.try_into().unwrap();
    let c: ElemFp12Acc = in_c.output.try_into().unwrap();

    

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1, _, hint_script) = chunk_dense_dense_mul1(
            a.clone(),
            b.f.clone(),
            c.clone(),
        );
    }

    let output_type = dmul1.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::Fp12(dmul1),
        hint_script,
        scr_type: ScriptType::DenseDenseMul1(),
    }
}



pub(crate) fn wrap_hint_add_eval_mul_for_fixed_qs(
    skip: bool,
    segment_id: usize,
    in_p3y: &Segment,
    in_p3x: &Segment,
    in_p2y: &Segment,
    in_p2x: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3y.id, in_p3y.output_type),
        (in_p3x.id, in_p3x.output_type),
        (in_p2y.id, in_p2y.output_type),
        (in_p2x.id, in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = in_p2x.output.try_into().unwrap();
    let p2y: ark_bn254::Fq = in_p2y.output.try_into().unwrap();
    let p3x: ark_bn254::Fq = in_p3x.output.try_into().unwrap();
    let p3y: ark_bn254::Fq = in_p3y.output.try_into().unwrap();

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval,_, hint_script) = chunk_add_eval_mul_for_fixed_qs(
            p3y,
            p3x,
            p2y,
            p2x,

            in_t2,
            in_t3,
            pub_q2,
            pub_q3,
            ate,
        );
    }

    let output_type = leval.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::MillerSparseSparseAdd(([in_t2, in_t3, pub_q2, pub_q3], ate)),
    }
}

pub(crate) fn wrap_hints_frob_fp12(
    skip: bool,
    segment_id: usize,
    in_f: &Segment,
    power: usize,
) -> Segment {

    let input_segment_info = vec![(in_f.id, in_f.output_type)];

    let f = in_f.output.try_into().unwrap();

    

    let (mut cp, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (cp,_, hint_script) = chunk_frob_fp12(
            f,
            power,
        );
    }

    let output_type = cp.ret_type();
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
    in_t4: &Segment,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
    in_p4y: &Segment,
    in_p4x: &Segment,
    power: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_t4.id, in_t4.output_type),
        (in_q4yc1.id, in_q4yc1.output_type),
        (in_q4yc0.id, in_q4yc0.output_type),
        (in_q4xc1.id, in_q4xc1.output_type),
        (in_q4xc0.id, in_q4xc0.output_type),
        (in_p4y.id, in_p4y.output_type),
        (in_p4x.id, in_p4x.output_type),
    ];

    let t4: ElemG2PointAcc = in_t4.output.try_into().unwrap();
    let p4x: ark_bn254::Fq = in_p4x.output.try_into().unwrap();
    let p4y: ark_bn254::Fq = in_p4y.output.try_into().unwrap();
    let q4xc0: ark_bn254::Fq = in_q4xc0.output.try_into().unwrap();
    let q4xc1: ark_bn254::Fq = in_q4xc1.output.try_into().unwrap();
    let q4yc0: ark_bn254::Fq = in_q4yc0.output.try_into().unwrap();
    let q4yc1: ark_bn254::Fq = in_q4yc1.output.try_into().unwrap();

    let (mut temp, mut hint_script) = (ElemG2PointAcc::mock(), script!());
    if !skip {
        (temp, _, hint_script) = chunk_point_add_with_frob(
            // sig, (segment_id as u32, output_type),
            // input_segment_info.clone(),
            t4,
            q4yc1,
            q4yc0,
            q4xc1,
            q4xc0,
            p4y,
            p4x,
            power,
        );
    }

    let output_type = temp.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::G2Acc(temp),
        hint_script,
        scr_type: ScriptType::PostMillerAddWithFrob(power),
    }
}

pub(crate) fn wrap_hint_add_eval_mul_for_fixed_qs_with_frob(
    skip: bool,
    segment_id: usize,
    in_p3y: &Segment,
    in_p3x: &Segment,
    in_p2y: &Segment,
    in_p2x: &Segment,
    in_t2: ark_bn254::G2Affine,
    in_t3: ark_bn254::G2Affine,
    pub_q2: ark_bn254::G2Affine,
    pub_q3: ark_bn254::G2Affine,
    ate: i8,
) -> Segment {
    
    let input_segment_info = vec![
        (in_p3y.id, in_p3y.output_type),
        (in_p3x.id, in_p3x.output_type),
        (in_p2y.id, in_p2y.output_type),
        (in_p2x.id, in_p2x.output_type),
    ];

    let p2x: ark_bn254::Fq = in_p2x.output.try_into().unwrap();
    let p2y: ark_bn254::Fq = in_p2y.output.try_into().unwrap();
    let p3x: ark_bn254::Fq = in_p3x.output.try_into().unwrap();
    let p3y: ark_bn254::Fq = in_p3y.output.try_into().unwrap();

    let (mut leval, mut hint_script) = (ElemSparseEval::mock(), script!());
    if !skip {
        (leval, _, hint_script) = chunk_add_eval_mul_for_fixed_qs_with_frob(
            p3y,
            p3x,
            p2y,
            p2x,

            in_t2,
            in_t3,
            pub_q2,
            pub_q3,
            ate,
        );
    }

    let output_type = leval.ret_type();
    Segment {
        id: segment_id as u32,
        output_type,
        inputs: input_segment_info,
        output: Element::SparseEval(leval),
        hint_script,
        scr_type: ScriptType::PostMillerSparseAddWithFrob(([in_t2, in_t3, pub_q2, pub_q3], ate)),
    }
}


pub(crate) fn wrap_hints_dense_dense_mul0_by_constant(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

    let input_segment_info = vec![(in_a.id, in_a.output_type)];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
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

    


    let (mut dmul0, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul0,_, hint_script) = chunk_dense_dense_mul0_by_constant(
            a.clone(),
            fixedacc,
        );
    }

    let output_type = dmul0.ret_type();
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
    in_a: &Segment, in_c0: &Segment,
    constant: ark_bn254::Fq12,
) -> Segment {

    let input_segment_info = vec![
        (in_a.id, in_a.output_type),
        (in_c0.id, in_c0.output_type)
    ];

    let a: ElemFp12Acc = in_a.output.try_into().unwrap();
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

    let (mut dmul1, mut hint_script) = (ElemFp12Acc::mock(), script!());
    if !skip {
        (dmul1,_, hint_script) = chunk_dense_dense_mul1_by_constant(
            a.clone(),
            in_c0.output.try_into().unwrap(),
            fixedacc,
        );
    }

    let output_type = dmul1.ret_type();
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
    use ark_ff::{Field};


    #[test]
    fn test_wrap_cinv() {
        let f = ark_bn254::Fq12::ONE + ark_bn254::Fq12::ONE +  ark_bn254::Fq12::ONE;
        let hash = extern_hash_fps(fp12_to_vec(f), true);
        let c = ElemFp12Acc {f, hash};
        let output_type = c.ret_type();
        let seg = Segment {
            id: 0,
            output_type,
            inputs: vec![],
            output: Element::Fp12(c),
            hint_script: script!(),
            scr_type: ScriptType::NonDeterministic,
        };

        let inv0 = wrap_inv0(false, 1, &seg);
        let inv1 = wrap_inv1(false, 1, &inv0);
        let inv2 = wrap_inv2(false, 1, &inv1, &seg);

        let out: ElemFp12Acc = inv2.output.try_into().unwrap();
        println!("match {}", out.f == f.inverse().unwrap());
    }
}