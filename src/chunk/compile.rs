
use std::collections::HashMap;

use ark_ec::bn::BnConfig;
use bitcoin_script::script;
use treepp::Script;

use crate::{chunk::hint_models::ElemG1Point, treepp};
use crate::chunk::hint_models::ElemTraitExt;

use super::hint_models::ElemFq;
use super::taps_msm::chunk_msm;
use super::{assert::{groth16, Pubs}, hint_models::{ElemFp12Acc, ElemFr, ElemG2PointAcc, EvalIns}, primitves::gen_bitcom, segment::{ScriptType, Segment}, taps_msm::{chunk_hash_p}, taps_mul::*, taps_point_eval::*, taps_point_ops::*, taps_premiller::*, wots::WOTSPubKey};

pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 40;
pub const NUM_U160: usize = 574-32+19;


pub(crate) struct Vkey {
    pub(crate) q2: ark_bn254::G2Affine,
    pub(crate) q3: ark_bn254::G2Affine,
    pub(crate) p3vk: Vec<ark_bn254::G1Affine>,
    pub(crate) p1q1: ark_bn254::Fq12,
    pub(crate) vky0: ark_bn254::G1Affine,
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

pub(crate) fn compile_ops(
    vk: Vkey,
) -> Vec<bitcoin_script::Script>  {
    println!("Preparing segments");
    let mock_segments = segments_from_pubs(vk);
    println!("Generating op scripts");
    let op_scripts = op_scripts_from_segments(&mock_segments).into_iter().filter(|f| f.len() > 0).collect();
    op_scripts
}

pub(crate) fn compile_taps(
    vk: Vkey,
    pubkeys: HashMap<u32, WOTSPubKey>,
    ops_scripts: Vec<bitcoin_script::Script>,
) ->  Vec<bitcoin_script::Script> {
    let mock_segments = segments_from_pubs(vk);
    let bitcom_scripts: Vec<treepp::Script> = bitcom_scripts_from_segments(&mock_segments, pubkeys).into_iter().filter(|f| f.len() > 0).collect();
    assert_eq!(ops_scripts.len(), bitcom_scripts.len());
    let res: Vec<treepp::Script>  = ops_scripts.into_iter().zip(bitcom_scripts).map(|(op_scr, bit_scr)| 
        script!(
            {bit_scr}
            {op_scr}
        )   
    ).collect();

    res
}

fn segments_from_pubs(vk: Vkey) -> Vec<Segment> {
    let mut segments: Vec<Segment> = vec![];
    let g1 = ElemG1Point::mock();
    let g2 = ElemG2PointAcc::mock().t;
    let fr = ElemFr::mock();
    let s = ElemFp12Acc::mock();
    let c = ElemFp12Acc::mock();
    let eval_ins: EvalIns = EvalIns { p2: g1, p3: g1, p4: g1, q4: g2, c: c.f, s: s.f, ks: vec![fr] };

    let pubs: Pubs = Pubs { q2: vk.q2, q3: vk.q3, fixed_acc: vk.p1q1, ks_vks: vk.p3vk, vky0: vk.vky0 };
    groth16(true, &mut segments, eval_ins, pubs, &mut None);
    segments
}

pub(crate) fn op_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {

    let mut tap_point_ops = cached(|(a,b,c,d,e,f,g,h)| chunk_point_ops(a,b,c,d,e,f,g,h));
    let mut tap_sparse_dense_mul = cached(|(a, b, c)| chunk_sparse_dense_mul(a, b, c ));
    let mut tap_dense_dense_mul0_by_constant = cached(|(a, b)| chunk_dense_dense_mul0_by_constant(a, b)); 
    let mut tap_dense_dense_mul1_by_constant = cached(|(a, b, c)| chunk_dense_dense_mul1_by_constant(a, b, c)); 
    let mut tap_frob_fp12 = cached(|(a, b)| chunk_frob_fp12(a,b));
    let mut tap_point_add_with_frob = cached(|a| chunk_point_add_with_frob(ElemG2PointAcc::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), a));
    let mut chunk_hash_p = cached(|(a, b, c, d)| chunk_hash_p(a, b, c, d ));
    let mut tap_msm = cached(|(a, b, c)| chunk_msm(a, b, c ));
    let mut tap_double_eval_mul_for_fixed_qs = cached(|(a, b)| chunk_double_eval_mul_for_fixed_qs(a, b));
    let mut tap_add_eval_mul_for_fixed_qs = cached(|(a, b, c, d, e)| tap_add_eval_mul_for_fixed_qs(a, b, c, d, e));
    let mut tap_add_eval_mul_for_fixed_qs_with_frob = cached(|(a, b, c, d, e)| tap_add_eval_mul_for_fixed_qs_with_frob(a, b, c, d, e));
    let tap_init_t4 = chunk_init_t4(ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock());
    // let tap_precompute_py = chunk_precompute_py();
    // let tap_precompute_px = chunk_precompute_px();
    // let tap_hash_c = chunk_hash_c();
    // let tap_hash_c2 = chunk_hash_c2();
    let mut tap_squaring = cached(chunk_squaring);
    let mut tap_point_dbl = cached(|(a, b, c)| chunk_point_dbl(a, b, c));
    let mut tap_dense_dense_mul0 = cached(|(a, b)| chunk_dense_dense_mul0(a, b));
    let mut tap_dense_dense_mul1 = cached(|(a, b, c)| chunk_dense_dense_mul1(a, b, c));

    let mut op_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let scr_type = seg.scr_type.clone();

        match scr_type {
            ScriptType::NonDeterministic => {
                op_scripts.push(script!());
            },
            ScriptType::PreMillerInitT4 => {
                op_scripts.push(tap_init_t4.1.clone());
            }
            ScriptType::PreMillerPrecomputePy => {
                op_scripts.push(chunk_precompute_py(ElemFq::mock()).1);
            },
            ScriptType::PreMillerPrecomputePx => {
                op_scripts.push(chunk_precompute_px(ElemFq::mock(), ElemFq::mock(), ElemFq::mock()).1);
            },
            ScriptType::PreMillerHashC => {
                op_scripts.push(chunk_hash_c([ElemFq::mock(); 12].to_vec()).1);
            },
            ScriptType::PreMillerHashC2 => {
                op_scripts.push(chunk_hash_c2(ElemFp12Acc::mock()).1);
            },
            ScriptType::PreMillerInv0 => {
                op_scripts.push(chunk_inv0(ElemFp12Acc::mock()).1);
            },
            ScriptType::PreMillerInv1 => {
                op_scripts.push(chunk_inv1(ElemFp12Acc::mock()).1);
            },
            ScriptType::PreMillerInv2 => {
                op_scripts.push(chunk_inv2(ElemFp12Acc::mock(), ElemFp12Acc::mock()).1);
            },
            ScriptType::MillerSquaring => {
                op_scripts.push(tap_squaring( ElemFp12Acc::mock()).1);
            },
            ScriptType::MillerDoubleAdd(a) => {
                op_scripts.push(tap_point_ops((ElemG2PointAcc::mock(), ElemFq::mock(), ElemFq::mock(),ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), a)).1);
            },
            ScriptType::MillerDouble => {
                op_scripts.push(tap_point_dbl( (ElemG2PointAcc::mock(), ElemFq::mock(), ElemFq::mock()) ).1);
            },
            ScriptType::SparseDenseMul(dbl_blk) => {
                op_scripts.push(tap_sparse_dense_mul((ElemFp12Acc::mock(), ElemG2PointAcc::mock(), dbl_blk)).1);
            },
            ScriptType::DenseDenseMul0() => {
                op_scripts.push(tap_dense_dense_mul0((ElemFp12Acc::mock(), ElemFp12Acc::mock())).1);
            },
            ScriptType::DenseDenseMul1() => {
                op_scripts.push(tap_dense_dense_mul1( (ElemFp12Acc::mock(), ElemFp12Acc::mock(), ElemFp12Acc::mock())  ).1);
            },
            ScriptType::PostMillerDenseDenseMulByConst0(inp) => {
                op_scripts.push(tap_dense_dense_mul0_by_constant( (ElemFp12Acc::mock(), ElemFp12Acc {f: inp, hash: [0u8;64]}) ).1);
            },
            ScriptType::PostMillerDenseDenseMulByConst1(inp) => {
                op_scripts.push(tap_dense_dense_mul1_by_constant( (ElemFp12Acc::mock(), ElemFp12Acc::mock(), ElemFp12Acc {f: inp, hash: [0u8;64]}) ).1);
            },

            ScriptType::MSM(inp) => {
                let msm_window = 7;
                let g16_scalars = (0..inp.1.len()).into_iter().map(|_| ElemFr::mock()).collect();
                let msm_scr: Vec<Script> = tap_msm((msm_window, g16_scalars, inp.1)).iter().map(|f| f.1.clone()).collect();
                op_scripts.push(msm_scr[inp.0].clone());
            },
            ScriptType::PostMillerFrobFp12(power) => {
                op_scripts.push(tap_frob_fp12( (ElemFp12Acc::mock(), power as usize) ).1);
            },
            ScriptType::PostMillerAddWithFrob(ate) => {
                op_scripts.push(tap_point_add_with_frob(ate).1);
            },
            ScriptType::PreMillerHashP(inp) => {
                let chp = chunk_hash_p((ElemG1Point::mock(), ElemFq::mock(), ElemFq::mock(), inp));
                op_scripts.push(chp.1);
            },
            ScriptType::MillerSparseSparseDbl(inp) => {
                op_scripts.push(tap_double_eval_mul_for_fixed_qs((inp.0, inp.1)).0);
            },
            ScriptType::MillerSparseSparseAdd(inp) => {
                op_scripts.push(tap_add_eval_mul_for_fixed_qs((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).0);
            },
            ScriptType::PostMillerSparseAddWithFrob(inp) => {
                op_scripts.push(tap_add_eval_mul_for_fixed_qs_with_frob((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).0);
            },
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys_map: HashMap<u32, WOTSPubKey>) -> Vec<treepp::Script> {
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let sec_out = (seg.id as u32, seg.output_type);
        let sec_in: Vec<(u32, bool)> = seg.inputs.iter().map(|f| (f.0 as u32, f.1)).collect();
        match seg.scr_type {
            ScriptType::NonDeterministic => {
                bitcom_scripts.push(script!());
            },
            _ => {
                bitcom_scripts.push(gen_bitcom(&pubkeys_map, sec_out, sec_in));
            }
        }
    }
    bitcom_scripts
}

