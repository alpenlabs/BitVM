
use std::collections::HashMap;

use ark_ff::{AdditiveGroup, Field, UniformRand};
use bitcoin_script::script;
use rand::{rngs::mock, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{chunk::hint_models::{ElemG1Point, G1PointExt}, treepp};

use super::{acc::{groth16, Pubs}, evaluate::EvalIns, hint_models::{ElemG2PointAcc, Element}, msm::{bitcom_hash_p, bitcom_msm, tap_hash_p, tap_msm}, segment::{ScriptType, Segment}, taps::*, taps_mul::*, wots::WOTSPubKey};

pub(crate) fn get_tapscript_link_ids() -> Vec<u32>  {
    vec![]
}

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
    let bitcom_scripts = bitcom_scripts_from_segments(&mock_segments, pubkeys);
    let res  =ops_scripts.into_iter().zip(bitcom_scripts).map(|(op_scr, bit_scr)| script!(
        {op_scr}
        {bit_scr}
    )).collect();
    res
}

fn segments_from_pubs(vk: Vkey) -> Vec<Segment> {
    let mut segments: Vec<Segment> = vec![];
    let g1 = ElemG1Point::mock();
    let g2 = ElemG2PointAcc::mock().t;
    let fr = ark_bn254::Fr::ONE;
    let s = ark_bn254::Fq12::ONE;
    let c = ark_bn254::Fq12::ONE;
    let eval_ins: EvalIns = EvalIns { p2: g1, p3: g1, p4: g1, q4: g2, c, s, ks: vec![fr] };

    let pubs: Pubs = Pubs { q2: vk.q2, q3: vk.q3, fixed_acc: vk.p1q1, ks_vks: vk.p3vk, vky0: vk.vky0 };
    groth16(true, &mut segments, eval_ins, pubs, &mut None);
    segments
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

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys_map: HashMap<u32, WOTSPubKey>) -> Vec<treepp::Script> {
    // let pubkeys_map: HashMap<u32, WOTSPubKey> = pubkeys
    //     .into_iter()
    //     .enumerate()
    //     .map(|(i, pk)| (i as u32, pk))
    //     .collect();
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

