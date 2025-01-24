
use std::collections::HashMap;

use ark_ec::bn::BnConfig;
use bitcoin_script::script;
use treepp::Script;
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::groth16::g16::{PublicKeys, N_TAPLEAVES};
use crate::{chunk::element::ElemG1Point, treepp};
use crate::chunk::element::ElemTraitExt;

use super::blake3compiled::hash_messages;
use super::element::{ElemFp6, ElemFq, ElementType};
use super::taps_msm::{chunk_hash_p, chunk_msm};
use super::{assert::{groth16, Pubs}, element::{ElemFp12Acc, ElemFr, ElemG2PointAcc, EvalIns}, primitves::gen_bitcom, segment::{ScriptType, Segment}, taps_mul::*, taps_point_eval::*, taps_point_ops::*, taps_premiller::*, wots::WOTSPubKey};

pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 32;
pub const NUM_U160: usize = 560;
const VALIDATING_TAPS: usize = 7;
const HASHING_TAPS: usize = NUM_U160;
pub const NUM_TAPS: usize = HASHING_TAPS + VALIDATING_TAPS; 

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
    let op_scripts: Vec<Script> = op_scripts_from_segments(&mock_segments).into_iter().collect();
    assert_eq!(op_scripts.len(), N_TAPLEAVES);
    op_scripts
}

pub(crate) fn compile_taps(
    vk: Vkey,
    inpubkeys: PublicKeys,
    ops_scripts: Vec<bitcoin_script::Script>,
) ->  Vec<bitcoin_script::Script> {
    let mock_segments = segments_from_pubs(vk);

    let mut scalar_pubkeys = inpubkeys.0.to_vec();
    scalar_pubkeys.reverse();
    let mut felts_pubkeys = inpubkeys.1.to_vec();
    felts_pubkeys.reverse();
    let mut hash_pubkeys = inpubkeys.2.to_vec();
    hash_pubkeys.reverse();
    let mock_felt_pub = inpubkeys.0[0];

    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    for si  in 0..mock_segments.len() {
        let s = &mock_segments[si];
        if s.is_validation {
            let mock_fld_pub_key = WOTSPubKey::P256(mock_felt_pub);
            pubkeys.insert(si as u32, mock_fld_pub_key);
        } else {
            if s.result.1 == ElementType::FieldElem {
                pubkeys.insert(si as u32, WOTSPubKey::P256(felts_pubkeys.pop().unwrap()));
            } else if s.result.1 == ElementType::ScalarElem {
                pubkeys.insert(si as u32, WOTSPubKey::P256(scalar_pubkeys.pop().unwrap()));
            } else {
                pubkeys.insert(si as u32, WOTSPubKey::P160(hash_pubkeys.pop().unwrap()));
            }
        }
    }

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
    let eval_ins: EvalIns = EvalIns { p2: g1, p4: g1, q4: g2, c: c.f, s: s.f, ks: vec![fr] };

    let pubs: Pubs = Pubs { q2: vk.q2, q3: vk.q3, fixed_acc: vk.p1q1, ks_vks: vk.p3vk, vky0: vk.vky0 };
    groth16(true, &mut segments, eval_ins, pubs, &mut None);
    segments
}

pub(crate) fn op_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {
   fn serialize_element_types(elems: &[ElementType]) -> String {
        // 1. Convert each variant to its string representation.
        let joined = elems
            .iter()
            .map(|elem| format!("{:?}", elem)) // uses #[derive(Debug)]
            .collect::<Vec<String>>()
            .join("-");
    
        // 2. Compute a simple 64-bit hash of that string
        let mut hasher = DefaultHasher::new();
        joined.hash(&mut hasher);
        let unique_hash = hasher.finish();
    
        // 3. Concatenate final result as "ENUM1-ENUM2-ENUM3|hash"
        format!("{}|{}", joined, unique_hash)
    }

    let mut tap_point_ops = cached(|(a,b,c,d,e,f,g)| chunk_point_ops(a,b,c,d,e,f,g));
    let mut tap_sparse_dense_mul = cached(|(a, b, c)| chunk_sparse_dense_mul(a, b, c ));
    let mut tap_final_verify = cached(|(a, b)| chunk_verify_fp12_is_unity(a, b)); 
    let mut tap_frob_fp12 = cached(|(a, b)| chunk_frob_fp12(a,b));
    let mut tap_point_add_with_frob = cached(|a| chunk_point_add_with_frob(ElemG2PointAcc::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemG1Point::mock(), a));
    let mut chunk_hash_p = cached(|(a, b)| chunk_hash_p(a, b ));
    let mut tap_msm = cached(|(a, b, c)| chunk_msm(a, b, c ));
    let mut tap_multiply_point_evals_on_tangent_for_fixed_g2 = cached(|(a, b)| chunk_multiply_point_evals_on_tangent_for_fixed_g2(ElemG1Point::mock(), ElemG1Point::mock(), a, b));
    let mut tap_multiply_point_evals_on_chord_for_fixed_g2 = cached(|(a, b, c, d, e)| chunk_multiply_point_evals_on_chord_for_fixed_g2(ElemG1Point::mock(), ElemG1Point::mock(), a, b, c, d, e));
    let mut tap_multiply_point_evals_on_chord_for_fixed_g2_with_frob = cached(|(a, b, c, d, e)| chunk_multiply_point_evals_on_chord_for_fixed_g2_with_frob(ElemG1Point::mock(), ElemG1Point::mock(), a, b, c, d, e));
    let tap_init_t4 = chunk_init_t4(ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock());
    let mut tap_squaring = cached(chunk_squaring);
    let mut tap_point_dbl = cached(|(a, b)| chunk_point_dbl(a, b));
    let mut tap_dense_dense_mul0 = cached(|(a, b)| chunk_dense_dense_mul0(a, b));
    let mut tap_dense_dense_mul1 = cached(|(a, b, c)| chunk_dense_dense_mul1(a, b, c));

    let mut op_scripts: Vec<treepp::Script> = vec![];

    let mut hashing_script_cache: HashMap<String, Script> = HashMap::new();
    for s in segments {
        if s.is_validation || s.scr_type == ScriptType::NonDeterministic {
            continue;
        }
        let mut elem_types_to_hash: Vec<ElementType> = s.parameter_ids.iter().rev().map(|f| f.1).collect();
        elem_types_to_hash.push(s.result.1);
        let elem_types_str = serialize_element_types(&elem_types_to_hash);
        if !hashing_script_cache.contains_key(&elem_types_str) {
            let hash_scr = script!(
                {hash_messages(elem_types_to_hash)}
                OP_TRUE
            );
            hashing_script_cache.insert(elem_types_str, hash_scr);
        }
    };

    for i in 0..segments.len() {
        let seg= &segments[i];
        let scr_type = seg.scr_type.clone();
        if scr_type == ScriptType::NonDeterministic {
            continue;
        }

        let op_scr  = match scr_type {
            ScriptType::NonDeterministic => {
                script!()
            },
            ScriptType::ValidateG1IsOnCurve => {
                chunk_verify_g1_is_on_curve(ElemFq::mock(), ElemFq::mock()).1
            }
            ScriptType::ValidateG1HashIsOnCurve => {
                chunk_verify_g1_hash_is_on_curve(ElemG1Point::mock()).1
            }
            ScriptType::ValidateG2IsOnCurve => {
                chunk_verify_g2_on_curve(ElemFq::mock(), ElemFq::mock(), ElemFq::mock(), ElemFq::mock()).1
            },
            ScriptType::ValidateFq12OnField => {
                chunk_verify_fq12_is_on_field([ElemFq::mock(); 12].to_vec()).1
            }
            ScriptType::PreMillerInitT4 => {
                tap_init_t4.1.clone()
            }
            ScriptType::PreMillerPrecomputeP => {
                chunk_precompute_p(ElemFq::mock(), ElemFq::mock()).1
            },
            ScriptType::PreMillerPrecomputePFromHash => {
                chunk_precompute_p_from_hash(ElemG1Point::mock()).1
            },
            ScriptType::PreMillerHashC => {
                chunk_hash_c([ElemFq::mock(); 12].to_vec()).1
            },
            ScriptType::PreMillerInv0 => {
                chunk_inv0(ElemFp12Acc::mock()).1
            },
            ScriptType::PreMillerInv1 => {
                chunk_inv1(ElemFp6::mock()).1
            },
            ScriptType::PreMillerInv2 => {
                chunk_inv2(ElemFp6::mock(), ElemFp12Acc::mock()).1
            },
            ScriptType::MillerSquaring => {
                tap_squaring( ElemFp12Acc::mock()).1
            },
            ScriptType::MillerDoubleAdd(a) => {
                tap_point_ops((ElemG2PointAcc::mock(), ElemFq::mock(), ElemFq::mock(),ElemFq::mock(), ElemFq::mock(), ElemG1Point::mock(), a)).1
            },
            ScriptType::MillerDouble => {
                tap_point_dbl( (ElemG2PointAcc::mock(), ElemG1Point::mock()) ).1
            },
            ScriptType::SparseDenseMul(dbl_blk) => {
                tap_sparse_dense_mul((ElemFp12Acc::mock(), ElemG2PointAcc::mock(), dbl_blk)).1
            },
            ScriptType::DenseDenseMul0() => {
                tap_dense_dense_mul0((ElemFp12Acc::mock(), ElemFp12Acc::mock())).1
            },
            ScriptType::DenseDenseMul1() => {
                tap_dense_dense_mul1( (ElemFp12Acc::mock(), ElemFp12Acc::mock(), ElemFp6::mock())  ).1
            },
            ScriptType::PostMillerFinalVerify(inp) => {
                tap_final_verify( (ElemFp12Acc::mock(), ElemFp12Acc {f: inp, hash: [0u8;64]}) ).1
            },
            ScriptType::MSM(inp) => {
                let msm_window = 7;
                let g16_scalars = (0..inp.1.len()).into_iter().map(|_| ElemFr::mock()).collect();
                let msm_scr: Vec<Script> = tap_msm((msm_window, g16_scalars, inp.1)).iter().map(|f| f.1.clone()).collect();
                msm_scr[inp.0].clone()
            },
            ScriptType::PostMillerFrobFp12(power) => {
                tap_frob_fp12( (ElemFp12Acc::mock(), power as usize) ).1
            },
            ScriptType::PostMillerAddWithFrob(ate) => {
                tap_point_add_with_frob(ate).1
            },
            ScriptType::PreMillerHashP(inp) => {
                chunk_hash_p((ElemG1Point::mock(), inp)).1
            },
            ScriptType::MillerSparseSparseDbl(inp) => {
                tap_multiply_point_evals_on_tangent_for_fixed_g2((inp.0, inp.1)).1
            },
            ScriptType::MillerSparseSparseAdd(inp) => {
                tap_multiply_point_evals_on_chord_for_fixed_g2((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).1
            },
            ScriptType::PostMillerSparseAddWithFrob(inp) => {
                tap_multiply_point_evals_on_chord_for_fixed_g2_with_frob((inp.0[0], inp.0[1], inp.0[2], inp.0[3], inp.1)).1
            },
        };
        if seg.is_validation { // validating segments do not have output hash, so don't add hashing layer; they are self sufficient
            op_scripts.push(op_scr);
        } else {
            let mut elem_types_to_hash: Vec<ElementType> = seg.parameter_ids.iter().rev().map(|(_, param_seg_type)| *param_seg_type).collect();
            elem_types_to_hash.push(seg.result.1);
            let elem_types_str = serialize_element_types(&elem_types_to_hash);
            let hash_scr = hashing_script_cache.get(&elem_types_str).unwrap();
            assert!(hash_scr.len() > 0);
            op_scripts.push(script!(
                {op_scr}
                {hash_scr.clone()}
            ));
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys_map: HashMap<u32, WOTSPubKey>) -> Vec<treepp::Script> {
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let mut sec = vec![];
        if !seg.is_validation {
            sec.push((seg.id as u32, segments[seg.id as usize].result.0.output_is_field_element()));
        };
        let sec_in: Vec<(u32, bool)> = seg.parameter_ids.iter().map(|(f, _)| {
            let elem = &segments[*(f) as usize];
            let elem_type = elem.result.0.output_is_field_element();
            (*f, elem_type)
        }).collect();
        sec.extend_from_slice(&sec_in);
        match seg.scr_type {
            ScriptType::NonDeterministic => {
                bitcom_scripts.push(script!());
            },
            _ => {
                bitcom_scripts.push(gen_bitcom(&pubkeys_map, sec));
            }
        }
    }
    bitcom_scripts
}

