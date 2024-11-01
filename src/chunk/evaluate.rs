use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::Field;
use bitcoin_script::script;
use std::collections::HashMap;

use crate::chunk::compile::ATE_LOOP_COUNT;
use crate::chunk::config::miller_config_gen;
use crate::chunk::msm::{bitcom_hash_p, bitcom_msm, hint_hash_p, hint_msm, tap_hash_p, tap_msm, HintInMSM};
use crate::chunk::primitves::emulate_extern_hash_fps;
use crate::chunk::{taps, taps_mul};
use crate::chunk::taps::{
    bitcom_add_eval_mul_for_fixed_Qs, bitcom_add_eval_mul_for_fixed_Qs_with_frob,
    bitcom_double_eval_mul_for_fixed_Qs,
    bitcom_frob_fp12, bitcom_hash_c, bitcom_hash_c2,  bitcom_initT4,
    bitcom_point_add_with_frob, bitcom_point_dbl, bitcom_point_ops, bitcom_precompute_Px,
    bitcom_precompute_Py,   hint_hash_c, hint_hash_c2,
     hint_init_T4,  hints_frob_fp12,
    hints_precompute_Px, hints_precompute_Py, tap_add_eval_mul_for_fixed_Qs,
    tap_add_eval_mul_for_fixed_Qs_with_frob, tap_double_eval_mul_for_fixed_Qs, tap_frob_fp12,
    tap_hash_c2,  tap_point_add_with_frob, tap_point_dbl, tap_point_ops,
    tap_precompute_Px, tap_precompute_Py,  HintInAdd,
    HintInDblAdd,  HintInDouble, HintInFrobFp12, HintInHashC,
    HintInHashP, HintInInitT4, HintInPrecomputePx, HintInPrecomputePy, HintInSparseAdd,
    HintInSparseDbl,   
    HintOutGrothC,  Link,
};

use crate::chunk::taps_mul::{bitcom_dense_dense_mul0, bitcom_dense_dense_mul0_by_constant, bitcom_dense_dense_mul1, bitcom_dense_dense_mul1_by_constant, bitcom_sparse_dense_mul, bitcom_squaring, hints_dense_dense_mul0, hints_dense_dense_mul0_by_constant, hints_dense_dense_mul1, hints_dense_dense_mul1_by_constant, tap_dense_dense_mul0, tap_dense_dense_mul0_by_constant, tap_dense_dense_mul1, tap_dense_dense_mul1_by_constant, tap_sparse_dense_mul, tap_squaring, HintInDenseMul0, HintInDenseMul1, HintInSparseDenseMul, HintInSquaring};
use crate::execute_script;

use super::config::{
    assign_link_ids, groth16_config_gen, msm_config_gen, post_miller_config_gen,
    pre_miller_config_gen,
};
use super::primitves::emulate_fq_to_nibbles;
use super::taps::{tap_hash_c, tap_initT4};
use super::taps::{HintOut, Sig};
use super::wots::WOTSPubKey;
use crate::treepp::*;

fn evaluate_miller_circuit(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, HintOut>,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
) -> (G2Affine, G2Affine, Option<(u32, Script)>) {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4,
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;

    let blocks = miller_config_gen();

    let mut itr = 0;

    fn get_index(blk_name: &str, id_to_sec: HashMap<String, (u32, bool)>) -> Link {
        id_to_sec.get(blk_name).unwrap().clone()
    }

    fn get_deps(deps: &str, id_to_sec: HashMap<String, (u32, bool)>) -> Vec<Link> {
        let splits: Vec<Link> = deps
            .split(",")
            .into_iter()
            .map(|s| get_index(s, id_to_sec.clone()))
            .collect();
        splits
    }

    let mut nt2 = t2.clone();
    let mut nt3 = t3.clone();
    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let bit = &ATE_LOOP_COUNT[j - 1];
        let blocks_of_a_loop = &blocks[itr];
        for k in 0..blocks_of_a_loop.len() {
            let block = &blocks_of_a_loop[k];
            let sec_out = get_index(&block.link_id, link_name_to_id.clone());
            let sec_in = get_deps(&block.dependencies, link_name_to_id.clone());
            let hints: Vec<HintOut> = block
                .dependencies
                .split(",")
                .into_iter()
                .map(|s| aux_output_per_link.get(s).unwrap().clone())
                .collect();
            println!(
                "{itr} ate {:?} ID {:?} deps {:?}",
                *bit, block.link_id, block.dependencies
            );
            println!(
                "{itr} {} ID {:?} deps {:?}",
                block.category, sec_out, sec_in
            );
            let blk_name = block.category.clone();
            if blk_name == "Sqr" {
                assert_eq!(hints.len(), 1);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::DenseMul1(r) => taps_mul::hint_squaring(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInSquaring::from_dmul1(r),
                    ),
                    HintOut::HashC(r) => taps_mul::hint_squaring(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInSquaring::from_hashc(r),
                    ),
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_squaring();
                let bcs_script = bitcom_squaring(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::Squaring(hintout));
            } else if blk_name == "DblAdd" {
                assert_eq!(hints.len(), 7);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 1..hints.len() {
                    match hints[i].clone() {
                        HintOut::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let q = G2Affine::new_unchecked(
                    ark_bn254::Fq2::new(ps[3], ps[2]),
                    ark_bn254::Fq2::new(ps[1], ps[0]),
                );
                let p = G1Affine::new_unchecked(ps[5], ps[4]);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDblAdd::from_initT4(r, p, q);
                        taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
                    }
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDblAdd::from_doubleadd(r, p, q);
                        taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInDblAdd::from_double(r, p, q);
                        taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
                    }
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_point_ops(*bit);
                let bcs_script =
                    bitcom_point_ops(pub_scripts_per_link_id, sec_out, sec_in.clone(), *bit);
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DblAdd(hintout));
            } else if blk_name == "Dbl" {
                assert_eq!(hints.len(), 3);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 1..hints.len() {
                    match hints[i].clone() {
                        HintOut::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p = G1Affine::new_unchecked(ps[1], ps[0]);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDouble::from_initT4(r, p.x, p.y);
                        taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    }
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDouble::from_doubleadd(r, p.x, p.y);
                        taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInDouble::from_double(r, p.x, p.y);
                        taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    }
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_point_dbl();
                let bcs_script = bitcom_point_dbl(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::Double(hintout));
            } else if blk_name == "SD1" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                    HintOut::Squaring(f) => f,
                    _ => panic!(),
                };
                let (sd_hint, hint_script) = match hints[1].clone() {
                    HintOut::DblAdd(f) => {
                        let hint_in = HintInSparseDenseMul::from_double_add_top(f, dense);
                        taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, true)
                    }
                    HintOut::Double(f) => {
                        let hint_in = HintInSparseDenseMul::from_double(f, dense);
                        taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, true)
                    }
                    _ => panic!(),
                };
                let ops_script = tap_sparse_dense_mul(true);
                let bcs_script =
                    bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::SparseDenseMul(sd_hint));
            } else if blk_name == "SS1" {
                assert_eq!(hints.len(), 4);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 0..hints.len() {
                    match hints[i].clone() {
                        HintOut::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                let hint_in: HintInSparseDbl =
                    HintInSparseDbl::from_groth_and_aux(p2, p3, nt2, nt3);
                let (hint_out, hint_script) =
                    taps::hint_double_eval_mul_for_fixed_Qs(sig, sec_out, sec_in.clone(), hint_in);
                let (ops_script, _, _) = tap_double_eval_mul_for_fixed_Qs(nt2, nt3);
                let bcs_script = bitcom_double_eval_mul_for_fixed_Qs(
                    pub_scripts_per_link_id,
                    sec_out,
                    sec_in.clone(),
                );
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(block.link_id.clone(), HintOut::SparseDbl(hint_out));
            } else if blk_name == "DD1" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    HintOut::SparseDenseMul(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    HintOut::SparseDbl(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul0::from_sparse_dense_dbl(c, d),
                );
                let ops_script = tap_dense_dense_mul0(false);
                let bcs_script =
                    bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul0(hint_out));
            } else if blk_name == "DD2" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    HintOut::SparseDenseMul(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    HintOut::SparseDbl(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul1::from_sparse_dense_dbl(c, d),
                );
                let ops_script = tap_dense_dense_mul1(false);
                let bcs_script =
                    bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul1(hint_out));
            } else if blk_name == "DD3" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    HintOut::DenseMul1(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = match hints[1].clone() {
                    HintOut::GrothC(r) => hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul0::from_dense_c(c, r),
                    ),
                    HintOut::HashC(r) => hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul0::from_hash_c(c, r),
                    ),
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_dense_dense_mul0(false);
                let bcs_script =
                    bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul0(hint_out));
            } else if blk_name == "DD4" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    HintOut::DenseMul1(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = match hints[1].clone() {
                    HintOut::GrothC(r) => hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_dense_c(c, r),
                    ),
                    HintOut::HashC(r) => hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_hash_c(c, r),
                    ),
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_dense_dense_mul1(false);
                let bcs_script =
                    bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul1(hint_out));
            } else if blk_name == "SD2" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                    HintOut::DenseMul1(f) => f,
                    _ => panic!(),
                };
                let (sd_hint, hint_script) = match hints[1].clone() {
                    HintOut::DblAdd(f) => {
                        let hint_in = HintInSparseDenseMul::from_doubl_add_bottom(f, dense);
                        taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, false)
                    }
                    _ => panic!(),
                };
                let ops_script = tap_sparse_dense_mul(false);
                let bcs_script =
                    bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::SparseDenseMul(sd_hint));
            } else if blk_name == "SS2" {
                assert_eq!(hints.len(), 4);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 0..hints.len() {
                    match hints[i].clone() {
                        HintOut::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                let hint_in: HintInSparseAdd =
                    HintInSparseAdd::from_groth_and_aux(p2, p3, q2, q3, nt2, nt3);
                let (hint_out, hint_script) = taps::hint_add_eval_mul_for_fixed_Qs(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    hint_in,
                    *bit,
                );
                let (ops_script, _, _) = tap_add_eval_mul_for_fixed_Qs(nt2, nt3, q2, q3, *bit);
                let bcs_script = bitcom_add_eval_mul_for_fixed_Qs(
                    pub_scripts_per_link_id,
                    sec_out,
                    sec_in.clone(),
                );
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(block.link_id.clone(), HintOut::SparseAdd(hint_out));
            } else if blk_name == "DD5" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    HintOut::SparseDenseMul(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    HintOut::SparseAdd(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul0::from_sparse_dense_add(c, d),
                );
                let ops_script = tap_dense_dense_mul0(false);
                let bcs_script =
                    bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul0(hint_out));
            } else if blk_name == "DD6" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    HintOut::SparseDenseMul(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    HintOut::SparseAdd(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script) = hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul1::from_sparse_dense_add(c, d),
                );
                let ops_script = tap_dense_dense_mul1(false);
                let bcs_script =
                    bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                   { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return (nt2, nt3, Some((sec_out.0, hint_script)));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul1(hint_out));
            } else {
                println!("unhandled {:?}", blk_name);
                panic!();
            }
        }
        itr += 1;
    }
    (nt2, nt3, None)
}

fn evaluate_post_miller_circuit(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, HintOut>,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    facc: String,
    tacc: String,
    fixed_acc: ark_bn254::Fq12,
) -> Option<(u32, Script)> {
    let tables = post_miller_config_gen(facc, tacc);

    let mut nt2 = t2;
    let mut nt3 = t3;
    for row in tables {
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| link_name_to_id.get(s).unwrap().clone())
            .collect();
        println!("row ID {:?} and deps {:?}", row.link_id, row.dependencies);
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        let hints_out: Vec<HintOut> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        if row.category.starts_with("Frob") {
            assert_eq!(hints_out.len(), 1);
            let hint_in = match hints_out[0].clone() {
                HintOut::GrothC(f) => HintInFrobFp12::from_groth_c(f),
                HintOut::HashC(f) => HintInFrobFp12::from_hash_c(f),
                _ => panic!(),
            };
            let mut power = 1;
            if row.category == "Frob2" {
                power = 2;
            } else if row.category == "Frob3" {
                power = 3;
            }
            let (h, hint_script) = hints_frob_fp12(sig, sec_out, sec_in.clone(), hint_in, power);
            let ops_script = tap_frob_fp12(power);
            let bcs_script = bitcom_frob_fp12(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::FrobFp12(h));
        } else if row.category == "DD1" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };
            let ((hint_out, hint_script), check_is_id) = match hints_out[1].clone() {
                HintOut::FrobFp12(d) => (
                    hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul0::from_dense_frob(c, d),
                    ),
                    false,
                ),
                HintOut::HashC(d) => {
                    // s
                    (
                        hints_dense_dense_mul0(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            HintInDenseMul0::from_hash_c(c, d),
                        ),
                        false,
                    )
                }
                _ => panic!("failed to match"),
            };
            let ops_script = tap_dense_dense_mul0(check_is_id);
            let bcs_script =
                bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul0(hint_out));
        } else if row.category == "DD2" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };
            let ((hint_out, hint_script), check_is_id) = match hints_out[1].clone() {
                HintOut::FrobFp12(d) => (
                    hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_dense_frob(c, d),
                    ),
                    false,
                ),
                HintOut::HashC(d) => (
                    hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_hash_c(c, d),
                    ),
                    false,
                ),
                _ => panic!("failed to match"),
            };
            let ops_script = tap_dense_dense_mul1(check_is_id);
            let bcs_script =
                bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul1(hint_out));
        } else if row.category == "DD3" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                HintOut::SparseDenseMul(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                HintOut::SparseAdd(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script) = hints_dense_dense_mul0(
                sig,
                sec_out,
                sec_in.clone(),
                HintInDenseMul0::from_sparse_dense_add(c, d),
            );
            let ops_script = tap_dense_dense_mul0(false);
            let bcs_script =
                bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul0(hint_out));
        } else if row.category == "DD4" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                HintOut::SparseDenseMul(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                HintOut::SparseAdd(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script) = hints_dense_dense_mul1(
                sig,
                sec_out,
                sec_in.clone(),
                HintInDenseMul1::from_sparse_dense_add(c, d),
            );
            let ops_script = tap_dense_dense_mul1(false);
            let bcs_script =
                bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul1(hint_out));
        } else if row.category == "Add1" || row.category == "Add2" {
            assert_eq!(hints_out.len(), 7);
            let mut ps: Vec<ark_bn254::Fq> = vec![];
            for i in 1..hints_out.len() {
                match hints_out[i].clone() {
                    HintOut::FieldElem(f) => {
                        ps.push(f);
                    }
                    _ => panic!(),
                }
            }
            let p = G1Affine::new_unchecked(ps[5], ps[4]);
            let q = G2Affine::new_unchecked(
                ark_bn254::Fq2::new(ps[3], ps[2]),
                ark_bn254::Fq2::new(ps[1], ps[0]),
            );
            if row.category == "Add1" {
                let (hintout, hint_script) = match hints_out[0].clone() {
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInAdd::from_doubleadd(r, p.x, p.y, q);
                        taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, 1)
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInAdd::from_double(r, p.x, p.y, q);
                        taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, 1)
                    }
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_point_add_with_frob(1);
                let bcs_script =
                    bitcom_point_add_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                    { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return Some((sec_out.0, hint_script));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(row.link_id.clone(), HintOut::Add(hintout));
            } else if row.category == "Add2" {
                let (hintout, hint_script) = match hints_out[0].clone() {
                    HintOut::Add(r) => {
                        let hint_in = HintInAdd::from_add(r, p.x, p.y, q);
                        taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, -1)
                    }
                    _ => panic!("failed to match"),
                };
                let ops_script = tap_point_add_with_frob(-1);
                let bcs_script =
                    bitcom_point_add_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script! {
                    { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return Some((sec_out.0, hint_script));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(row.link_id.clone(), HintOut::Add(hintout));
            }
        } else if row.category == "SD" {
            assert_eq!(hints_out.len(), 2);
            let dense = match hints_out[0].clone() {
                HintOut::DenseMul1(f) => f,
                _ => panic!(),
            };
            let (sd_hint, hint_script) = match hints_out[1].clone() {
                HintOut::Add(f) => {
                    let hint_in = HintInSparseDenseMul::from_add(f, dense);
                    taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, false)
                }
                _ => panic!(),
            };
            let ops_script = tap_sparse_dense_mul(false);
            let bcs_script =
                bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::SparseDenseMul(sd_hint));
        } else if row.category == "SS1" || row.category == "SS2" {
            assert_eq!(hints_out.len(), 4);
            let mut ps: Vec<ark_bn254::Fq> = vec![];
            for i in 0..hints_out.len() {
                match hints_out[i].clone() {
                    HintOut::FieldElem(f) => {
                        ps.push(f);
                    }
                    _ => panic!(),
                }
            }
            let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
            let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
            let hint_in: HintInSparseAdd =
                HintInSparseAdd::from_groth_and_aux(p2, p3, q2, q3, nt2, nt3);
            if row.category == "SS1" {
                let (hint_out, hint_script) = taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    hint_in,
                    1,
                );
                let (ops_script, _, _) =
                    tap_add_eval_mul_for_fixed_Qs_with_frob(nt2, nt3, q2, q3, 1);
                let bcs_script = bitcom_add_eval_mul_for_fixed_Qs_with_frob(
                    pub_scripts_per_link_id,
                    sec_out,
                    sec_in.clone(),
                );
                let script = script! {
                    { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return Some((sec_out.0, hint_script));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), HintOut::SparseAdd(hint_out));
            } else if row.category == "SS2" {
                let (hint_out, hint_script) = taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    hint_in,
                    -1,
                );
                let (ops_script, _, _) =
                    tap_add_eval_mul_for_fixed_Qs_with_frob(nt2, nt3, q2, q3, -1);
                let bcs_script = bitcom_add_eval_mul_for_fixed_Qs_with_frob(
                    pub_scripts_per_link_id,
                    sec_out,
                    sec_in.clone(),
                );
                let script = script! {
                    { hint_script.clone() }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                if exec_result.success {
                    return Some((sec_out.0, hint_script));
                } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                    for i in 0..exec_result.final_stack.len() {
                        println!("{i:} {:?}", exec_result.final_stack.get(i));
                    }
                    panic!()
                }
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), HintOut::SparseAdd(hint_out));
            } 
        
        } else if row.category == "DK1" {
            assert!(hints_out.len() == 1);
            let a = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };

            let (hint_out, hint_script) = hints_dense_dense_mul0_by_constant(sig, sec_out, sec_in.clone(), HintInDenseMul0 { a: a.c, b: fixed_acc });
            let ops_script = tap_dense_dense_mul0_by_constant(true, fixed_acc);
            let bcs_script =
                bitcom_dense_dense_mul0_by_constant(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul0(hint_out));
        } else if row.category == "DK2" {
            assert!(hints_out.len() == 2);
            let a = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script) = hints_dense_dense_mul1_by_constant(sig, sec_out, sec_in.clone(), HintInDenseMul1 { a: a.c, b: fixed_acc });
            let ops_script = tap_dense_dense_mul1_by_constant(true, fixed_acc);
            let bcs_script =
                bitcom_dense_dense_mul1_by_constant(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul1(hint_out));
        } else {
            panic!();
        } 
    
    
    
    }

    None
}

fn evaluate_groth16_params(
    sig: &mut Sig, // TODO: add sig values here ?
    link_name_to_id: HashMap<String, (u32, bool)>,
    p2: G1Affine,
    p3: G1Affine,
    p4: G1Affine,
    q4: G2Affine,
    c: Fq12,
    s: Fq12,
    ks: Vec<ark_bn254::Fr>,
) -> HashMap<String, HintOut> {
    let cv = vec![
        c.c0.c0.c0, c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0, c.c0.c2.c1, c.c1.c0.c0,
        c.c1.c0.c1, c.c1.c1.c0, c.c1.c1.c1, c.c1.c2.c0, c.c1.c2.c1,
    ];

    let sv = vec![
        s.c0.c0.c0, s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0, s.c0.c2.c1, s.c1.c0.c0,
        s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0, s.c1.c2.c1,
    ];

    let cvinv = c.inverse().unwrap();
    let cvinvhash = emulate_extern_hash_fps(
        vec![
            cvinv.c0.c0.c0,
            cvinv.c0.c0.c1,
            cvinv.c0.c1.c0,
            cvinv.c0.c1.c1,
            cvinv.c0.c2.c0,
            cvinv.c0.c2.c1,
            cvinv.c1.c0.c0,
            cvinv.c1.c0.c1,
            cvinv.c1.c1.c0,
            cvinv.c1.c1.c1,
            cvinv.c1.c2.c0,
            cvinv.c1.c2.c1,
        ],
        false,
    );

    let gparams = groth16_config_gen();
    let gouts = vec![
        HintOut::FieldElem(p4.y),
        HintOut::FieldElem(p4.x),
        HintOut::FieldElem(p3.y),
        HintOut::FieldElem(p3.x),
        HintOut::FieldElem(p2.y),
        HintOut::FieldElem(p2.x),
        HintOut::FieldElem(cv[11]),
        HintOut::FieldElem(cv[10]),
        HintOut::FieldElem(cv[9]),
        HintOut::FieldElem(cv[8]),
        HintOut::FieldElem(cv[7]),
        HintOut::FieldElem(cv[6]),
        HintOut::FieldElem(cv[5]),
        HintOut::FieldElem(cv[4]),
        HintOut::FieldElem(cv[3]),
        HintOut::FieldElem(cv[2]),
        HintOut::FieldElem(cv[1]),
        HintOut::FieldElem(cv[0]),
        HintOut::FieldElem(sv[11]),
        HintOut::FieldElem(sv[10]),
        HintOut::FieldElem(sv[9]),
        HintOut::FieldElem(sv[8]),
        HintOut::FieldElem(sv[7]),
        HintOut::FieldElem(sv[6]),
        HintOut::FieldElem(sv[5]),
        HintOut::FieldElem(sv[4]),
        HintOut::FieldElem(sv[3]),
        HintOut::FieldElem(sv[2]),
        HintOut::FieldElem(sv[1]),
        HintOut::FieldElem(sv[0]),
        HintOut::GrothC(HintOutGrothC {
            c: cvinv,
            chash: cvinvhash,
        }),
        HintOut::FieldElem(q4.y.c1),
        HintOut::FieldElem(q4.y.c0),
        HintOut::FieldElem(q4.x.c1),
        HintOut::FieldElem(q4.x.c0),
        HintOut::ScalarElem(ks[0]),
        HintOut::ScalarElem(ks[1]),
        HintOut::ScalarElem(ks[2]),
    ];
    assert_eq!(gparams.len(), gouts.len());

    let mut id_to_witness: HashMap<String, HintOut> = HashMap::new();
    for i in 0..gparams.len() {
        id_to_witness.insert(gparams[i].link_id.clone(), gouts[i].clone());
    }

    let mut tups: Vec<(u32, [u8; 64])> = Vec::new();
    for (txt, wit) in id_to_witness.iter() {
        let id = link_name_to_id.get(txt).unwrap().clone().0;
        match wit {
            HintOut::FieldElem(f) => {
                tups.push((id, emulate_fq_to_nibbles(*f)));
            }
            HintOut::GrothC(f) => {
                tups.push((id, f.chash));
            }
            _ => (),
        }
    }
    id_to_witness
}

fn evaluate_msm(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, HintOut>,
    pub_ins: usize,
    qs: Vec<ark_bn254::G1Affine>,
) -> Option<(u32, bitcoin_script::Script)> {
    let tables = msm_config_gen(String::from("k0,k1,k2"));
    let mut msm_tap_index = 0;
    for row in tables {
        println!(
            "itr {:?} ID {:?} deps {:?}",
            msm_tap_index, row.link_id, row.dependencies
        );
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| link_name_to_id.get(s).unwrap().clone())
            .collect();
        let hints: Vec<HintOut> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, sec_in);
        if row.category == "MSM" {
            assert!(
                (hints.len() == pub_ins && msm_tap_index == 0)
                    || (hints.len() == pub_ins + 1 && msm_tap_index > 0)
            );
            let mut scalars = vec![];
            for i in 0..pub_ins {
                let x = match hints[i] {
                    HintOut::ScalarElem(r) => r,
                    _ => panic!("failed to match"),
                };
                scalars.push(x);
            }
            let mut acc = ark_bn254::G1Affine::identity();
            for i in pub_ins..hints.len() {
                let x = match &hints[i] {
                    HintOut::MSM(r) => r,
                    _ => panic!("failed to match"),
                };
                acc = x.t;
            }
            let (hint_res, hint_script) = hint_msm(
                sig,
                sec_out,
                sec_in.clone(),
                HintInMSM { t: acc, scalars },
                msm_tap_index,
                qs.clone(),
            );
            let ops_script = tap_msm(8, msm_tap_index, qs.clone());
            let bcs_script = bitcom_msm(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);

            aux_output_per_link.insert(row.link_id, HintOut::MSM(hint_res));
        }
        msm_tap_index += 1;
    }

    None
}

fn evaluate_pre_miller_circuit(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, HintOut>,
    vky0: ark_bn254::G1Affine
) -> Option<(u32, bitcoin_script::Script)> {
    let tables = pre_miller_config_gen();

    for row in tables {
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| link_name_to_id.get(s).unwrap().clone())
            .collect();
        let hints: Vec<HintOut> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        println!("row name {:?} ID {:?}", row.category, sec_out);
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, sec_in);

        if row.category == "T4Init" {
            assert!(hints.len() == 4);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (hint_res, hint_script) = hint_init_T4(
                sig,
                sec_out,
                sec_in.clone(),
                HintInInitT4::from_groth_q4(xs),
            );
            let ops_script = tap_initT4();
            let bcs_script = bitcom_initT4(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);

            aux_output_per_link.insert(row.link_id, HintOut::InitT4(hint_res));
        } else if row.category == "PrePy" {
            assert!(hints.len() == 1);
            let pt = match hints[0] {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let (pyd, hint_script) = hints_precompute_Py(
                sig,
                sec_out,
                sec_in.clone(),
                HintInPrecomputePy::from_point(pt),
            );
            let ops_script = tap_precompute_Py();
            let bcs_script = bitcom_precompute_Py(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let len = script.len();
            let exec_result = execute_script(script);
            if exec_result.success {
                println!("success {}", len);
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);

            aux_output_per_link.insert(row.link_id, HintOut::FieldElem(pyd));
        } else if row.category == "PrePx" {
            assert!(hints.len() == 3);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (pxd, hint_script) = hints_precompute_Px(
                sig,
                sec_out,
                sec_in.clone(),
                HintInPrecomputePx::from_points(xs),
            );
            let ops_script = tap_precompute_Px();
            let bcs_script = bitcom_precompute_Px(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);

            aux_output_per_link.insert(row.link_id, HintOut::FieldElem(pxd));
        } else if row.category == "HashC" {
            assert!(hints.len() == 12);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (hout, hint_script) =
                hint_hash_c(sig, sec_out, sec_in.clone(), HintInHashC::from_points(xs));
            let ops_script = tap_hash_c();
            let bcs_script = bitcom_hash_c(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::HashC(hout));
        } else if row.category == "HashC2" {
            assert!(hints.len() == 1);
            let hint_in_hashc2 = match hints[0].clone() {
                HintOut::HashC(r) => HintInHashC::from_hashc(r), // c->c2
                HintOut::GrothC(r) => HintInHashC::from_grothc(r), // cinv -> cinv2
                _ => panic!("failed to match"),
            };
            let (hout, hint_script) = hint_hash_c2(
                sig,
                sec_out,
                sec_in.clone(),
                hint_in_hashc2,
            );
            let ops_script = tap_hash_c2();
            let bcs_script = bitcom_hash_c2(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            if !aux_output_per_link.contains_key(&row.link_id) {
                aux_output_per_link.insert(row.link_id, HintOut::HashC(hout));
            }
        } else if row.category == "DD1" {
            assert!(hints.len() == 2);
            let d = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let (c, hint_script) = match hints[0].clone() {
                HintOut::HashC(c) => hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul0::from_groth_hc(c, d),
                ),
                _ => panic!("failed to match"),
            };
            let ops_script = tap_dense_dense_mul0(true);
            let bcs_script =
                bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                {bcs_script}
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::DenseMul0(c));
        } else if row.category == "DD2" {
            assert!(hints.len() == 3);
            let b = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            // let c0 = match hints[2].clone() {
            //     HintOut::GrothC(r) => r,
            //     _ => panic!("failed to match"),
            // };
            let (hout, hint_script) = match hints[0].clone() {
                HintOut::HashC(a) => hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul1::from_groth_hc(a, b),
                ),
                _ => panic!("failed to match"),
            };
            let ops_script = tap_dense_dense_mul1(true);
            let bcs_script =
                bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::DenseMul1(hout));
        } else if row.category == "P3Hash" {
            assert!(hints.len() == 3);
            let t = match hints[0].clone() {
                HintOut::MSM(r) => r.t,
                _ => panic!("failed to match"),
            };
            let p3y = match hints[1].clone() {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let p3x = match hints[2].clone() {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };

            let ops_script = tap_hash_p(vky0);
            let (_, hint_script) = hint_hash_p(
                sig,
                sec_out,
                sec_in.clone(),
                HintInHashP {
                    qx: vky0.x,
                    qy: vky0.y,
                    tx: t.x,
                    ty: t.y,
                    rx: p3x,
                    ry: p3y,
                },
            );
            let bcs_script = bitcom_hash_p(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script! {
                { hint_script.clone() }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            if exec_result.success {
                return Some((sec_out.0, hint_script));
            } else if !exec_result.success && exec_result.final_stack.len() > 1 {
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            }
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
        }
    }
    None
}

pub fn evaluate(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    p2: G1Affine,
    p3: G1Affine,
    p4: G1Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    q4: G2Affine,
    c: Fq12,
    s: Fq12,
    fixed_acc: ark_bn254::Fq12,
    ks: Vec<ark_bn254::Fr>,
    ks_vks: Vec<ark_bn254::G1Affine>,
    vky0: ark_bn254::G1Affine,
) -> Option<(u32, bitcoin_script::Script)> {
    let (link_name_to_id, facc, tacc) = assign_link_ids();
    let mut aux_out_per_link: HashMap<String, HintOut> = HashMap::new();

    let grothmap = evaluate_groth16_params(
        sig,
        link_name_to_id.clone(),
        p2,
        p3,
        p4,
        q4,
        c,
        s,
        ks.clone(),
    );
    aux_out_per_link.extend(grothmap);

    let re = evaluate_msm(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        ks.len(),
        ks_vks,
    );
    if re.is_some() {
        println!("Disprove evaluate_msm");
        return re;
    }

    let re = evaluate_pre_miller_circuit(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        vky0,
    );
    if re.is_some() {
        println!("Disprove evaluate_pre_miller_circuit");
        return re;
    }

    let (nt2, nt3, re) = evaluate_miller_circuit(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        q2,
        q3,
        q2,
        q3,
    );
    if re.is_some() {
        println!("Disprove evaluate_miller_circuit");
        return re;
    }
    let re = evaluate_post_miller_circuit(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        nt2,
        nt3,
        q2,
        q3,
        facc.clone(),
        tacc,
        fixed_acc,
    );
    if re.is_some() {
        println!("Disprove evaluate_post_miller_circuit");
        return re;
    }

    let hint = aux_out_per_link.get("fin");
    if hint.is_none() {
        println!("debug hintmap {:?}", aux_out_per_link);
    } else {
        let hint = hint.unwrap();
        match hint {
            HintOut::DenseMul1(c) => {
                assert_eq!(c.c, ark_bn254::Fq12::ONE);
            }
            _ => {}
        }
    }
    None
}
// 32 byte
// compact 9196 <- disprove
// not 4707 <- assert

// 20 byte
// compact 5908 <- disprove
// not 3027 <- assert

// 32-byte commit: 50 x 4707
// 20-byte commit: 598 x 3027
// total locking script: 50 x 4707 + 598 x 3027  = 20,45,496 bytes
// unlocking script size: 639408
