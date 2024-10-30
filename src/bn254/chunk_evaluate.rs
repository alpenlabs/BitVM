use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::Field;
use bitcoin::opcodes::OP_TRUE;
use bitcoin_script::script;
use std::collections::HashMap;

use crate::bn254::chunk_compile::ATE_LOOP_COUNT;
use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_msm::{bitcom_msm, hint_msm, tap_msm, HintInMSM};
use crate::bn254::chunk_primitves::emulate_extern_hash_fps;
use crate::bn254::chunk_taps;
use crate::bn254::chunk_taps::{
    bitcom_add_eval_mul_for_fixed_Qs, bitcom_add_eval_mul_for_fixed_Qs_with_frob,
    bitcom_dense_dense_mul0, bitcom_dense_dense_mul1, bitcom_double_eval_mul_for_fixed_Qs,
    bitcom_frob_fp12, bitcom_hash_c, bitcom_hash_c2, bitcom_hash_p, bitcom_initT4,
    bitcom_point_add_with_frob, bitcom_point_dbl, bitcom_point_ops, bitcom_precompute_Px,
    bitcom_precompute_Py, bitcom_sparse_dense_mul, bitcom_squaring, hint_hash_c, hint_hash_c2,
    hint_hash_p, hint_init_T4, hints_dense_dense_mul0, hints_dense_dense_mul1, hints_frob_fp12,
    hints_precompute_Px, hints_precompute_Py, tap_add_eval_mul_for_fixed_Qs,
    tap_add_eval_mul_for_fixed_Qs_with_frob, tap_double_eval_mul_for_fixed_Qs, tap_frob_fp12,
    tap_hash_c2, tap_hash_p, tap_point_add_with_frob, tap_point_dbl, tap_point_ops,
    tap_precompute_Px, tap_precompute_Py, tap_sparse_dense_mul, tap_squaring, HashBytes, HintInAdd,
    HintInDblAdd, HintInDenseMul0, HintInDenseMul1, HintInDouble, HintInFrobFp12, HintInHashC,
    HintInHashP, HintInInitT4, HintInPrecomputePx, HintInPrecomputePy, HintInSparseAdd,
    HintInSparseDbl, HintInSparseDenseMul, HintInSquaring, HintOutFixedAcc, HintOutFrobFp12,
    HintOutGrothC, HintOutPubIdentity, HintOutSparseDbl, Link,
};
use crate::execute_script;
use crate::signatures::winternitz_compact::WOTSPubKey;

use super::chunk_config::{
    assign_link_ids, groth16_config_gen, msm_config_gen, post_miller_config_gen,
    pre_miller_config_gen,
};
use super::chunk_primitves::emulate_fq_to_nibbles;
use super::chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4};
use super::chunk_taps::{tup_to_scr, HintOut, Sig};
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
                    HintOut::DenseMul1(r) => chunk_taps::hint_squaring(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInSquaring::from_dmul1(r),
                    ),
                    HintOut::GrothC(r) => chunk_taps::hint_squaring(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInSquaring::from_grothc(r),
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
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
                    }
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDblAdd::from_doubleadd(r, p, q);
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInDblAdd::from_double(r, p, q);
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in, *bit)
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
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    }
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDouble::from_doubleadd(r, p.x, p.y);
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInDouble::from_double(r, p.x, p.y);
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
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
                        chunk_taps::hint_sparse_dense_mul(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            true,
                        )
                    }
                    HintOut::Double(f) => {
                        let hint_in = HintInSparseDenseMul::from_double(f, dense);
                        chunk_taps::hint_sparse_dense_mul(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            true,
                        )
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
                let (hint_out, hint_script) = chunk_taps::hint_double_eval_mul_for_fixed_Qs(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    hint_in,
                );
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
                        chunk_taps::hint_sparse_dense_mul(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            false,
                        )
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
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs(
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
        println!("row ID {:?}", row.link_id);
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        let hints_out: Vec<HintOut> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        if row.category.starts_with("Frob") {
            assert_eq!(hints_out.len(), 1);
            let cinv = match hints_out[0].clone() {
                HintOut::GrothC(f) => f,
                _ => panic!(),
            };
            let mut power = 1;
            if row.category == "Frob2" {
                power = 2;
            } else if row.category == "Frob3" {
                power = 3;
            }
            let hint_in = HintInFrobFp12::from_groth_c(cinv);
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
                HintOut::GrothC(d) => {
                    // s
                    (
                        hints_dense_dense_mul0(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            HintInDenseMul0::from_dense_c(c, d),
                        ),
                        false,
                    )
                }
                HintOut::FixedAcc(r) => (
                    hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul0::from_dense_fixed_acc(c, r),
                    ),
                    true,
                ),
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
                HintOut::GrothC(d) => (
                    hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_dense_c(c, d),
                    ),
                    false,
                ),
                HintOut::FixedAcc(r) => (
                    hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        HintInDenseMul1::from_dense_fixed_acc(c, r),
                    ),
                    true,
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
                        chunk_taps::hint_point_add_with_frob(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            1,
                        )
                    }
                    HintOut::Double(r) => {
                        let hint_in = HintInAdd::from_double(r, p.x, p.y, q);
                        chunk_taps::hint_point_add_with_frob(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            1,
                        )
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
                        chunk_taps::hint_point_add_with_frob(
                            sig,
                            sec_out,
                            sec_in.clone(),
                            hint_in,
                            -1,
                        )
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
                    chunk_taps::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, false)
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
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
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
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
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
        }
    }

    None
}

fn evaluate_public_params(
    sig: &mut Sig,
    link_name_to_id: HashMap<String, (u32, bool)>,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    fixed_acc: ark_bn254::Fq12,
) -> HashMap<String, HintOut> {
    let f = ark_bn254::Fq12::ONE;
    let idhash = emulate_extern_hash_fps(
        vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ],
        true,
    );
    let fixedacc_hash = emulate_extern_hash_fps(
        vec![
            fixed_acc.c0.c0.c0,
            fixed_acc.c0.c0.c1,
            fixed_acc.c0.c1.c0,
            fixed_acc.c0.c1.c1,
            fixed_acc.c0.c2.c0,
            fixed_acc.c0.c2.c1,
            fixed_acc.c1.c0.c0,
            fixed_acc.c1.c0.c1,
            fixed_acc.c1.c1.c0,
            fixed_acc.c1.c1.c1,
            fixed_acc.c1.c2.c0,
            fixed_acc.c1.c2.c1,
        ],
        false,
    );

    let id = HintOutPubIdentity {
        idhash,
        v: ark_bn254::Fq12::ONE,
    };
    let fixed_acc = HintOutFixedAcc {
        f: fixed_acc,
        fhash: fixedacc_hash,
    };

    let mut id_to_witness: HashMap<String, HintOut> = HashMap::new();
    id_to_witness.insert("identity".to_string(), HintOut::PubIdentity(id));
    id_to_witness.insert("Q3y1".to_string(), HintOut::FieldElem(q3.y.c1));
    id_to_witness.insert("Q3y0".to_string(), HintOut::FieldElem(q3.y.c0));
    id_to_witness.insert("Q3x1".to_string(), HintOut::FieldElem(q3.x.c1));
    id_to_witness.insert("Q3x0".to_string(), HintOut::FieldElem(q3.x.c0));
    id_to_witness.insert("Q2y1".to_string(), HintOut::FieldElem(q2.y.c1));
    id_to_witness.insert("Q2y0".to_string(), HintOut::FieldElem(q2.y.c0));
    id_to_witness.insert("Q2x1".to_string(), HintOut::FieldElem(q2.x.c1));
    id_to_witness.insert("Q2x0".to_string(), HintOut::FieldElem(q2.x.c0));
    id_to_witness.insert("f_fixed".to_string(), HintOut::FixedAcc(fixed_acc));

    let tup = vec![
        (link_name_to_id.get("identity").unwrap().clone(), idhash),
        (
            link_name_to_id.get("Q3y1").unwrap().clone(),
            emulate_fq_to_nibbles(q3.y.c1),
        ),
        (
            link_name_to_id.get("Q3y0").unwrap().clone(),
            emulate_fq_to_nibbles(q3.y.c0),
        ),
        (
            link_name_to_id.get("Q3x1").unwrap().clone(),
            emulate_fq_to_nibbles(q3.x.c1),
        ),
        (
            link_name_to_id.get("Q3x0").unwrap().clone(),
            emulate_fq_to_nibbles(q3.x.c0),
        ),
        (
            link_name_to_id.get("Q2y1").unwrap().clone(),
            emulate_fq_to_nibbles(q2.y.c1),
        ),
        (
            link_name_to_id.get("Q2y0").unwrap().clone(),
            emulate_fq_to_nibbles(q2.y.c0),
        ),
        (
            link_name_to_id.get("Q2x1").unwrap().clone(),
            emulate_fq_to_nibbles(q2.x.c1),
        ),
        (
            link_name_to_id.get("Q2x0").unwrap().clone(),
            emulate_fq_to_nibbles(q2.x.c0),
        ),
        (
            link_name_to_id.get("f_fixed").unwrap().clone(),
            fixedacc_hash,
        ),
    ];

    tup_to_scr(sig, tup);

    id_to_witness
}

fn evaluate_groth16_params(
    sig: &mut Sig,
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
    let chash = emulate_extern_hash_fps(cv.clone(), false);
    let chash2 = emulate_extern_hash_fps(cv.clone(), true);

    let sv = vec![
        s.c0.c0.c0, s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0, s.c0.c2.c1, s.c1.c0.c0,
        s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0, s.c1.c2.c1,
    ];
    let shash = emulate_extern_hash_fps(sv.clone(), false);

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
    let cvinvhash2 = emulate_extern_hash_fps(
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
        true,
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
        HintOut::GrothC(HintOutGrothC { c, chash }),
        HintOut::GrothC(HintOutGrothC { c, chash: chash2 }),
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
        HintOut::GrothC(HintOutGrothC { c: s, chash: shash }),
        HintOut::GrothC(HintOutGrothC {
            c: cvinv,
            chash: cvinvhash,
        }),
        HintOut::GrothC(HintOutGrothC {
            c: cvinv,
            chash: cvinvhash2,
        }),
        HintOut::FieldElem(q4.y.c1),
        HintOut::FieldElem(q4.y.c0),
        HintOut::FieldElem(q4.x.c1),
        HintOut::FieldElem(q4.x.c0),
        HintOut::ScalarElem(ks[0]),
        HintOut::ScalarElem(ks[1]),
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
    let tables = msm_config_gen(String::from("k0,k1"));
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
            if !aux_output_per_link.contains_key(&row.link_id) {
                aux_output_per_link.insert(row.link_id, HintOut::HashC(hout));
            }
        } else if row.category == "HashC2" {
            assert!(hints.len() == 1);
            let prev_hash = match hints[0].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let (hout, hint_script) = hint_hash_c2(
                sig,
                sec_out,
                sec_in.clone(),
                HintInHashC::from_groth(prev_hash),
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
                HintOut::GrothC(c) => hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul0::from_grothc(c, d),
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
            let c0 = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let (hout, hint_script) = match hints[0].clone() {
                HintOut::HashC(a) => hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul1::from_groth_hc(a, b),
                ),
                HintOut::GrothC(a) => hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    HintInDenseMul1::from_grothc(a, b),
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
            assert!(hints.len() == 2);
            let p3y = match hints[0].clone() {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let p3x = match hints[1].clone() {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };

            let h = aux_output_per_link.get(&row.link_id).unwrap();
            let hout = match h {
                HintOut::MSM(m) => m,
                _ => panic!("failed to match"),
            };

            let ops_script = tap_hash_p();
            let (_, hint_script) = hint_hash_p(
                sig,
                sec_out,
                sec_in.clone(),
                HintInHashP {
                    c: G1Affine::new_unchecked(p3x, p3y),
                    hashc: hout.hasht,
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
            //ScriptItem {category: String::from("P3Hash"), link_id: String::from("M31"), dependencies: String::from("GP3y,GP3x"), is_type_field: false},
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
) -> Option<(u32, bitcoin_script::Script)> {
    let (link_name_to_id, facc, tacc) = assign_link_ids();
    let mut aux_out_per_link: HashMap<String, HintOut> = HashMap::new();
    let pubmap = evaluate_public_params(sig, link_name_to_id.clone(), q2, q3, fixed_acc);
    aux_out_per_link.extend(pubmap);
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

#[cfg(test)]
mod test {
    use std::{io, ops::Neg};

    use ark_ec::{AffineRepr, CurveGroup};

    use crate::{
        bn254::{
            chunk_compile::{compile, Vkey},
            chunk_config::{get_type_for_link_id, keygen},
            chunk_utils::{
                read_map_from_file, read_scripts_from_file, write_map_to_file,
                write_scripts_to_file, write_scripts_to_separate_files,
            },
        },
        groth16::offchain_checker::compute_c_wi,
        signatures::{winternitz, winternitz_compact, winternitz_compact_hash, winternitz_hash},
    };

    use super::*;

    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct GrothProof {
        c: ark_bn254::Fq12,
        s: ark_bn254::Fq12,
        f_fixed: ark_bn254::Fq12, // mill(p1,q1)
        p2: ark_bn254::G1Affine,  // vk->q2
        p4: ark_bn254::G1Affine,
        q4: ark_bn254::G2Affine,
        scalars: Vec<ark_bn254::Fr>, // msm(scalar, vk_gamma) -> p3; vk->q3
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct GrothVK {
        vk_pubs: Vec<ark_bn254::G1Affine>,
        q2: ark_bn254::G2Affine,
        q3: ark_bn254::G2Affine,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    struct GrothProofBytes {
        c: Vec<u8>,
        s: Vec<u8>,
        f_fixed: Vec<u8>,
        p2: Vec<u8>,
        p4: Vec<u8>,
        q4: Vec<u8>,
        scalars: Vec<Vec<u8>>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    pub(crate) struct GrothVKBytes {
        q2: Vec<u8>,
        q3: Vec<u8>,
        vk_pubs: Vec<Vec<u8>>,
    }

    impl GrothProof {
        fn write_groth16_proof_to_file(&self, filename: &str) {
            let mut cbytes = Vec::new();
            let mut sbytes = Vec::new();
            let mut fbytes = Vec::new();
            let mut p2bytes = Vec::new();
            let mut p4bytes = Vec::new();
            let mut q4bytes = Vec::new();
            let mut scalarbytes_arr = Vec::new();
            self.c.serialize_uncompressed(&mut cbytes).unwrap();
            self.s.serialize_uncompressed(&mut sbytes).unwrap();
            self.f_fixed.serialize_uncompressed(&mut fbytes).unwrap();
            self.p2.serialize_uncompressed(&mut p2bytes).unwrap();
            self.p4.serialize_uncompressed(&mut p4bytes).unwrap();
            self.q4.serialize_uncompressed(&mut q4bytes).unwrap();
            for scalar in self.scalars.clone() {
                let mut scalbytes = Vec::new();
                scalar.serialize_uncompressed(&mut scalbytes).unwrap();
                scalarbytes_arr.push(scalbytes);
            }
            let gbytes = GrothProofBytes {
                c: cbytes,
                s: sbytes,
                f_fixed: fbytes,
                p2: p2bytes,
                p4: p4bytes,
                q4: q4bytes,
                scalars: scalarbytes_arr,
            };
            gbytes.write_to_file(filename).unwrap();
        }

        fn read_groth16_proof_from_file(filename: &str) -> Self {
            let gpb = GrothProofBytes::read_from_file(filename).unwrap();
            let s = Self {
                c: ark_bn254::Fq12::deserialize_uncompressed_unchecked(gpb.c.as_slice()).unwrap(),
                s: ark_bn254::Fq12::deserialize_uncompressed_unchecked(gpb.s.as_slice()).unwrap(),
                f_fixed: ark_bn254::Fq12::deserialize_uncompressed_unchecked(
                    gpb.f_fixed.as_slice(),
                )
                .unwrap(),
                p2: ark_bn254::G1Affine::deserialize_uncompressed_unchecked(gpb.p2.as_slice())
                    .unwrap(),
                p4: ark_bn254::G1Affine::deserialize_uncompressed_unchecked(gpb.p4.as_slice())
                    .unwrap(),
                q4: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q4.as_slice())
                    .unwrap(),
                scalars: gpb
                    .scalars
                    .iter()
                    .map(|x| {
                        ark_bn254::Fr::deserialize_uncompressed_unchecked(x.as_slice()).unwrap()
                    })
                    .collect(),
            };
            s
        }
    }

    impl GrothVK {
        fn write_vk_to_file(&self, filename: &str) {
            let mut q2bytes = Vec::new();
            let mut q3bytes = Vec::new();
            let mut vkpubs_arr = Vec::new();
            self.q2.serialize_uncompressed(&mut q2bytes).unwrap();
            self.q3.serialize_uncompressed(&mut q3bytes).unwrap();
            for vkp in self.vk_pubs.clone() {
                let mut scalbytes = Vec::new();
                vkp.serialize_uncompressed(&mut scalbytes).unwrap();
                vkpubs_arr.push(scalbytes);
            }
            let gbytes = GrothVKBytes {
                q2: q2bytes,
                q3: q3bytes,
                vk_pubs: vkpubs_arr,
            };
            gbytes.write_to_file(filename).unwrap();
        }

        fn read_vk_from_file(filename: &str) -> Self {
            let gpb = GrothVKBytes::read_from_file(filename).unwrap();
            let s = Self {
                q2: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q2.as_slice())
                    .unwrap(),
                q3: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q3.as_slice())
                    .unwrap(),
                vk_pubs: gpb
                    .vk_pubs
                    .iter()
                    .map(|x| {
                        ark_bn254::G1Affine::deserialize_uncompressed_unchecked(x.as_slice())
                            .unwrap()
                    })
                    .collect(),
            };
            s
        }
    }

    fn generate_mock_proof() -> (GrothProof, GrothVK) {
        use crate::groth16::verifier::Verifier;
        use ark_bn254::Bn254;
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ec::pairing::Pairing;
        use ark_ff::PrimeField;
        use ark_groth16::Groth16;
        use ark_relations::lc;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
        use ark_std::{test_rng, UniformRand};
        use rand::{RngCore, SeedableRng};

        #[derive(Copy)]
        struct DummyCircuit<F: PrimeField> {
            pub a: Option<F>,
            pub b: Option<F>,
            pub num_variables: usize,
            pub num_constraints: usize,
        }

        impl<F: PrimeField> Clone for DummyCircuit<F> {
            fn clone(&self) -> Self {
                DummyCircuit {
                    a: self.a,
                    b: self.b,
                    num_variables: self.num_variables,
                    num_constraints: self.num_constraints,
                }
            }
        }

        impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let a =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                let b =
                    cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
                let c = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a * b)
                })?;

                for _ in 0..(self.num_variables - 3) {
                    let _ = cs
                        .new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                }

                for _ in 0..self.num_constraints - 1 {
                    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
                }

                cs.enforce_constraint(lc!(), lc!(), lc!())?;

                Ok(())
            }
        }

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let pub_commit = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        let (_, msm_g1) = Verifier::prepare_inputs(&vec![pub_commit], &vk);

        // G1/G2 points for pairings
        let (p3, p2, p1, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;

        let (c, s) = compute_c_wi(f);

        (
            GrothProof {
                c,
                s,
                f_fixed: p1q1,
                p2,
                p4,
                q4,
                scalars: vec![pub_commit],
            },
            GrothVK {
                q2,
                q3,
                vk_pubs: vk.gamma_abc_g1,
            },
        )
    }

    impl GrothVKBytes {
        fn write_to_file(&self, path: &str) -> io::Result<()> {
            let proof_encoded = serde_json::to_vec(self)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(&proof_encoded)?;
            Ok(())
        }

        fn read_from_file(path: &str) -> io::Result<Self> {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let proof = serde_json::from_slice(&buffer)?;
            Ok(proof)
        }
    }

    impl GrothProofBytes {
        fn write_to_file(&self, path: &str) -> io::Result<()> {
            let proof_encoded = serde_json::to_vec(self)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(&proof_encoded)?;
            Ok(())
        }

        fn read_from_file(path: &str) -> io::Result<Self> {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let proof = serde_json::from_slice(&buffer)?;
            Ok(proof)
        }
    }

    #[test]
    fn test_gen_groth() {
        let gp_f = "chunker_data/groth_proof.bin";
        let vk_f = "chunker_data/groth_vk.bin";
        let (mock_proof, mock_vk) = generate_mock_proof();
        mock_proof.write_groth16_proof_to_file(gp_f);
        mock_vk.write_vk_to_file(vk_f);
        let read_mock_proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let read_vk = GrothVK::read_vk_from_file(vk_f);
        assert_eq!(read_mock_proof, mock_proof);
        assert_eq!(read_vk, mock_vk);
    }

    #[test]
    fn test_operator_generates_keys() {
        let pubs_f = "chunker_data/pubkeys.json";
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pubs = keygen(master_secret);
        write_map_to_file(&pubs, pubs_f).unwrap();
        let read_pubs = read_map_from_file(pubs_f).unwrap();
        assert_eq!(read_pubs, pubs);
    }

    #[test]
    fn test_compile_to_taptree() {
        let vk_f = "chunker_data/groth_vk.bin";
        let pubs_f = "chunker_data/pubkeys.json";
        let pubkeys = read_map_from_file(pubs_f).unwrap();
        let vk = GrothVK::read_vk_from_file(vk_f);
        let save_to_file = true;

        let node_scripts_per_link = compile(
            Vkey {
                q2: vk.q2,
                q3: vk.q3,
                p3vk: vk.vk_pubs,
            },
            &pubkeys,
        );

        if save_to_file {
            let mut script_cache = HashMap::new();
            for (k, v) in node_scripts_per_link {
                script_cache.insert(k, vec![v]);
            }
            write_scripts_to_separate_files(script_cache, "tapnode");
        }
    }

    #[test]
    fn test_operator_generates_assertion() {
        let gp_f = "chunker_data/groth_proof.bin";
        let vk_f = "chunker_data/groth_vk.bin";
        let assert_f = "chunker_data/assert.json";
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dump_assertions_to_file = true;

        let pub_scripts_per_link_id = &keygen(master_secret);
        let mut sig = Sig {
            msk: Some(master_secret),
            cache: HashMap::new(),
        };

        let proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let vk = GrothVK::read_vk_from_file(vk_f);
        let msm_scalar = vec![proof.scalars[0], ark_bn254::Fr::ONE];
        let msm_gs = vec![vk.vk_pubs[1], vk.vk_pubs[0]];
        let p3 = msm_gs[1] * msm_scalar[1] + msm_gs[0] * msm_scalar[0]; // move to initial proof
        let p3 = p3.into_affine();

        let fault = evaluate(
            &mut sig,
            pub_scripts_per_link_id,
            proof.p2,
            p3,
            proof.p4,
            vk.q2,
            vk.q3,
            proof.q4,
            proof.c,
            proof.s,
            proof.f_fixed,
            msm_scalar,
            msm_gs,
        );
        assert!(fault.is_none());
        if dump_assertions_to_file {
            write_scripts_to_file(sig.cache, assert_f);
        }
    }

    #[test]
    fn test_challenger_executes_disprove() {
        let chunker_data_path = "chunker_data";
        let gp_f = &format!("{chunker_data_path}/groth_proof.bin");
        let vk_f = &format!("{chunker_data_path}/groth_vk.bin");
        let assert_f = &format!("{chunker_data_path}/assert.json");
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pubs_f = &format!("{chunker_data_path}/pubkeys.json");

        let pub_scripts_per_link_id = read_map_from_file(pubs_f).unwrap();
        let proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let vk = GrothVK::read_vk_from_file(vk_f);
        let msm_scalar = vec![proof.scalars[0], ark_bn254::Fr::ONE];
        let msm_gs = vec![vk.vk_pubs[1], vk.vk_pubs[0]];
        let p3 = msm_gs[1] * msm_scalar[1] + msm_gs[0] * msm_scalar[0]; // move to initial proof
        let p3 = p3.into_affine();

        // read assertions
        let index_to_corrupt = 98;
        let index_is_field = get_type_for_link_id(index_to_corrupt).unwrap();
        println!(
            "load with faulty assertion ({}, {})",
            index_to_corrupt, index_is_field
        );

        let mut assertion = read_scripts_from_file(assert_f);
        let mut corrup_scr = winternitz_hash::sign_digits(
            &format!("{}{:04X}", master_secret, index_to_corrupt),
            [1u8; 40],
        );
        if index_is_field {
            corrup_scr = winternitz::sign_digits(
                &format!("{}{:04X}", master_secret, index_to_corrupt),
                [1u8; 64],
            );
        }
        assertion.insert(index_to_corrupt, corrup_scr);

        let mut sig = Sig {
            msk: None,
            cache: assertion,
        };

        let fault = evaluate(
            &mut sig,
            &pub_scripts_per_link_id,
            proof.p2,
            p3,
            proof.p4,
            vk.q2,
            vk.q3,
            proof.q4,
            proof.c,
            proof.s,
            proof.f_fixed,
            msm_scalar,
            msm_gs,
        );
        assert!(fault.is_some());
        let fault = fault.unwrap();
        let index_to_corrupt = fault.0;
        let hints_to_disprove = fault.1;

        let read = read_scripts_from_file(&format!(
            "{chunker_data_path}/tapnode_{index_to_corrupt}.json"
        ));
        let read_scr = read.get(&index_to_corrupt).unwrap();
        assert_eq!(read_scr.len(), 1);
        let tap_node = read_scr[0].clone();
        println!("Executing Disprove Node {:?}", index_to_corrupt);

        let script = script! {
            { hints_to_disprove.clone() }
            {tap_node}
        };
        let exec_result = execute_script(script);
        println!("Exec Result Pass: {}", exec_result.success);
        if !exec_result.success {
            println!("Exec Result Failed :");
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        } else {
            let mut disprove_map: HashMap<u32, Vec<Script>> = HashMap::new();
            let disprove_f = &format!("{chunker_data_path}/disprove_{index_to_corrupt}.json");
            disprove_map.insert(index_to_corrupt, vec![hints_to_disprove]);
            write_scripts_to_file(disprove_map, disprove_f);
        }
    }
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
