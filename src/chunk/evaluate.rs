use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::{BigInteger, Field, PrimeField};
use bitcoin_script::script;
use std::collections::HashMap;

use crate::chunk::compile::ATE_LOOP_COUNT;
use crate::chunk::config::miller_config_gen;
use crate::chunk::msm::{bitcom_hash_p, bitcom_msm, hint_hash_p, hint_msm, tap_hash_p, tap_msm};
use crate::chunk::primitves::extern_hash_fps;
use crate::chunk::{taps, taps_mul};
use crate::chunk::taps::*;
use crate::chunk::hint_models::*;

use crate::chunk::taps_mul::*;
use crate::execute_script;
use crate::signatures::wots::{wots160, wots256};

use super::config::{
    assign_link_ids, groth16_config_gen, msm_config_gen, post_miller_config_gen, pre_miller_config_gen, NUM_PUBS, NUM_U160, NUM_U256, PUB_ID
};
use super::hint_models::Element;
use super::primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles, extern_nibbles_to_limbs};
use super::taps::{tap_hash_c, tap_initT4};
use super::taps::{Sig};
use super::wots::WOTSPubKey;
use crate::treepp::*;

fn evaluate_miller_circuit(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, Element>,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    force_validate: bool,
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
            let hints: Vec<Element> = block
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
                let (hintout, hint_script, maybe_wrong) = match hints[0].clone() {
                    Element::Fp12(r) => taps_mul::hint_squaring(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        r,
                    ),
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hintout));
            } else if blk_name == "DblAdd" {
                assert_eq!(hints.len(), 7);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 1..hints.len() {
                    match hints[i].clone() {
                        Element::FieldElem(f) => {
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
                let (hintout, hint_script, maybe_wrong) = match hints[0].clone() {
                    Element::G2Acc(r) => {
                        taps::hint_point_ops(sig, sec_out, sec_in.clone(), r, p.x, p.y, q.x.c0, q.x.c1, q.y.c0, q.y.c1, *bit)
                    }
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::G2Acc(hintout));
            } else if blk_name == "Dbl" {
                assert_eq!(hints.len(), 3);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 1..hints.len() {
                    match hints[i].clone() {
                        Element::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p = G1Affine::new_unchecked(ps[1], ps[0]);
                let (hintout, hint_script, maybe_wrong) = match hints[0].clone() {
                    Element::G2Acc(r) => {
                        taps::hint_point_dbl(sig, sec_out, sec_in.clone(), r, p.x, p.y)
                    }
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::G2Acc(hintout));
            } else if blk_name == "SD1" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                    Element::Fp12(f) => f,
                    _ => panic!(),
                };
                let (sd_hint, hint_script, maybe_wrong) = match hints[1].clone() {
                    Element::G2Acc(t) => {
                        let is_dbl_blk = true;
                        taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), dense, t, is_dbl_blk)
                    }
                    _ => panic!(),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(sd_hint));
            } else if blk_name == "SS1" {
                assert_eq!(hints.len(), 4);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 0..hints.len() {
                    match hints[i].clone() {
                        Element::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                // let hint_in: HintInSparseEvals =
                //     HintInSparseEvals::from_groth_and_aux(p2, p3, nt2, nt3, None, None);
                let (hint_out, hint_script, maybe_wrong) =
                    taps::hint_double_eval_mul_for_fixed_Qs(sig, sec_out, sec_in.clone(), p2.x, p2.y, p3.x, p3.y, nt2, nt3);
                if force_validate || maybe_wrong {
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
                }
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(block.link_id.clone(), Element::SparseEval(hint_out));
            } else if blk_name == "DD1" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    Element::SparseEval(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    c, d.f,
                );
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul0();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
            } else if blk_name == "DD2" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    Element::SparseEval(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    c, d.f,
                );
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul1();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
            } else if blk_name == "DD3" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = match hints[1].clone() {
                    Element::Fp12(r) => hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        c, r,
                    ),
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul0();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
            } else if blk_name == "DD4" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = match hints[1].clone() {
                    Element::Fp12(r) => hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        c, r,
                    ),
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul1();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
            } else if blk_name == "SD2" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                    Element::Fp12(f) => f,
                    _ => panic!(),
                };
                let (sd_hint, hint_script, maybe_wrong) = match hints[1].clone() {
                    Element::G2Acc(t) => {
                        let is_dbl_blk = false;
                        taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), dense, t, is_dbl_blk)
                    }
                    _ => panic!(),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(sd_hint));
            } else if blk_name == "SS2" {
                assert_eq!(hints.len(), 4);
                let mut ps: Vec<ark_bn254::Fq> = vec![];
                for i in 0..hints.len() {
                    match hints[i].clone() {
                        Element::FieldElem(f) => {
                            ps.push(f);
                        }
                        _ => panic!(),
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                // let hint_in: HintInSparseEvals =
                //     HintInSparseEvals::from_groth_and_aux(p2, p3, nt2, nt3,Some(q2), Some(q3));
                let (hint_out, hint_script, maybe_wrong) = taps::hint_add_eval_mul_for_fixed_Qs(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    p2.x, p2.y, p3.x, p3.y, nt2, nt3, q2, q3,
                    *bit,
                );
                if force_validate || maybe_wrong {
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
                }
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(block.link_id.clone(), Element::SparseEval(hint_out));
            } else if blk_name == "DD5" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    Element::SparseEval(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul0(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    c, d.f,
                );
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul0();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
            } else if blk_name == "DD6" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    Element::Fp12(r) => r,
                    _ => panic!("failed to match"),
                };
                let d = match hints[1].clone() {
                    Element::SparseEval(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul1(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    c, d.f,
                );
                if force_validate || maybe_wrong {
                    let ops_script = tap_dense_dense_mul1();
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
                }
                aux_output_per_link.insert(block.link_id.clone(), Element::Fp12(hint_out));
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
    aux_output_per_link: &mut HashMap<String, Element>,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    facc: String,
    tacc: String,
    fixed_acc: ark_bn254::Fq12,
    force_validate: bool,
) -> Option<(u32, Script)> {
    let tables = post_miller_config_gen(facc, tacc);

    let fixed_acc: ElemFp12Acc = ElemFp12Acc { f: fixed_acc, hash: extern_hash_fps(
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
    ) };
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
        let hints_out: Vec<Element> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        if row.category.starts_with("Frob") {
            assert_eq!(hints_out.len(), 1);
            let hint_in = match hints_out[0].clone() {
                Element::Fp12(f) => f,
                _ => panic!(),
            };
            let mut power = 1;
            if row.category == "Frob2" {
                power = 2;
            } else if row.category == "Frob3" {
                power = 3;
            }
            let (h, hint_script, maybe_wrong) = hints_frob_fp12(sig, sec_out, sec_in.clone(), hint_in, power);
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::Fp12(h));
        } else if row.category == "DD1" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let ((hint_out, hint_script, maybe_wrong), check_is_id) = match hints_out[1].clone() {
                Element::Fp12(d) => (
                    hints_dense_dense_mul0(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        c, d,
                    ),
                    false,
                ),
                _ => panic!("failed to match"),
            };
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul0();
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else if row.category == "DD2" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let ((hint_out, hint_script, maybe_wrong), check_is_id) = match hints_out[1].clone() {
                Element::Fp12(d) => (
                    hints_dense_dense_mul1(
                        sig,
                        sec_out,
                        sec_in.clone(),
                        c, d,
                    ),
                    false,
                ),
                _ => panic!("failed to match"),
            };
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul1();
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else if row.category == "DD3" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                Element::SparseEval(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul0(
                sig,
                sec_out,
                sec_in.clone(),
                c, d.f,
            );
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul0();
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else if row.category == "DD4" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                Element::SparseEval(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul1(
                sig,
                sec_out,
                sec_in.clone(),
                c, d.f,
            );
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul1();
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else if row.category == "Add1" || row.category == "Add2" {
            assert_eq!(hints_out.len(), 7);
            let mut ps: Vec<ark_bn254::Fq> = vec![];
            for i in 1..hints_out.len() {
                match hints_out[i].clone() {
                    Element::FieldElem(f) => {
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
                let (hintout, hint_script, maybe_wrong) = match hints_out[0].clone() {
                    Element::G2Acc(r) => {
                        taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), r, p.x, p.y, q.x.c0, q.x.c1, q.y.c0, q.y.c1, 1)
                    }
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(row.link_id.clone(), Element::G2Acc(hintout));
            } else if row.category == "Add2" {
                let (hintout, hint_script, maybe_wrong) = match hints_out[0].clone() {
                    Element::G2Acc(r) => {
                        taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), r, p.x, p.y, q.x.c0, q.x.c1, q.y.c0, q.y.c1, -1)
                    }
                    _ => panic!("failed to match"),
                };
                if force_validate || maybe_wrong {
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
                }
                aux_output_per_link.insert(row.link_id.clone(), Element::G2Acc(hintout));
            }
        } else if row.category == "SD" {
            assert_eq!(hints_out.len(), 2);
            let dense = match hints_out[0].clone() {
                Element::Fp12(f) => f,
                _ => panic!(),
            };
            let (sd_hint, hint_script, maybe_wrong) = match hints_out[1].clone() {
                Element::G2Acc(t) => {
                    let is_dbl_blk = false;
                    taps_mul::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), dense, t, is_dbl_blk)
                }
                _ => panic!(),
            };
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(sd_hint));
        } else if row.category == "SS1" || row.category == "SS2" {
            assert_eq!(hints_out.len(), 4);
            let mut ps: Vec<ark_bn254::Fq> = vec![];
            for i in 0..hints_out.len() {
                match hints_out[i].clone() {
                    Element::FieldElem(f) => {
                        ps.push(f);
                    }
                    _ => panic!(),
                }
            }
            let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
            let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
            // let hint_in: HintInSparseEvals =
            //     HintInSparseEvals::from_groth_and_aux(p2, p3, nt2, nt3,Some(q2), Some(q3));
            if row.category == "SS1" {
                let (hint_out, hint_script, maybe_wrong) = taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    p2.x, p2.y, p3.x, p3.y, nt2, nt3, q2, q3,
                    1,
                );
                if force_validate || maybe_wrong {
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
                }
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), Element::SparseEval(hint_out));
            } else if row.category == "SS2" {
                let (hint_out, hint_script, maybe_wrong) = taps::hint_add_eval_mul_for_fixed_Qs_with_frob(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    p2.x, p2.y, p3.x, p3.y, nt2, nt3, q2, q3,
                    -1,
                );
                if force_validate || maybe_wrong {
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
                }
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), Element::SparseEval(hint_out));
            } 
        
        } else if row.category == "DK1" {
            assert!(hints_out.len() == 1);
            let a = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };

            let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul0_by_constant(sig, sec_out, sec_in.clone(), a, fixed_acc);
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul0_by_constant(true, fixed_acc.f);
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else if row.category == "DK2" {
            assert!(hints_out.len() == 2);
            let a = match hints_out[0].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out, hint_script, maybe_wrong) = hints_dense_dense_mul1_by_constant(sig, sec_out, sec_in.clone(), a, fixed_acc);
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul1_by_constant(true, fixed_acc.f);
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
            }
            aux_output_per_link.insert(row.link_id.clone(), Element::Fp12(hint_out));
        } else {
            panic!();
        } 
    
    
    
    }

    None
}


fn evaluate_groth16_params_from_sig(
    sig: &mut Sig,
    link_name_to_id: HashMap<String, (u32, bool)>,
    ) -> HashMap<String, Element> {
    assert!(sig.cache.len() > 0);
    let gparams = groth16_config_gen();

    let mut id_to_witness: HashMap<String, Vec<u8>> = HashMap::new();
    for i in 0..gparams.len() {
        let id = link_name_to_id.get(&gparams[i].link_id).unwrap().0;
        let sigdata = sig.cache.get(&id).unwrap();
        let mut nibs = vec![];
        match sigdata {
            SigData::Sig160(sig_msg) => {
                 nibs.extend_from_slice(&sig_msg.map(|(_sig, digit)| digit));
            },
            SigData::Sig256(sig_msg) => {
                nibs.extend_from_slice(&sig_msg.map(|(sig, digit)| digit));
            }
        };
        id_to_witness.insert(gparams[i].link_id.clone(), nibs.to_vec());
    }
    let mut hout_per_name = HashMap::new();
    for i in 0..gparams.len() {
        let item = &gparams[i];
        let hout = if item.category == "GrothPubs" {
            let nibs = &id_to_witness.get(&item.link_id).unwrap().clone()[0..64];
            let mut nibs = nibs
                .chunks(2)
                .rev()
                .map(|bn| (bn[1] << 4) + bn[0])
                .collect::<Vec<u8>>();
            nibs.reverse();
            let fr =  ark_bn254::Fr::from_le_bytes_mod_order(&nibs);
            Element::ScalarElem(fr)
        } else {
            if item.is_type_field {
                let nibs = &id_to_witness.get(&item.link_id).unwrap().clone()[0..64];
                let mut nibs = nibs
                    .chunks(2)
                    .rev()
                    .map(|bn| (bn[1] << 4) + bn[0])
                    .collect::<Vec<u8>>();
                nibs.reverse();
                let fq =  ark_bn254::Fq::from_le_bytes_mod_order(&nibs);
                Element::FieldElem(fq)
            } else {
                let nibs = &id_to_witness.get(&item.link_id).unwrap().clone()[0..40];
                let mut nibs = nibs[0..40].to_vec();
                nibs.reverse();
                // for chunk in nibs.chunks_exact_mut(2) {
                //     chunk.swap(0, 1);
                // }
                let nibs: [u8; 40] = nibs.try_into().unwrap();
                let mut padded_nibs = [0u8; 64]; // initialize with zeros
                padded_nibs[24..64].copy_from_slice(&nibs[0..40]);
                Element::Fp12(ElemFp12Acc { f: ark_bn254::Fq12::ONE, hash: padded_nibs })
            }
        };
        hout_per_name.insert(item.link_id.clone(), hout);
    }

    let mut r2 = vec![
        "Gc11", "Gc10", "Gc9", "Gc8", "Gc7", "Gc6", "Gc5", "Gc4", "Gc3", "Gc2", "Gc1", "Gc0",
    ];
    r2.reverse();
    let mut cs = vec![];
    for item in r2 {
        let hout = hout_per_name.get(item).unwrap();
        if let Element::FieldElem(c) = hout {
            cs.push(*c);
        };
    }
    let gc = fq12_from_vec(cs);
    let f = gc.inverse().unwrap();
    // let cs = vec![
    //     f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
    //     f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
    // ];
    //let chash = emulate_extern_hash_fps(cs.clone(), false);
    let v = hout_per_name.get("cinv").unwrap();
    if let Element::Fp12(x) = v {
        hout_per_name.insert(String::from("cinv"), Element::Fp12(ElemFp12Acc { f, hash: x.hash }));
    }
    return hout_per_name;

}

fn fq12_from_vec(fs: Vec<ark_bn254::Fq>) -> ark_bn254::Fq12 {
    ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(ark_bn254::Fq2::new(fs[0], fs[1]), ark_bn254::Fq2::new(fs[2], fs[3]), ark_bn254::Fq2::new(fs[4], fs[5])), 
        ark_bn254::Fq6::new(ark_bn254::Fq2::new(fs[6], fs[7]), ark_bn254::Fq2::new(fs[8], fs[9]), ark_bn254::Fq2::new(fs[10], fs[11])),  
    )
}
fn evaluate_groth16_params(
    eval_ins: EvalIns,
) -> HashMap<String, Element> {
    let p2 = eval_ins.p2;
    let p3 = eval_ins.p3;
    let p4 = eval_ins.p4;
    let q4 = eval_ins.q4;
    let c = eval_ins.c;
    let s = eval_ins.s;
    let ks = eval_ins.ks;
    let cv = vec![
        c.c0.c0.c0, c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0, c.c0.c2.c1, c.c1.c0.c0,
        c.c1.c0.c1, c.c1.c1.c0, c.c1.c1.c1, c.c1.c2.c0, c.c1.c2.c1,
    ];

    let sv = vec![
        s.c0.c0.c0, s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0, s.c0.c2.c1, s.c1.c0.c0,
        s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0, s.c1.c2.c1,
    ];

    let cvinv = c.inverse().unwrap();
    let cvinvhash = extern_hash_fps(
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
    let mut gouts = vec![
        Element::FieldElem(p4.y),
        Element::FieldElem(p4.x),
        Element::FieldElem(p3.y),
        Element::FieldElem(p3.x),
        Element::FieldElem(p2.y),
        Element::FieldElem(p2.x),
        Element::FieldElem(cv[11]),
        Element::FieldElem(cv[10]),
        Element::FieldElem(cv[9]),
        Element::FieldElem(cv[8]),
        Element::FieldElem(cv[7]),
        Element::FieldElem(cv[6]),
        Element::FieldElem(cv[5]),
        Element::FieldElem(cv[4]),
        Element::FieldElem(cv[3]),
        Element::FieldElem(cv[2]),
        Element::FieldElem(cv[1]),
        Element::FieldElem(cv[0]),
        Element::FieldElem(sv[11]),
        Element::FieldElem(sv[10]),
        Element::FieldElem(sv[9]),
        Element::FieldElem(sv[8]),
        Element::FieldElem(sv[7]),
        Element::FieldElem(sv[6]),
        Element::FieldElem(sv[5]),
        Element::FieldElem(sv[4]),
        Element::FieldElem(sv[3]),
        Element::FieldElem(sv[2]),
        Element::FieldElem(sv[1]),
        Element::FieldElem(sv[0]),
        Element::Fp12(ElemFp12Acc {
            f: cvinv,
            hash: cvinvhash,
        }),
        Element::FieldElem(q4.y.c1),
        Element::FieldElem(q4.y.c0),
        Element::FieldElem(q4.x.c1),
        Element::FieldElem(q4.x.c0),
        // HintOut::ScalarElem(ks[0]),
        // HintOut::ScalarElem(ks[1]),
        // HintOut::ScalarElem(ks[2]),
    ];
    for i in 0..ks.len() {
        gouts.push(Element::ScalarElem(ks[i]));
    }


    assert_eq!(gparams.len(), gouts.len());

    let mut id_to_witness: HashMap<String, Element> = HashMap::new();
    for i in 0..gparams.len() {
        id_to_witness.insert(gparams[i].link_id.clone(), gouts[i].clone());
    }

    id_to_witness
}

fn evaluate_msm(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, Element>,
    pub_ins: usize,
    qs: Vec<ark_bn254::G1Affine>,
    force_validate: bool
) -> Option<(u32, bitcoin_script::Script)> {
    let tables = msm_config_gen(String::from(PUB_ID));
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
        let hints: Vec<Element> = row
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
                    Element::ScalarElem(r) => r,
                    _ => panic!("failed to match"),
                };
                scalars.push(x);
            }
            let mut acc = ark_bn254::G1Affine::identity();
            for i in pub_ins..hints.len() {
                let x = match &hints[i] {
                    Element::MSMG1(r) => r,
                    _ => panic!("failed to match"),
                };
                acc = x.clone();
            }
            let (hint_res, hint_script, maybe_wrong) = hint_msm(
                sig,
                sec_out,
                sec_in.clone(),
                acc, 
                scalars,
                msm_tap_index,
                qs.clone(),
            );
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::MSMG1(hint_res));
        }
        msm_tap_index += 1;
    }

    None
}

fn evaluate_pre_miller_circuit(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    link_name_to_id: HashMap<String, (u32, bool)>,
    aux_output_per_link: &mut HashMap<String, Element>,
    vky0: ark_bn254::G1Affine,
    force_validate: bool,
) -> Option<(u32, bitcoin_script::Script)> {
    let tables = pre_miller_config_gen();

    for row in tables {
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| link_name_to_id.get(s).unwrap().clone())
            .collect();
        let hints: Vec<Element> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| aux_output_per_link.get(s).unwrap().clone())
            .collect();
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        println!("row name {:?} ID {:?}", row.category, sec_out);
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, sec_in);
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, row.dependencies);

        if row.category == "T4Init" {
            assert!(hints.len() == 4);
            let mut cs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    Element::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                cs.push(x);
            }
            let (hint_res, hint_script, maybe_wrong) = hint_init_T4(
                sig,
                sec_out,
                sec_in.clone(),
                cs[3], cs[2], cs[1], cs[0]
            );
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::G2Acc(hint_res));
        } else if row.category == "PrePy" {
            assert!(hints.len() == 1);
            let pt = match hints[0] {
                Element::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let (pyd, hint_script, maybe_wrong) = hints_precompute_Py(
                sig,
                sec_out,
                sec_in.clone(),
                pt,
            );
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::FieldElem(pyd));
        } else if row.category == "PrePx" {
            assert!(hints.len() == 3);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    Element::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (pxd, hint_script, maybe_wrong) = hints_precompute_Px(
                sig,
                sec_out,
                sec_in.clone(),
                xs[1], xs[0]
            );
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::FieldElem(pxd));
        } else if row.category == "HashC" {
            assert!(hints.len() == 12);
            let mut gs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    Element::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                gs.push(x);
            }
            // let gsf = ark_bn254::Fq12::new(
            //     ark_bn254::Fq6::new(
            //         ark_bn254::Fq2::new(gs[11], gs[10]),
            //         ark_bn254::Fq2::new(gs[9], gs[8]),
            //         ark_bn254::Fq2::new(gs[7], gs[6]),
            //     ),
            //     ark_bn254::Fq6::new(
            //         ark_bn254::Fq2::new(gs[5], gs[4]),
            //         ark_bn254::Fq2::new(gs[3], gs[2]),
            //         ark_bn254::Fq2::new(gs[1], gs[0]),
            //     ),
            // );
            gs.reverse();
            let (hout, hint_script, maybe_wrong) =
                hint_hash_c(sig, sec_out, sec_in.clone(), gs);
            if force_validate || maybe_wrong {
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
            }
            aux_output_per_link.insert(row.link_id, Element::Fp12(hout));
        } else if row.category == "HashC2" {
            assert!(hints.len() == 1);
            let hint_in_hashc2 = match hints[0].clone() {
                Element::Fp12(r) => r, // c->c2
                _ => panic!("failed to match"),
            };
            let (hout, hint_script, maybe_wrong) = hint_hash_c2(
                sig,
                sec_out,
                sec_in.clone(),
                hint_in_hashc2,
            );
            if force_validate || maybe_wrong {
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
            }
            if !aux_output_per_link.contains_key(&row.link_id) {
                aux_output_per_link.insert(row.link_id, Element::Fp12(hout));
            }
        } else if row.category == "DD1" {
            assert!(hints.len() == 2);
            let d = match hints[1].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            let (c, hint_script, maybe_wrong) = match hints[0].clone() {
                Element::Fp12(c) => hints_dense_dense_mul0_by_hash(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    c, d.hash,
                ),
                _ => panic!("failed to match"),
            };
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul0_by_hash();
                let bcs_script =
                    bitcom_dense_dense_mul0_by_hash(pub_scripts_per_link_id, sec_out, sec_in.clone());
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
            }
            aux_output_per_link.insert(row.link_id, Element::Fp12(c));
        } else if row.category == "DD2" {
            assert!(hints.len() == 3);
            let b = match hints[1].clone() {
                Element::Fp12(r) => r,
                _ => panic!("failed to match"),
            };
            // let c0 = match hints[2].clone() {
            //     HintOut::GrothC(r) => r,
            //     _ => panic!("failed to match"),
            // };
            let (hout, hint_script, maybe_wrong) = match hints[0].clone() {
                Element::Fp12(a) => hints_dense_dense_mul1_by_hash(
                    sig,
                    sec_out,
                    sec_in.clone(),
                    a, b.hash,
                ),
                _ => panic!("failed to match"),
            };
            if force_validate || maybe_wrong {
                let ops_script = tap_dense_dense_mul1_by_hash();
                let bcs_script =
                    bitcom_dense_dense_mul1_by_hash(pub_scripts_per_link_id, sec_out, sec_in.clone());
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
            aux_output_per_link.insert(row.link_id, Element::Fp12(hout));
        } else if row.category == "P3Hash" {
            assert!(hints.len() == 3);
            let t = match hints[0].clone() {
                Element::MSMG1(r) => r,
                _ => panic!("failed to match"),
            };
            let p3y = match hints[1].clone() {
                Element::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let p3x = match hints[2].clone() {
                Element::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };

            let (hint_out, hint_script, maybe_wrong) = hint_hash_p(
                sig,
                sec_out,
                sec_in.clone(),
                p3x, p3y, t, vky0
            );
            if force_validate || maybe_wrong {
                let ops_script = tap_hash_p(vky0);
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
            aux_output_per_link.insert(row.link_id, Element::HashBytes(hint_out));
        }
    }
    None
}

pub(crate) struct EvalIns {
    pub(crate) p2: G1Affine,
    pub(crate) p3: G1Affine,
    pub(crate) p4: G1Affine,
    pub(crate) q4: G2Affine,
    pub(crate) c: ark_bn254::Fq12,
    pub(crate) s: ark_bn254::Fq12,
    pub(crate) ks: Vec<ark_bn254::Fr>,
}

pub(crate) fn evaluate(
    sig: &mut Sig,
    pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,
    eval_ins: Option<EvalIns>,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    fixed_acc: ark_bn254::Fq12,
    ks_vks: Vec<ark_bn254::G1Affine>,
    vky0: ark_bn254::G1Affine,
    force_validate: bool,
) -> (HashMap<String, Element>, Option<(u32, bitcoin_script::Script)>) {
    let (link_name_to_id, facc, tacc) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
    let mut aux_out_per_link: HashMap<String, Element> = HashMap::new();

    let mut grothmap = HashMap::new();
    if sig.cache.len() > 0 {
        grothmap = evaluate_groth16_params_from_sig(sig, link_name_to_id.clone());
    } else {
        grothmap = evaluate_groth16_params(
            eval_ins.unwrap()
        );
    }
    aux_out_per_link.extend(grothmap);


    let re = evaluate_msm(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        NUM_PUBS,
        ks_vks,
        force_validate
    );
    if re.is_some() {
        println!("Disprove evaluate_msm");
        return (aux_out_per_link, re);
    }

    let re = evaluate_pre_miller_circuit(
        sig,
        pub_scripts_per_link_id,
        link_name_to_id.clone(),
        &mut aux_out_per_link,
        vky0,
        force_validate
    );
    if re.is_some() {
        println!("Disprove evaluate_pre_miller_circuit");
        return (aux_out_per_link, re);
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
        force_validate,
    );
    if re.is_some() {
        println!("Disprove evaluate_miller_circuit");
        return (aux_out_per_link, re);
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
        force_validate
    );
    if re.is_some() {
        println!("Disprove evaluate_post_miller_circuit");
        return (aux_out_per_link, re);
    }

    let hint = aux_out_per_link.get("fin");
    if hint.is_none() {
        println!("debug hintmap {:?}", aux_out_per_link);
    } else {
        let hint = hint.unwrap();
        match hint {
            Element::Fp12(c) => {
                assert_eq!(c.f, ark_bn254::Fq12::ONE);
            }
            _ => {}
        }
    }
    (aux_out_per_link, None)
}

 pub(crate) fn extract_values_from_hints(aux_out_per_link: HashMap<String, Element>) -> HashMap<u32, [u8; 64]> {
    let (link_name_to_id, facc, tacc) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
    let mut nibbles_per_index: HashMap<u32, [u8;64]> = HashMap::new();

    for (k, v) in aux_out_per_link {
        let x = match v {
            Element::G2Acc(r) => r.out(),
            Element::G2Acc(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::G2Acc(r) => r.out(),
            Element::FieldElem(f) => extern_fq_to_nibbles(f),
            Element::Fp12(f) => f.out(),
            Element::Fp12(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::G2Acc(r) => r.out(),
            Element::MSMG1(r) => r.out(),
            Element::ScalarElem(r) => extern_fr_to_nibbles(r),
            Element::SparseEval(r) => r.out(),
            Element::SparseEval(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::Fp12(r) => r.out(),
            Element::HashBytes(r) => r,
        };
        let index = link_name_to_id.get(&k).unwrap().0;
        nibbles_per_index.insert(index, x);
    }
    nibbles_per_index
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

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use super::*;
    #[test]
    fn evaluate_groth16_params_from_sig_test() {

        pub(crate) fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
        
            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
                msg_bytes.push(byte);
            }
        
            msg_bytes
        }

        fn extract_sigs_from_hints(secret: &str, aux_out_per_link: HashMap<String, Element>) -> HashMap<u32, SigData> {
            let (link_name_to_id, facc, tacc) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
            let mut nibbles_per_index: HashMap<u32, SigData> = HashMap::new();
        
            for (k, v) in aux_out_per_link {
                let index = link_name_to_id.get(&k).unwrap().0;
                let x = match v {
                    Element::FieldElem(f) => {
                        let msg_bytes = extern_fq_to_nibbles(f);
                        let bal: [u8; 32] = nib_to_byte_array(&msg_bytes).try_into().unwrap();
                        let c = wots256::get_signature(&format!("{secret}{:04x}", index), &bal);
                        SigData::Sig256(c)
                    },
                    Element::Fp12(r) => {
                        // println!("match {:?}", r.chash);
                        let bal: [u8; 32] = nib_to_byte_array(&r.hash).try_into().unwrap();
        
                        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
                        let c = wots160::get_signature(&format!("{secret}{:04x}", index), &bal);
                        SigData::Sig160(c)
                    },
                    Element::ScalarElem(f) => {
                        let msg_bytes = extern_fr_to_nibbles(f);
                        let bal: [u8; 32] = nib_to_byte_array(&msg_bytes).try_into().unwrap();
                        let c = wots256::get_signature(&format!("{secret}{:04x}", index), &bal);
                        SigData::Sig256(c)
                    }
                    _ => {
                        println!("problem");
                        SigData::Sig256(wots256::get_signature(&format!("{secret}{:04x}", index), &[]))
                    },
                };
                nibbles_per_index.insert(index, x);
            }
            nibbles_per_index
         }
        
        let (link_name_to_id, facc, tacc) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
        let sig = &mut Sig { msk: None, cache: HashMap::new() };
        let mut rng = &mut test_rng();
        let ks = [ark_bn254::Fr::rand(&mut rng), ark_bn254::Fr::rand(&mut rng), ark_bn254::Fr::rand(&mut rng)];
        let eval_ins: EvalIns = EvalIns { p2: ark_bn254::G1Affine::rand(&mut rng), p3: ark_bn254::G1Affine::rand(&mut rng), p4: ark_bn254::G1Affine::rand(&mut rng), q4: ark_bn254::G2Affine::rand(&mut rng), c: ark_bn254::Fq12::ONE, s: ark_bn254::Fq12::ONE, ks: ks.to_vec()};
        let eval1 = evaluate_groth16_params(eval_ins);
        let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";

        println!("ks {:?}", ks);
        let assertions = extract_sigs_from_hints(secret, eval1.clone());
        sig.cache = assertions;
        let eval2 = evaluate_groth16_params_from_sig(sig, link_name_to_id);
        println!("eval1 {:?}", eval1);
        println!("eval2 {:?}", eval2);
        assert_eq!(eval1.len(), eval2.len());
        for (k, v) in eval1 {
            println!("k {:?}", k);
            let r = eval2.get(&k).unwrap().clone();
            match v {
                Element::FieldElem(v) => {
                    if let Element::FieldElem(rs) = r {
                        assert_eq!(v, rs);
                    }
                },
                Element::ScalarElem(v) => {
                    if let Element::ScalarElem(rs) = r {
                        assert_eq!(v, rs);
                    }
                },
                Element::Fp12(v) => {
                    if let Element::Fp12(rs) = r {
                        assert_eq!(v.f, rs.f);
                        assert_eq!(v.hash, rs.hash);
                    } 
                }
                _ => (),
            }
        }
    }


}