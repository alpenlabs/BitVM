
use std::collections::{HashMap};
use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::{Field};
use bitcoin::opcodes::OP_TRUE;
use bitcoin_script::script;

use crate::bn254::chunk_compile::ATE_LOOP_COUNT;
use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_msm::{bitcom_msm, hint_msm, tap_msm, HintInMSM};
use crate::bn254::chunk_primitves::emulate_extern_hash_fps;
use crate::bn254::chunk_taps::{bitcom_add_eval_mul_for_fixed_Qs, bitcom_add_eval_mul_for_fixed_Qs_with_frob, bitcom_dense_dense_mul0, bitcom_dense_dense_mul1, bitcom_double_eval_mul_for_fixed_Qs, bitcom_frob_fp12, bitcom_hash_c, bitcom_hash_c2, bitcom_initT4, bitcom_point_add_with_frob, bitcom_point_dbl, bitcom_point_ops, bitcom_precompute_Px, bitcom_precompute_Py, bitcom_sparse_dense_mul, bitcom_squaring, hint_hash_c, hint_hash_c2, hint_init_T4, hints_dense_dense_mul0, hints_dense_dense_mul1, hints_frob_fp12, hints_precompute_Px, hints_precompute_Py, tap_add_eval_mul_for_fixed_Qs, tap_add_eval_mul_for_fixed_Qs_with_frob, tap_double_eval_mul_for_fixed_Qs, tap_frob_fp12, tap_hash_c2, tap_point_add_with_frob, tap_point_dbl, tap_point_ops, tap_precompute_Px, tap_precompute_Py, tap_sparse_dense_mul, tap_squaring, HashBytes, HintInAdd, HintInDblAdd, HintInDenseMul0, HintInDenseMul1, HintInDouble, HintInFrobFp12, HintInHashC, HintInInitT4, HintInPrecomputePx, HintInPrecomputePy, HintInSparseAdd, HintInSparseDbl, HintInSparseDenseMul, HintInSquaring, HintOutFixedAcc, HintOutFrobFp12, HintOutGrothC, HintOutPubIdentity, HintOutSparseDbl, Link};
use crate::bn254::chunk_taps;
use crate::execute_script;
use crate::signatures::winternitz_compact::WOTSPubKey;

use super::chunk_config::{assign_link_ids, groth16_config_gen, msm_config_gen, post_miller_config_gen, pre_miller_config_gen};
use super::chunk_primitves::emulate_fq_to_nibbles;
use super::chunk_taps::{tup_to_scr, HintOut, Sig};
use super::{chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4}};


fn evaluate_miller_circuit(sig: &mut Sig, pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>, link_name_to_id: HashMap<String, (u32, bool)>, aux_output_per_link: &mut HashMap<String, HintOut>, t2: ark_bn254::G2Affine, t3: ark_bn254::G2Affine, q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine) -> (G2Affine, G2Affine) {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)
 
    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;

    let blocks = miller_config_gen();

    let mut itr = 0;

    fn get_index(blk_name: &str, id_to_sec: HashMap<String, (u32, bool)>)-> Link {
        id_to_sec.get(blk_name).unwrap().clone()
    }

    fn get_deps(deps: &str, id_to_sec: HashMap<String, (u32, bool)>) -> Vec<Link> {
        let splits: Vec<Link>= deps.split(",").into_iter().map(|s| get_index(s, id_to_sec.clone())).collect();
        splits
    }

    let mut nt2 = t2.clone();
    let mut nt3 = t3.clone();
    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let bit = &ATE_LOOP_COUNT[j-1];    
        let blocks_of_a_loop = &blocks[itr];
        for k in 0..blocks_of_a_loop.len() {
            let block = &blocks_of_a_loop[k];
            let sec_out = get_index(&block.link_id, link_name_to_id.clone());
            let sec_in = get_deps(&block.dependencies, link_name_to_id.clone());
            let hints: Vec<HintOut> = block.dependencies.split(",").into_iter().map(|s| aux_output_per_link.get(s).unwrap().clone()).collect();
            println!("{itr} ate {:?} ID {:?} deps {:?}", *bit, block.link_id, block.dependencies);
            println!("{itr} {} ID {:?} deps {:?}", block.category, sec_out, sec_in);
            let blk_name = block.category.clone();
            if blk_name == "Sqr" {
                assert_eq!(hints.len(), 1);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::DenseMul1(r) => {
                        chunk_taps::hint_squaring(sig, sec_out, sec_in.clone(), HintInSquaring::from_dmul1(r))
                    },
                    HintOut::GrothC(r) => {
                        chunk_taps::hint_squaring(sig, sec_out, sec_in.clone(), HintInSquaring::from_grothc(r))
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_squaring();
                    let bcs_script = bitcom_squaring(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                        },
                        _ => panic!()
                    }
                }
                let q = G2Affine::new_unchecked(ark_bn254::Fq2::new(ps[3], ps[2]), ark_bn254::Fq2::new(ps[1], ps[0]));
                let p = G1Affine::new_unchecked(ps[5], ps[4]);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDblAdd::from_initT4(r, p,q);
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in,*bit)
                    },
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDblAdd::from_doubleadd(r, p,q);
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in,*bit)
                    },
                    HintOut::Double(r) => {
                        let hint_in = HintInDblAdd::from_double(r, p,q);
                        chunk_taps::hint_point_ops(sig, sec_out, sec_in.clone(), hint_in,*bit)
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_point_ops(*bit);
                    let bcs_script = bitcom_point_ops(pub_scripts_per_link_id, sec_out, sec_in.clone(), *bit);
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                        },
                        _ => panic!()
                    }
                }
                let p = G1Affine::new_unchecked(ps[1], ps[0]);
                let (hintout, hint_script) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDouble::from_initT4(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    },
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDouble::from_doubleadd(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    },
                    HintOut::Double(r) => {
                        let hint_in = HintInDouble::from_double(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sig, sec_out, sec_in.clone(), hint_in)
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_point_dbl();
                    let bcs_script = bitcom_point_dbl(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::Double(hintout));
            } else if blk_name == "SD1" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                        HintOut::Squaring(f) => f,
                        _ => panic!()
                    };
                let (sd_hint, hint_script) = match hints[1].clone() {
                        HintOut::DblAdd(f) => {
                            let hint_in = HintInSparseDenseMul::from_double_add_top(f, dense);
                            chunk_taps::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, true)
                        },
                        HintOut::Double(f) => {
                            let hint_in = HintInSparseDenseMul::from_double(f, dense);
                            chunk_taps::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, true)
                        }
                        _ => panic!()
                    };
                    let ops_script = tap_sparse_dense_mul( true);
                    let bcs_script = bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                        },
                        _ => panic!()
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                let hint_in: HintInSparseDbl = HintInSparseDbl::from_groth_and_aux(p2, p3, nt2, nt3);
                let (hint_out, hint_script) = chunk_taps::hint_double_eval_mul_for_fixed_Qs(sig, sec_out, sec_in.clone(), hint_in);
                    let (ops_script,_,_) = tap_double_eval_mul_for_fixed_Qs(nt2, nt3);
                    let bcs_script = bitcom_double_eval_mul_for_fixed_Qs(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                let (hint_out, hint_script) = hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_sparse_dense_dbl(c, d));
                    let ops_script = tap_dense_dense_mul0(false);
                    let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                let (hint_out, hint_script) = hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_sparse_dense_dbl(c, d));
                    let ops_script = tap_dense_dense_mul1( false);
                    let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                    HintOut::GrothC(r) => {
                        hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_dense_c(c, r))
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_dense_dense_mul0(false);
                    let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                    HintOut::GrothC(r) => {
                        hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_dense_c(c, r))
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_dense_dense_mul1( false);
                    let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(block.link_id.clone(), HintOut::DenseMul1(hint_out));
            } else if blk_name == "SD2" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                        HintOut::DenseMul1(f) => f,
                        _ => panic!()
                    };
                let (sd_hint, hint_script) = match hints[1].clone() {
                        HintOut::DblAdd(f) => {
                            let hint_in = HintInSparseDenseMul::from_doubl_add_bottom(f, dense);
                            chunk_taps::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, false)
                        },
                        _ => panic!()
                    };
                    let ops_script = tap_sparse_dense_mul(false);
                    let bcs_script = bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                        },
                        _ => panic!()
                    }
                }
                let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
                let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
                let hint_in: HintInSparseAdd = HintInSparseAdd::from_groth_and_aux(p2, p3,q2, q3, nt2, nt3);
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs(sig, sec_out, sec_in.clone(), hint_in, *bit);
                    let (ops_script, _, _) = tap_add_eval_mul_for_fixed_Qs(nt2, nt3, q2, q3, *bit);
                    let bcs_script = bitcom_add_eval_mul_for_fixed_Qs(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                let (hint_out, hint_script) = hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_sparse_dense_add(c, d));
                    let ops_script = tap_dense_dense_mul0( false);
                    let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
                let (hint_out, hint_script) = hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_sparse_dense_add(c, d));
                    let ops_script = tap_dense_dense_mul1( false);
                    let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
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
    (nt2, nt3)

}

fn evaluate_post_miller_circuit(sig: &mut Sig, pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>,  link_name_to_id: HashMap<String, (u32, bool)>, aux_output_per_link: &mut HashMap<String, HintOut>, t2: ark_bn254::G2Affine,  t3: ark_bn254::G2Affine,  q2: ark_bn254::G2Affine,  q3: ark_bn254::G2Affine, facc: String, tacc: String )  {
    let tables = post_miller_config_gen(facc,tacc);

    let mut nt2 = t2;
    let mut nt3 = t3;
    for row in tables {
        let sec_in: Vec<Link> = row.dependencies.split(",").into_iter().map(|s| link_name_to_id.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.link_id);
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        let hints_out: Vec<HintOut> = row.dependencies.split(",").into_iter().map(|s| aux_output_per_link.get(s).unwrap().clone()).collect();
        if row.category.starts_with("Frob") {
            assert_eq!(hints_out.len(), 1);
            let cinv = match hints_out[0].clone() {
                HintOut::GrothC(f) => f,
                _ => panic!()
            };
            let mut power = 1;
            if row.category == "Frob2" {
                power = 2;
            } else if row.category == "Frob3" {
                power = 3;
            }
            let hint_in = HintInFrobFp12::from_groth_c(cinv);
            let (h, hint_script) = hints_frob_fp12(sig, sec_out,sec_in.clone(), hint_in, power);
                let ops_script = tap_frob_fp12(power);
                let bcs_script = bitcom_frob_fp12(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
                HintOut::FrobFp12(d) => {
                    (hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_dense_frob(c, d)), false)
                },
                HintOut::GrothC(d) => { // s
                    (hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_dense_c(c, d)), false)
                },
                HintOut::FixedAcc(r) => {
                    (hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_dense_fixed_acc(c, r)), true)
                },
                _ => panic!("failed to match"),
            };
                let ops_script = tap_dense_dense_mul0( check_is_id);
                let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
                HintOut::FrobFp12(d) => {
                    (hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_dense_frob(c, d)), false)
                },
                HintOut::GrothC(d) => {
                    (hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_dense_c(c, d)), false)
                },
                HintOut::FixedAcc(r) => {
                    (hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_dense_fixed_acc(c, r)), true)
                },
                _ => panic!("failed to match"),
            };
                let ops_script = tap_dense_dense_mul1(check_is_id);
                let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
            let (hint_out,hint_script) = hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_sparse_dense_add(c, d));
                let ops_script = tap_dense_dense_mul0(false);
                let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
            let (hint_out, hint_script) = hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_sparse_dense_add(c, d));
                let ops_script = tap_dense_dense_mul1(false);
                let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id.clone(), HintOut::DenseMul1(hint_out));
        } else if row.category == "Add1" || row.category == "Add2"  {
            assert_eq!(hints_out.len(), 7);
            let mut ps: Vec<ark_bn254::Fq> = vec![];
            for i in 1..hints_out.len() {
                match hints_out[i].clone() {
                    HintOut::FieldElem(f) => {
                        ps.push(f);
                    },
                    _ => panic!()
                }
            }
            let p = G1Affine::new_unchecked(ps[5], ps[4]);
            let q = G2Affine::new_unchecked(ark_bn254::Fq2::new(ps[3], ps[2]), ark_bn254::Fq2::new(ps[1], ps[0]));
            if row.category == "Add1" {
                let (hintout, hint_script) = match hints_out[0].clone() {
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInAdd::from_doubleadd(r, p.x, p.y, q);
                        chunk_taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, 1)
                    },
                    HintOut::Double(r) => {
                        let hint_in = HintInAdd::from_double(r, p.x,p.y, q);
                        chunk_taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, 1)
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_point_add_with_frob(1);
                    let bcs_script = bitcom_point_add_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(row.link_id.clone(), HintOut::Add(hintout));
            } else if row.category == "Add2" {
                let (hintout, hint_script) = match hints_out[0].clone() {
                    HintOut::Add(r) => {
                        let hint_in = HintInAdd::from_add(r, p.x,p.y, q);
                        chunk_taps::hint_point_add_with_frob(sig, sec_out, sec_in.clone(), hint_in, -1)
                    },
                    _ => panic!("failed to match"),
                };
                    let ops_script = tap_point_add_with_frob( -1);
                    let bcs_script = bitcom_point_add_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script.clone() }
                        { bcs_script.clone() }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                    assert!(exec_result.final_stack.len() == 1);
                aux_output_per_link.insert(row.link_id.clone(), HintOut::Add(hintout));
            }
        } else if row.category == "SD" {
            assert_eq!(hints_out.len(), 2);
            let dense = match hints_out[0].clone() {
                    HintOut::DenseMul1(f) => f,
                    _ => panic!()
                };
            let (sd_hint, hint_script) = match hints_out[1].clone() {
                    HintOut::Add(f) => {
                        let hint_in = HintInSparseDenseMul::from_add(f, dense);
                        chunk_taps::hint_sparse_dense_mul(sig, sec_out, sec_in.clone(), hint_in, false)
                    },
                    _ => panic!()
                };
                let ops_script = tap_sparse_dense_mul(false);
                let bcs_script = bitcom_sparse_dense_mul(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
                    },
                    _ => panic!()
                }
            }
            let p2 = G1Affine::new_unchecked(ps[3], ps[2]);
            let p3 = G1Affine::new_unchecked(ps[1], ps[0]);
            let hint_in: HintInSparseAdd = HintInSparseAdd::from_groth_and_aux(p2, p3,q2, q3, nt2, nt3);
            if row.category == "SS1" {
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs_with_frob(sig, sec_out, sec_in.clone(), hint_in, 1);
                    let (ops_script, _, _) = tap_add_eval_mul_for_fixed_Qs_with_frob( nt2, nt3, q2, q3, 1);
                    let bcs_script = bitcom_add_eval_mul_for_fixed_Qs_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), HintOut::SparseAdd(hint_out));
            } else if row.category == "SS2" {
                let (hint_out, hint_script) = chunk_taps::hint_add_eval_mul_for_fixed_Qs_with_frob(sig, sec_out, sec_in.clone(), hint_in, -1);
                    let (ops_script, _, _) = tap_add_eval_mul_for_fixed_Qs_with_frob( nt2, nt3, q2, q3, -1);
                    let bcs_script = bitcom_add_eval_mul_for_fixed_Qs_with_frob(pub_scripts_per_link_id, sec_out, sec_in.clone());
                    let script = script!{
                        { hint_script }
                        { bcs_script }
                        { ops_script }
                    };
                    let exec_result = execute_script(script);
                    assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                aux_output_per_link.insert(row.link_id.clone(), HintOut::SparseAdd(hint_out));
            }
        } 
    }
}

fn evaluate_public_params(sig: &mut Sig, link_name_to_id: HashMap<String, (u32, bool)>, q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine, fixed_acc: ark_bn254::Fq12) -> HashMap<String, HintOut> {
    let f = ark_bn254::Fq12::ONE;
    let idhash = emulate_extern_hash_fps(vec![f.c0.c0.c0,f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0,f.c0.c2.c1, f.c1.c0.c0,f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0,f.c1.c2.c1], true);
    let fixedacc_hash = emulate_extern_hash_fps(vec![fixed_acc.c0.c0.c0,fixed_acc.c0.c0.c1, fixed_acc.c0.c1.c0, fixed_acc.c0.c1.c1, fixed_acc.c0.c2.c0,fixed_acc.c0.c2.c1, fixed_acc.c1.c0.c0,fixed_acc.c1.c0.c1, fixed_acc.c1.c1.c0, fixed_acc.c1.c1.c1, fixed_acc.c1.c2.c0,fixed_acc.c1.c2.c1], false);

    let id = HintOutPubIdentity {idhash, v: ark_bn254::Fq12::ONE};
    let fixed_acc = HintOutFixedAcc {f: fixed_acc, fhash: fixedacc_hash };
    
    let mut id_to_witness: HashMap<String, HintOut> = HashMap::new();
    id_to_witness.insert("identity".to_string(),HintOut::PubIdentity(id));
    id_to_witness.insert("Q3y1".to_string(),HintOut::FieldElem(q3.y.c1));
    id_to_witness.insert("Q3y0".to_string(),HintOut::FieldElem(q3.y.c0));
    id_to_witness.insert("Q3x1".to_string(),HintOut::FieldElem(q3.x.c1));
    id_to_witness.insert("Q3x0".to_string(),HintOut::FieldElem(q3.x.c0));
    id_to_witness.insert("Q2y1".to_string(),HintOut::FieldElem(q2.y.c1));
    id_to_witness.insert("Q2y0".to_string(),HintOut::FieldElem(q2.y.c0));
    id_to_witness.insert("Q2x1".to_string(),HintOut::FieldElem(q2.x.c1));
    id_to_witness.insert("Q2x0".to_string(),HintOut::FieldElem(q2.x.c0));
    id_to_witness.insert("f_fixed".to_string(),HintOut::FixedAcc(fixed_acc));

    let tup = vec![
        (link_name_to_id.get("identity").unwrap().clone(), idhash),
        (link_name_to_id.get("Q3y1").unwrap().clone(), emulate_fq_to_nibbles(q3.y.c1)),
        (link_name_to_id.get("Q3y0").unwrap().clone(), emulate_fq_to_nibbles(q3.y.c0)),
        (link_name_to_id.get("Q3x1").unwrap().clone(), emulate_fq_to_nibbles(q3.x.c1)),
        (link_name_to_id.get("Q3x0").unwrap().clone(), emulate_fq_to_nibbles(q3.x.c0)),

        (link_name_to_id.get("Q2y1").unwrap().clone(), emulate_fq_to_nibbles(q2.y.c1)),
        (link_name_to_id.get("Q2y0").unwrap().clone(), emulate_fq_to_nibbles(q2.y.c0)),
        (link_name_to_id.get("Q2x1").unwrap().clone(), emulate_fq_to_nibbles(q2.x.c1)),
        (link_name_to_id.get("Q2x0").unwrap().clone(), emulate_fq_to_nibbles(q2.x.c0)),

        (link_name_to_id.get("f_fixed").unwrap().clone(), fixedacc_hash),
    ];

    tup_to_scr(sig, tup);

    id_to_witness
}

fn evaluate_groth16_params(sig: &mut Sig, link_name_to_id: HashMap<String, (u32, bool)>, p2: G1Affine, p3: G1Affine, p4: G1Affine, q4: G2Affine, c: Fq12, s: Fq12, ks: Vec<ark_bn254::Fr>) -> HashMap<String, HintOut> {
    let cv = vec![c.c0.c0.c0,c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0,c.c0.c2.c1, c.c1.c0.c0,c.c1.c0.c1, c.c1.c1.c0, c.c1.c1.c1, c.c1.c2.c0,c.c1.c2.c1];
    let chash = emulate_extern_hash_fps(cv.clone(), false);
    let chash2 = emulate_extern_hash_fps(cv.clone(), true);
    
    let sv = vec![s.c0.c0.c0,s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0,s.c0.c2.c1, s.c1.c0.c0,s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0,s.c1.c2.c1];
    let shash = emulate_extern_hash_fps(sv.clone(), false);

    let cvinv = c.inverse().unwrap();
    let cvinvhash = emulate_extern_hash_fps(vec![cvinv.c0.c0.c0,cvinv.c0.c0.c1, cvinv.c0.c1.c0, cvinv.c0.c1.c1, cvinv.c0.c2.c0,cvinv.c0.c2.c1, cvinv.c1.c0.c0,cvinv.c1.c0.c1, cvinv.c1.c1.c0, cvinv.c1.c1.c1, cvinv.c1.c2.c0,cvinv.c1.c2.c1], false);
    let cvinvhash2 = emulate_extern_hash_fps(vec![cvinv.c0.c0.c0,cvinv.c0.c0.c1, cvinv.c0.c1.c0, cvinv.c0.c1.c1, cvinv.c0.c2.c0,cvinv.c0.c2.c1, cvinv.c1.c0.c0,cvinv.c1.c0.c1, cvinv.c1.c1.c0, cvinv.c1.c1.c1, cvinv.c1.c2.c0,cvinv.c1.c2.c1], true);

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
        HintOut::GrothC(HintOutGrothC { c:s, chash:shash }),
        HintOut::GrothC(HintOutGrothC { c:cvinv, chash: cvinvhash}),
        HintOut::GrothC(HintOutGrothC { c:cvinv, chash: cvinvhash2}),
        HintOut::FieldElem(q4.y.c1),
        HintOut::FieldElem(q4.y.c0),
        HintOut::FieldElem(q4.x.c1),
        HintOut::FieldElem(q4.x.c0),
        HintOut::ScalarElem(ks[0]),
        HintOut::ScalarElem(ks[1])
    ];
    assert_eq!(gparams.len(), gouts.len());

    let mut id_to_witness: HashMap<String, HintOut> = HashMap::new();
    for i in 0..gparams.len() {
        id_to_witness.insert(gparams[i].link_id.clone(), gouts[i].clone());
    }

    let mut tups: Vec<(u32, [u8;64])> = Vec::new(); 
    for (txt, wit) in id_to_witness.iter() {
        let id = link_name_to_id.get(txt).unwrap().clone().0;
        match wit {
            HintOut::FieldElem(f) => {
                tups.push((id, emulate_fq_to_nibbles(*f)));
            },
            HintOut::GrothC(f) => {
                tups.push((id, f.chash));
            }
            _ => (),
        }
    }
    id_to_witness
}

fn evaluate_msm(sig: &mut Sig, pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>, link_name_to_id: HashMap<String, (u32, bool)>, aux_output_per_link: &mut HashMap<String, HintOut>, pub_ins: usize, qs: Vec<ark_bn254::G1Affine>) {
    let tables = msm_config_gen(String::from("k0,k1"));
    let mut msm_tap_index = 0;
    for row in tables {
        println!("itr {:?} ID {:?} deps {:?}", msm_tap_index, row.link_id, row.dependencies);
        let sec_in: Vec<Link> = row.dependencies.split(",").into_iter().map(|s| link_name_to_id.get(s).unwrap().clone()).collect();
        let hints: Vec<HintOut> = row.dependencies.split(",").into_iter().map(|s| aux_output_per_link.get(s).unwrap().clone()).collect();
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, sec_in);
        if row.category == "MSM" {
            assert!((hints.len() == pub_ins && msm_tap_index == 0) || (hints.len() == pub_ins + 1 && msm_tap_index > 0));
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
            let (hint_res, hint_script) = hint_msm(sig, sec_out, sec_in.clone(), HintInMSM {t: acc, scalars}, msm_tap_index, qs.clone());
            let ops_script = tap_msm(8, msm_tap_index, qs.clone());
            let bcs_script = bitcom_msm(pub_scripts_per_link_id, sec_out, sec_in.clone());
            let script = script!{
                { hint_script }
                { bcs_script }
                { ops_script }
            };
            let exec_result = execute_script(script);
            assert!(!exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            
            aux_output_per_link.insert(row.link_id, HintOut::MSM(hint_res));
        }
        msm_tap_index += 1;
    }
}

fn evaluate_pre_miller_circuit(sig: &mut Sig, pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>, link_name_to_id: HashMap<String, (u32, bool)>, aux_output_per_link: &mut HashMap<String, HintOut>) {
    let tables = pre_miller_config_gen();

    for row in tables {
        let sec_in: Vec<Link> = row.dependencies.split(",").into_iter().map(|s| link_name_to_id.get(s).unwrap().clone()).collect();
        let hints: Vec<HintOut> = row.dependencies.split(",").into_iter().map(|s| aux_output_per_link.get(s).unwrap().clone()).collect();
        let sec_out = link_name_to_id.get(&row.link_id).unwrap().clone();
        println!("row name {:?} ID {:?}", row.category, sec_out);
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
            let (hint_res, hint_script) = hint_init_T4(sig, sec_out, sec_in.clone(), HintInInitT4::from_groth_q4(xs));
                let ops_script = tap_initT4();
                let bcs_script = bitcom_initT4(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);

            aux_output_per_link.insert(row.link_id, HintOut::InitT4(hint_res));
        } else if row.category == "PrePy" {
            assert!(hints.len()== 1);
            let pt = match hints[0] {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let (pyd,hint_script) = hints_precompute_Py(sig, sec_out, sec_in.clone(), HintInPrecomputePy::from_point(pt));
                let ops_script = tap_precompute_Py();
                let bcs_script = bitcom_precompute_Py(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
            let (pyd,hint_script) = hints_precompute_Px(sig, sec_out, sec_in.clone(), HintInPrecomputePx::from_points(xs));
                let ops_script = tap_precompute_Px();
                let bcs_script = bitcom_precompute_Px(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::FieldElem(pyd));
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
            let (hout, hint_script) = hint_hash_c(sig, sec_out, sec_in.clone(), HintInHashC::from_points(xs));
                let ops_script = tap_hash_c();
                let bcs_script = bitcom_hash_c(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
            let (hout,hint_script) = hint_hash_c2(sig, sec_out, sec_in.clone(), HintInHashC::from_groth(prev_hash));
                let ops_script = tap_hash_c2();
                let bcs_script = bitcom_hash_c2(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
                HintOut::HashC(c) => {
                    hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_groth_hc(c, d))
                },
                HintOut::GrothC(c) => {
                    hints_dense_dense_mul0(sig, sec_out, sec_in.clone(), HintInDenseMul0::from_grothc(c, d))
                },
                _ => panic!("failed to match"),
            };
                let ops_script = tap_dense_dense_mul0(true);
                let bcs_script = bitcom_dense_dense_mul0(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    {bcs_script}
                    { ops_script }
                };
                let exec_result = execute_script(script);
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
                HintOut::HashC(a) => {
                    hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_groth_hc(a, b))
                },
                HintOut::GrothC(a) => {
                    hints_dense_dense_mul1(sig, sec_out, sec_in.clone(), HintInDenseMul1::from_grothc(a, b))
                },
                _ => panic!("failed to match"),
            };
                let ops_script = tap_dense_dense_mul1(true);
                let bcs_script = bitcom_dense_dense_mul1(pub_scripts_per_link_id, sec_out, sec_in.clone());
                let script = script!{
                    { hint_script }
                    { bcs_script }
                    { ops_script }
                };
                let exec_result = execute_script(script);
                assert!(!exec_result.success);
                assert!(exec_result.final_stack.len() == 1);
            aux_output_per_link.insert(row.link_id, HintOut::DenseMul1(hout));
        }
    }
}

pub fn evaluate(sig: &mut Sig, pub_scripts_per_link_id: &HashMap<u32, WOTSPubKey>, p2: G1Affine, p3: G1Affine, p4: G1Affine,q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine, q4: G2Affine, c: Fq12, s: Fq12, fixed_acc: ark_bn254::Fq12, ks: Vec<ark_bn254::Fr>, ks_vks: Vec<ark_bn254::G1Affine>) {
    let (link_name_to_id, facc, tacc) = assign_link_ids();
    let mut aux_out_per_link: HashMap<String, HintOut> = HashMap::new();
    let pubmap = evaluate_public_params(sig, link_name_to_id.clone(), q2, q3, fixed_acc);
    aux_out_per_link.extend(pubmap);
    let grothmap = evaluate_groth16_params(sig, link_name_to_id.clone(), p2, p3, p4, q4, c, s, ks.clone());
    aux_out_per_link.extend(grothmap);

    evaluate_pre_miller_circuit(sig, pub_scripts_per_link_id, link_name_to_id.clone(), &mut aux_out_per_link);
    evaluate_msm(sig, pub_scripts_per_link_id, link_name_to_id.clone(), &mut aux_out_per_link, ks.len(), ks_vks);
    
    let (nt2, nt3) = evaluate_miller_circuit(sig, pub_scripts_per_link_id, link_name_to_id.clone(), &mut aux_out_per_link, q2, q3, q2, q3);
    evaluate_post_miller_circuit(sig, pub_scripts_per_link_id, link_name_to_id.clone(), &mut aux_out_per_link, nt2, nt3, q2, q3, facc.clone(), tacc);

    let hint = aux_out_per_link.get("fin");
    if hint.is_none() {
        println!("debug hintmap {:?}", aux_out_per_link);
    } else {
        let hint = hint.unwrap();
        match hint {
            HintOut::DenseMul1(c)=> {
                assert_eq!(c.c, ark_bn254::Fq12::ONE);
            },
            _ => {},
        }
    }
}


#[cfg(test)]
mod test {
    use std::ops::Neg;

    use ark_ec::{AffineRepr, CurveGroup};

    use crate::{bn254::{chunk_config::keygen, chunk_msm::try_msm}, groth16::offchain_checker::compute_c_wi, signatures::winternitz_compact};

    use super::*;

    #[test]
    fn test_groth16_verifier() {
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
            fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
                let c = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a * b)
                })?;

                for _ in 0..(self.num_variables - 3) {
                    let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
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
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );

        println!("expected msm {:?}", p1);


        println!();
        println!();

        let f = Bn254::multi_miller_loop_affine([p1,p2,p3,p4], [q1,q2,q3,q4]).0;
        let p3q3 = Bn254::multi_miller_loop_affine([p3], [q3]).0;

        let (c, s) = compute_c_wi(f);

        let fixed_acc = p3q3;

        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";


        let pub_scripts_per_link_id = &keygen(master_secret);
        let mut sig = Sig { msk: Some(master_secret), cache: HashMap::new() };
        evaluate(&mut sig, pub_scripts_per_link_id, p1, p2, p4, q1, q2, q4, c, s, fixed_acc, vec![pub_commit, ark_bn254::Fr::ONE], vec![vk.gamma_abc_g1[1], vk.gamma_abc_g1[0]]);

        // println!("corrupt");
        // // mock faulty data
        // let index_to_corrupt = 101;
        // let corrup_scr = winternitz_compact::sign(&format!("{}{:04X}", master_secret, index_to_corrupt), [1u8;64]);
        // sig.cache.insert(index_to_corrupt, corrup_scr);
        // evaluate(&mut sig, pub_scripts_per_link_id, p2, p3, p4, q2, q3, q4, c, s, fixed_acc);
    }
}