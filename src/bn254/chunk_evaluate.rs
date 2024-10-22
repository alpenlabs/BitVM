
use std::collections::{HashMap};
use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::{Field, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_primitves::emulate_extern_hash_fps;
use crate::bn254::chunk_taps::{hint_hash_c, hint_hash_c2, hint_init_T4, hints_dense_dense_mul0, hints_dense_dense_mul1, hints_frob_fp12, hints_precompute_Px, hints_precompute_Py, tap_add_eval_mul_for_fixed_Qs, tap_frob_fp12, tap_point_add, tap_precompute_Px, tap_precompute_Py, tap_sparse_dense_mul, HashBytes, HintInAdd, HintInDblAdd, HintInDenseMul0, HintInDenseMul1, HintInDouble, HintInFrobFp12, HintInHashC, HintInInitT4, HintInPrecomputePx, HintInPrecomputePy, HintInSparseAdd, HintInSparseDbl, HintInSparseDenseMul, HintInSquaring, HintOutFixedAcc, HintOutFrobFp12, HintOutGrothC, HintOutPubIdentity};
use crate::bn254::{ chunk_taps};

use super::chunk_compile::assign_link_ids;
use super::chunk_config::{groth16_derivatives, groth16_params, post_miller_config_gen, post_miller_params, pre_miller_config_gen, public_params};
use super::chunk_taps::HintOut;
use super::{chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4}};


// given a groth16 verification key, generate all of the tapscripts in compile mode
fn evaluate_miller_circuit(id_to_sec: HashMap<String, u32>,hintmap: &mut HashMap<String, HintOut>, t2: ark_bn254::G2Affine, t3: ark_bn254::G2Affine, q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine) -> (G2Affine, G2Affine) {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;

    const ATE_LOOP_COUNT: &'static [i8] = &[
         0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
         0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
         -1, 0, 0, 0, 1, 0, 1, 1,
     ];
    let blocks = miller_config_gen();

    let mut itr = 0;
    // println!("max id {:?}", max_id);
    let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";


    fn get_index(blk_name: &str, id_to_sec: HashMap<String, u32>)-> u32 {
        id_to_sec.get(blk_name).unwrap().clone()
    }

    fn get_deps(deps: &str, id_to_sec: HashMap<String, u32>) -> Vec<u32> {
        let splits: Vec<u32>= deps.split(",").into_iter().map(|s| get_index(s, id_to_sec.clone())).collect();
        splits
    }

    let mut nt2 = t2.clone();
    let mut nt3 = t3.clone();
    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        let blocks_of_a_loop = &blocks[itr];
        for block in blocks_of_a_loop {
            let self_index = get_index(&block.ID, id_to_sec.clone());
            let deps_indices = get_deps(&block.Deps, id_to_sec.clone());
            let hints: Vec<HintOut> = block.Deps.split(",").into_iter().map(|s| hintmap.get(s).unwrap().clone()).collect();
            println!("{itr} ate {:?} ID {:?} deps {:?}", *bit, block.ID, block.Deps);
            println!("{itr} {} ID {:?} deps {:?}", block.name, self_index, deps_indices);
            let blk_name = block.name.clone();
            if blk_name == "Sqr" {
                assert_eq!(hints.len(), 1);
                let (hintout, _) = match hints[0].clone() {
                    HintOut::DenseMul1(r) => {
                        chunk_taps::hints_squaring(sec_key_for_bitcomms, self_index, deps_indices, HintInSquaring::from_dmul1(r))
                    },
                    HintOut::GrothC(r) => {
                        chunk_taps::hints_squaring(sec_key_for_bitcomms, self_index, deps_indices, HintInSquaring::from_grothc(r))
                    },
                    _ => panic!("failed to match"),
                };
                hintmap.insert(block.ID.clone(), HintOut::Squaring(hintout));
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
                let (hintout, _) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDblAdd::from_initT4(r, p,q);
                        chunk_taps::hint_point_ops(sec_key_for_bitcomms, self_index, deps_indices, hint_in,*bit)
                    },
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDblAdd::from_doubleadd(r, p,q);
                        chunk_taps::hint_point_ops(sec_key_for_bitcomms, self_index, deps_indices, hint_in,*bit)
                    },
                    HintOut::Double(r) => {
                        let hint_in = HintInDblAdd::from_double(r, p,q);
                        chunk_taps::hint_point_ops(sec_key_for_bitcomms, self_index, deps_indices, hint_in,*bit)
                    },
                    _ => panic!("failed to match"),
                };
                hintmap.insert(block.ID.clone(), HintOut::DblAdd(hintout));
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
                let (hintout, _) = match hints[0].clone() {
                    HintOut::InitT4(r) => {
                        let hint_in = HintInDouble::from_initT4(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sec_key_for_bitcomms, self_index, deps_indices, hint_in)
                    },
                    HintOut::DblAdd(r) => {
                        let hint_in = HintInDouble::from_doubleadd(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sec_key_for_bitcomms, self_index, deps_indices, hint_in)
                    },
                    HintOut::Double(r) => {
                        let hint_in = HintInDouble::from_double(r, p.x,p.y);
                        chunk_taps::hint_point_dbl(sec_key_for_bitcomms, self_index, deps_indices, hint_in)
                    },
                    _ => panic!("failed to match"),
                };
                hintmap.insert(block.ID.clone(), HintOut::Double(hintout));
            } else if blk_name == "SD1" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                        HintOut::Squaring(f) => f,
                        _ => panic!()
                    };
                let (sd_hint, _) = match hints[1].clone() {
                        HintOut::DblAdd(f) => {
                            let hint_in = HintInSparseDenseMul::from_double_add_top(f, dense);
                            chunk_taps::hints_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, hint_in, true)
                        },
                        HintOut::Double(f) => {
                            let hint_in = HintInSparseDenseMul::from_double(f, dense);
                            chunk_taps::hints_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, hint_in, true)
                        }
                        _ => panic!()
                    };

                hintmap.insert(block.ID.clone(), HintOut::SparseDenseMul(sd_hint));
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
                let (hint_out, _) = chunk_taps::hint_double_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices, hint_in);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                hintmap.insert(block.ID.clone(), HintOut::SparseDbl(hint_out));
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
                let (hint_out,_) = hints_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul0::from_sparse_dense_dbl(c, d));
                hintmap.insert(block.ID.clone(), HintOut::DenseMul0(hint_out));
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
                let (hint_out,_) = hints_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul1::from_sparse_dense_dbl(c, d));
                hintmap.insert(block.ID.clone(), HintOut::DenseMul1(hint_out));
            } else if blk_name == "DD3" {
                assert!(hints.len() == 2);
                let c = match hints[0].clone() {
                    HintOut::DenseMul1(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, _) = match hints[1].clone() {
                    HintOut::GrothC(r) => {
                        hints_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul0::from_dense_c(c, r))
                    },
                    _ => panic!("failed to match"),
                };

                hintmap.insert(block.ID.clone(), HintOut::DenseMul0(hint_out));
            } else if blk_name == "DD4" {
                assert!(hints.len() == 3);
                let c = match hints[0].clone() {
                    HintOut::DenseMul1(r) => r,
                    _ => panic!("failed to match"),
                };
                let (hint_out, _) = match hints[1].clone() {
                    HintOut::GrothC(r) => {
                        hints_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul1::from_dense_c(c, r))
                    },
                    _ => panic!("failed to match"),
                };
                hintmap.insert(block.ID.clone(), HintOut::DenseMul1(hint_out));
            } else if blk_name == "SD2" {
                assert_eq!(hints.len(), 2);
                let dense = match hints[0].clone() {
                        HintOut::DenseMul1(f) => f,
                        _ => panic!()
                    };
                let (sd_hint, _) = match hints[1].clone() {
                        HintOut::DblAdd(f) => {
                            let hint_in = HintInSparseDenseMul::from_doubl_add_bottom(f, dense);
                            chunk_taps::hints_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, hint_in, false)
                        },
                        _ => panic!()
                    };
                hintmap.insert(block.ID.clone(), HintOut::SparseDenseMul(sd_hint));
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
                let (hint_out, _) = chunk_taps::hint_add_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices, hint_in);
                nt2 = hint_out.t2;
                nt3 = hint_out.t3;
                hintmap.insert(block.ID.clone(), HintOut::SparseAdd(hint_out));
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
            let (hint_out,_) = hints_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul0::from_sparse_dense_add(c, d));
            hintmap.insert(block.ID.clone(), HintOut::DenseMul0(hint_out));
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
                let (hint_out,_) = hints_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, HintInDenseMul1::from_sparse_dense_add(c, d));
                hintmap.insert(block.ID.clone(), HintOut::DenseMul1(hint_out));
            } else {
                println!("unhandled {:?}", blk_name);
                panic!();
            }
        }
        itr += 1;
    }   
    (nt2, nt3)

}


fn evaluate_post_miller_circuit(id_map: HashMap<String, u32>, hintmap: &mut HashMap<String, HintOut>, t2: ark_bn254::G2Affine,  t3: ark_bn254::G2Affine,  q2: ark_bn254::G2Affine,  q3: ark_bn254::G2Affine, facc: String, tacc: String ) -> HashMap<String, u32> {
    let tables = post_miller_config_gen(facc,tacc);
    let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    let mut nt2 = t2;
    let mut nt3 = t3;
    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.ID);
        let sec_out = id_map.get(&row.ID).unwrap().clone();
        let hints_out: Vec<HintOut> = row.Deps.split(",").into_iter().map(|s| hintmap.get(s).unwrap().clone()).collect();
        if row.name.starts_with("Frob") {
            assert_eq!(hints_out.len(), 1);
            let cinv = match hints_out[0].clone() {
                HintOut::GrothC(f) => f,
                _ => panic!()
            };
            let mut power = 1;
            if row.name == "Frob2" {
                power = 2;
            } else if row.name == "Frob3" {
                power = 3;
            }
            let hint_in = HintInFrobFp12::from_groth_c(cinv);
            let (h, _) = hints_frob_fp12(sec_key, sec_out,sec_in, hint_in, power);
            hintmap.insert(row.ID, HintOut::FrobFp12(h));
        } else if row.name == "DD1" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };
            let hint_out = match hints_out[1].clone() {
                HintOut::FrobFp12(d) => {
                    let (hint_out,_) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_dense_frob(c, d));
                    hint_out
                },
                HintOut::GrothC(d) => { // s
                    let (hint_out,_) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_dense_c(c, d));
                    hint_out
                },
                HintOut::FixedAcc(r) => {
                    let (hint_out, _) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_dense_fixed_acc(c, r));
                    hint_out
                },
                _ => panic!("failed to match"),
            };
            hintmap.insert(row.ID.clone(), HintOut::DenseMul0(hint_out));
        } else if row.name == "DD2" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                HintOut::DenseMul1(r) => r,
                _ => panic!("failed to match"),
            };
            let hint_out = match hints_out[1].clone() {
                HintOut::FrobFp12(d) => {
                    let (hint_out,_) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_dense_frob(c, d));
                    hint_out
                },
                HintOut::GrothC(d) => {
                    let (hint_out,_) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_dense_c(c, d));
                    hint_out
                },
                HintOut::FixedAcc(r) => {
                    let (hint_out, _) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_dense_fixed_acc(c, r));
                    hint_out
                },
                _ => panic!("failed to match"),
            };
            hintmap.insert(row.ID.clone(), HintOut::DenseMul1(hint_out));
        } else if row.name == "DD3" {
            assert!(hints_out.len() == 2);
            let c = match hints_out[0].clone() {
                HintOut::SparseDenseMul(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                HintOut::SparseAdd(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out,_) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_sparse_dense_add(c, d));
            hintmap.insert(row.ID.clone(), HintOut::DenseMul0(hint_out));
        } else if row.name == "DD4" {
            assert!(hints_out.len() == 3);
            let c = match hints_out[0].clone() {
                HintOut::SparseDenseMul(r) => r,
                _ => panic!("failed to match"),
            };
            let d = match hints_out[1].clone() {
                HintOut::SparseAdd(r) => r,
                _ => panic!("failed to match"),
            };
            let (hint_out,_) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_sparse_dense_add(c, d));
            hintmap.insert(row.ID.clone(), HintOut::DenseMul1(hint_out));
        } else if row.name == "Add1" || row.name == "Add2"  {
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
            let (hintout, _) = match hints_out[0].clone() {
                HintOut::DblAdd(r) => {
                    let hint_in = HintInAdd::from_doubleadd(r, p.x, p.y, q);
                    chunk_taps::hint_point_add(sec_key, sec_out, sec_in, hint_in, 1)
                },
                HintOut::Double(r) => {
                    let hint_in = HintInAdd::from_double(r, p.x,p.y, q);
                    chunk_taps::hint_point_add(sec_key, sec_out, sec_in, hint_in, 1)
                },
                HintOut::Add(r) => {
                    let hint_in = HintInAdd::from_add(r, p.x,p.y, q);
                    chunk_taps::hint_point_add(sec_key, sec_out, sec_in, hint_in, -1)
                },
                _ => panic!("failed to match"),
            };
            hintmap.insert(row.ID.clone(), HintOut::Add(hintout));
        } else if row.name == "SD" {
            assert_eq!(hints_out.len(), 2);
            let dense = match hints_out[0].clone() {
                    HintOut::DenseMul1(f) => f,
                    _ => panic!()
                };
            let (sd_hint, _) = match hints_out[1].clone() {
                    HintOut::Add(f) => {
                        let hint_in = HintInSparseDenseMul::from_add(f, dense);
                        chunk_taps::hints_sparse_dense_mul(sec_key, sec_out, sec_in, hint_in, false)
                    },
                    _ => panic!()
                };
            hintmap.insert(row.ID.clone(), HintOut::SparseDenseMul(sd_hint));
        } else if row.name == "SS" {
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
            let (hint_out, _) = chunk_taps::hint_add_eval_mul_for_fixed_Qs(sec_key, sec_out, sec_in, hint_in);
            nt2 = hint_out.t2;
            nt3 = hint_out.t3;
            hintmap.insert(row.ID.clone(), HintOut::SparseAdd(hint_out));
        } 
    }
    return id_map;
}

fn evaluate_public_params(q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine, fixed_acc: ark_bn254::Fq12) -> HashMap<String, HintOut> {
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
    id_to_witness
}

fn evaluate_groth16_params(p2: G1Affine, p3: G1Affine, p4: G1Affine, q4: G2Affine, c: Fq12, s: Fq12) -> HashMap<String, HintOut> {
    let cv = vec![c.c0.c0.c0,c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0,c.c0.c2.c1, c.c1.c0.c0,c.c1.c0.c1, c.c1.c1.c0, c.c1.c1.c1, c.c1.c2.c0,c.c1.c2.c1];
    let chash = emulate_extern_hash_fps(cv.clone(), false);
    let chash2 = emulate_extern_hash_fps(cv.clone(), true);
    
    let sv = vec![s.c0.c0.c0,s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0,s.c0.c2.c1, s.c1.c0.c0,s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0,s.c1.c2.c1];
    let shash = emulate_extern_hash_fps(sv.clone(), false);

    let cvinv = c.inverse().unwrap();
    let cvinvhash = emulate_extern_hash_fps(vec![cvinv.c0.c0.c0,cvinv.c0.c0.c1, cvinv.c0.c1.c0, cvinv.c0.c1.c1, cvinv.c0.c2.c0,cvinv.c0.c2.c1, cvinv.c1.c0.c0,cvinv.c1.c0.c1, cvinv.c1.c1.c0, cvinv.c1.c1.c1, cvinv.c1.c2.c0,cvinv.c1.c2.c1], false);
    let cvinvhash2 = emulate_extern_hash_fps(vec![cvinv.c0.c0.c0,cvinv.c0.c0.c1, cvinv.c0.c1.c0, cvinv.c0.c1.c1, cvinv.c0.c2.c0,cvinv.c0.c2.c1, cvinv.c1.c0.c0,cvinv.c1.c0.c1, cvinv.c1.c1.c0, cvinv.c1.c1.c1, cvinv.c1.c2.c0,cvinv.c1.c2.c1], true);

    let gparams = groth16_params();
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
    ];
    assert_eq!(gparams.len(), gouts.len());

    let mut id_to_witness: HashMap<String, HintOut> = HashMap::new();
    for i in 0..gparams.len() {
        id_to_witness.insert(gparams[i].clone(), gouts[i].clone());
    }
    id_to_witness
}

fn evaluate_pre_miller_circuit(id_map: HashMap<String, u32>, hintmap: &mut HashMap<String, HintOut>) {
    let tables = pre_miller_config_gen();
    let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        let hints: Vec<HintOut> = row.Deps.split(",").into_iter().map(|s| hintmap.get(s).unwrap().clone()).collect();
        let sec_out = id_map.get(&row.ID).unwrap().clone();
        if row.name == "T4Init" {
            assert!(hints.len() == 4);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (hint_res, _) = hint_init_T4(sec_key, sec_out,sec_in, HintInInitT4::from_groth_q4(xs));
            hintmap.insert(row.ID, HintOut::InitT4(hint_res));
        } else if row.name == "PrePy" {
            assert!(hints.len()== 1);
            let pt = match hints[0] {
                HintOut::FieldElem(r) => r,
                _ => panic!("failed to match"),
            };
            let (pyd,_) = hints_precompute_Py(sec_key, sec_out, sec_in, HintInPrecomputePy::from_point(pt));
            hintmap.insert(row.ID, HintOut::FieldElem(pyd));
        } else if row.name == "PrePx" {
            assert!(hints.len() == 3);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (pyd,_) = hints_precompute_Px(sec_key, sec_out, sec_in, HintInPrecomputePx::from_points(xs));
            hintmap.insert(row.ID, HintOut::FieldElem(pyd));
        } else if row.name == "HashC" {
            assert!(hints.len() == 12);
            let mut xs = vec![];
            for i in 0..hints.len() {
                let x = match hints[i] {
                    HintOut::FieldElem(r) => r,
                    _ => panic!("failed to match"),
                };
                xs.push(x);
            }
            let (hout,_) = hint_hash_c(sec_key, sec_out, sec_in, HintInHashC::from_points(xs));
            if !hintmap.contains_key(&row.ID) {
                hintmap.insert(row.ID, HintOut::HashC(hout));
            }
        } else if row.name == "HashC2" {
            assert!(hints.len() == 1);
            let prev_hash = match hints[0].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let (hout,_) = hint_hash_c2(sec_key, sec_out, sec_in, HintInHashC::from_groth(prev_hash));
            if !hintmap.contains_key(&row.ID) {
                hintmap.insert(row.ID, HintOut::HashC(hout));
            }
        } else if row.name == "DD1" {
            assert!(hints.len() == 2);
            let d = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let c = match hints[0].clone() {
                HintOut::HashC(c) => {
                    let (pyd,_) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_groth_hc(c, d));
                    pyd
                },
                HintOut::GrothC(c) => {
                    let (pyd,_) = hints_dense_dense_mul0(sec_key, sec_out, sec_in, HintInDenseMul0::from_grothc(c, d));
                    pyd
                },
                _ => panic!("failed to match"),
            };
            hintmap.insert(row.ID, HintOut::DenseMul0(c));
        } else if row.name == "DD2" {
            assert!(hints.len() == 3);
            let b = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let c0 = match hints[1].clone() {
                HintOut::GrothC(r) => r,
                _ => panic!("failed to match"),
            };
            let hout = match hints[0].clone() {
                HintOut::HashC(a) => {
                    let (pyd,_) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_groth_hc(a, b));
                    pyd
                },
                HintOut::GrothC(a) => {
                    let (pyd,_) = hints_dense_dense_mul1(sec_key, sec_out, sec_in, HintInDenseMul1::from_grothc(a, b));
                    pyd
                },
                _ => panic!("failed to match"),
            };
            hintmap.insert(row.ID, HintOut::DenseMul1(hout));
        }
    }
}

fn evaluate(p2: G1Affine, p3: G1Affine, p4: G1Affine,q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine, q4: G2Affine, c: Fq12, s: Fq12, fixed_acc: ark_bn254::Fq12) {
    let (id_to_sec, facc, tacc) = assign_link_ids();
    let mut hintmap: HashMap<String, HintOut> = HashMap::new();
    let pubmap = evaluate_public_params(q2, q3, fixed_acc);
    hintmap.extend(pubmap);
    let grothmap = evaluate_groth16_params(p2, p3, p4, q4, c, s);
    hintmap.extend(grothmap);
    evaluate_pre_miller_circuit(id_to_sec.clone(), &mut hintmap);
    let (nt2, nt3) = evaluate_miller_circuit(id_to_sec.clone(), &mut hintmap, q2, q3, q2, q3);
    evaluate_post_miller_circuit(id_to_sec, &mut hintmap, nt2, nt3, q2, q3, facc, tacc);
    println!("Done");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_evaluate() {
        let mut prng = ChaCha20Rng::seed_from_u64(0); 
        let q2 = G2Affine::rand(&mut prng);
        let q3 = G2Affine::rand(&mut prng);
        let q4 = G2Affine::rand(&mut prng);

        let p2 = G1Affine::rand(&mut prng);
        let p3 = G1Affine::rand(&mut prng);
        let p4 = G1Affine::rand(&mut prng);
        let c = ark_bn254::Fq12::rand(&mut prng);
        let s = ark_bn254::Fq12::rand(&mut prng);
        let fixed_acc = ark_bn254::Fq12::ONE;
        evaluate(p2, p3, p4, q2, q3, q4, c, s, fixed_acc);
    }
}