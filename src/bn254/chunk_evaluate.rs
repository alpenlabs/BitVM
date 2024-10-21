
use std::collections::{HashMap};
use ark_bn254::g2::G2Affine;
use ark_bn254::{Fq12, G1Affine};
use ark_ff::{Field, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_primitves::emulate_extern_hash_fps;
use crate::bn254::chunk_taps::{tap_add_eval_mul_for_fixed_Qs, tap_frob_fp12, tap_point_add, tap_sparse_dense_mul, HashBytes, HintOutFixedAcc, HintOutGrothC, HintOutGrothCInv, HintOutGrothS, HintOutPubIdentity};
use crate::bn254::{ chunk_taps};

use super::chunk_compile::assign_link_ids;
use super::chunk_config::{groth16_derivatives, groth16_params, post_miller_config_gen, post_miller_params, pre_miller_config_gen, public_params};
use super::chunk_taps::HintOut;
use super::{chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4}};


// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile_miller_circuit(id_to_sec: HashMap<String, u32>, t2: ark_bn254::G2Affine, t3: ark_bn254::G2Affine, q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine) -> (G2Affine, G2Affine) {
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
            println!("{itr} ate {:?} ID {:?} deps {:?}", *bit, block.ID, block.Deps);
            println!("{itr} {} ID {:?} deps {:?}", block.name, self_index, deps_indices);
            let blk_name = block.name.clone();
            if blk_name == "Sqr" {
                chunk_taps::tap_squaring(sec_key_for_bitcomms, self_index, deps_indices);
            } else if blk_name == "DblAdd" {
                chunk_taps::tap_point_ops(sec_key_for_bitcomms, self_index, deps_indices, *bit);
            } else if blk_name == "Dbl" {
                chunk_taps::tap_point_dbl(sec_key_for_bitcomms, self_index, deps_indices);
            } else if blk_name == "SD1" {
                chunk_taps::tap_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, true);
            } else if blk_name == "SS1" {
                let (_, a, b) = chunk_taps::tap_double_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices, nt2, nt3);
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD1" {
                chunk_taps::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "DD2" {
                chunk_taps::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "DD3" {
                chunk_taps::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "DD4" {
                chunk_taps::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "SD2" {
                chunk_taps::tap_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "SS2" {
                let (_, a, b) = chunk_taps::tap_add_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices, nt2, nt3, q2, q3);
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD5" {
                chunk_taps::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else if blk_name == "DD6" {
                chunk_taps::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
            } else {
                println!("unhandled {:?}", blk_name);
                panic!();
            }
        }
        itr += 1;
    }   
    (nt2, nt3)

}


fn compile_pre_miller_circuit(id_map: HashMap<String, u32>)  {
    let tables = pre_miller_config_gen();
    let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.ID);
        let sec_out: Vec<u32> = row.ID.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        if row.name == "T4Init" {
            tap_initT4(sec_key, sec_out[0],sec_in);
        } else if row.name == "PreP" {
            // tap_precompute_P(sec_key, sec_out, sec_in);
        } else if row.name == "HashC" {
            tap_hash_c(sec_key, sec_out[0], sec_in);
        } else if row.name == "DD1" {
            tap_dense_dense_mul0(sec_key, sec_out[0], sec_in, true);
        } else if row.name == "DD2" {
            tap_dense_dense_mul1(sec_key, sec_out[0], sec_in, true);
        }
    }
}

fn compile_post_miller_circuit(id_map: HashMap<String, u32>, t2: ark_bn254::G2Affine,  t3: ark_bn254::G2Affine,  q2: ark_bn254::G2Affine,  q3: ark_bn254::G2Affine, facc: String, tacc: String ) -> HashMap<String, u32> {
    let tables = post_miller_config_gen(facc,tacc);
    let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    let mut nt2 = t2;
    let mut nt3 = t3;
    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.ID);
        let sec_out: Vec<u32> = row.ID.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        if row.name == "Frob1" {
            tap_frob_fp12(sec_key, sec_out[0],sec_in, 1);
        } else if row.name == "Frob2" {
            tap_frob_fp12(sec_key, sec_out[0],sec_in, 2);
        } else if row.name == "Frob3" {
            tap_frob_fp12(sec_key, sec_out[0],sec_in, 3);
        } else if row.name == "DD1" {
            tap_dense_dense_mul0(sec_key, sec_out[0], sec_in, false);
        } else if row.name == "DD2" {
            tap_dense_dense_mul1(sec_key, sec_out[0], sec_in, false);
        } else if row.name == "DD3" {
            tap_dense_dense_mul0(sec_key, sec_out[0], sec_in, true);
        } else if row.name == "DD4" {
            tap_dense_dense_mul1(sec_key, sec_out[0], sec_in, true);
        } else if row.name == "Add1" {
            tap_point_add(sec_key, sec_out[0], sec_in, 1);
        } else if row.name == "Add2" {
            tap_point_add(sec_key, sec_out[0], sec_in, -1);
        } else if row.name == "SD" {
            tap_sparse_dense_mul(sec_key, sec_out[0], sec_in, false);
        } else if row.name == "SS" {
            let (scr, a, b) = tap_add_eval_mul_for_fixed_Qs(sec_key, sec_out[0], sec_in, nt2, nt3, q2, q3);
            nt2=a;
            nt3=b;
        }
    }
    return id_map;
}

fn evaluate_public_params() -> Vec<HintOut> {
    let mut prng = ChaCha20Rng::seed_from_u64(0); 
    let idhash: HashBytes = [0u8; 64];
    let q2 = G2Affine::rand(&mut prng);
    let q3 = G2Affine::rand(&mut prng);
    let fixed_acc = ark_bn254::Fq12::rand(&mut prng);
    let id = HintOutPubIdentity {idhash, v: ark_bn254::Fq12::ONE};
    let fixed_acc = HintOutFixedAcc {f: fixed_acc };
    vec![
        HintOut::PubIdentity(id),
        HintOut::FieldElem(q3.y.c1),
        HintOut::FieldElem(q3.y.c0),
        HintOut::FieldElem(q3.x.c1),
        HintOut::FieldElem(q3.x.c0),
        HintOut::FieldElem(q2.y.c1),
        HintOut::FieldElem(q2.y.c0),
        HintOut::FieldElem(q2.x.c1),
        HintOut::FieldElem(q2.x.c0),
        HintOut::FixedAcc(fixed_acc),
    ]
}

fn evaluate_groth16_params(p2: G1Affine, p3: G1Affine, p4: G1Affine, q4: G2Affine, c: Fq12, s: Fq12) -> Vec<HintOut> {
    let cv = vec![c.c0.c0.c0,c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0,c.c0.c2.c1, c.c1.c0.c0,c.c1.c0.c1, c.c1.c1.c0, c.c1.c1.c1, c.c1.c2.c0,c.c1.c2.c1];
    let chash = emulate_extern_hash_fps(cv.clone(), false);
    let sv = vec![s.c0.c0.c0,s.c0.c0.c1, s.c0.c1.c0, s.c0.c1.c1, s.c0.c2.c0,s.c0.c2.c1, s.c1.c0.c0,s.c1.c0.c1, s.c1.c1.c0, s.c1.c1.c1, s.c1.c2.c0,s.c1.c2.c1];
    let shash = emulate_extern_hash_fps(sv.clone(), false);

    let cvinv = c.inverse().unwrap();
    let cvinvhash = emulate_extern_hash_fps(vec![cvinv.c0.c0.c0,cvinv.c0.c0.c1, cvinv.c0.c1.c0, cvinv.c0.c1.c1, cvinv.c0.c2.c0,cvinv.c0.c2.c1, cvinv.c1.c0.c0,cvinv.c1.c0.c1, cvinv.c1.c1.c0, cvinv.c1.c1.c1, cvinv.c1.c2.c0,cvinv.c1.c2.c1], false);

    vec![
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
        HintOut::GrothS(HintOutGrothS { s, shash }),
        HintOut::GrothCInv(HintOutGrothCInv { cinv:cvinv, cinvhash: cvinvhash}),
        HintOut::FieldElem(q4.y.c1),
        HintOut::FieldElem(q4.y.c0),
        HintOut::FieldElem(q4.x.c1),
        HintOut::FieldElem(q4.x.c0),
    ]
}

fn evaluate_pre_miller_circuit() {
    // let tables = pre_miller_config_gen();
    // let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    // for row in tables {
    //     let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
    //     println!("row ID {:?}", row.ID);
    //     let sec_out: Vec<u32> = row.ID.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
    //     if row.name == "T4Init" {
    //         tap_initT4(sec_key, sec_out[0],sec_in);
    //     } else if row.name == "PreP" {
    //         tap_precompute_P(sec_key, sec_out, sec_in);
    //     } else if row.name == "HashC" {
    //         tap_hash_c(sec_key, sec_out[0], sec_in);
    //     } else if row.name == "DD1" {
    //         tap_dense_dense_mul0(sec_key, sec_out[0], sec_in, true);
    //     } else if row.name == "DD2" {
    //         tap_dense_dense_mul1(sec_key, sec_out[0], sec_in, true);
    //     }
    // }
}

fn evaluate(q2: G2Affine, q3: G2Affine) {
    let (id_map, facc, tacc) = assign_link_ids();
    compile_pre_miller_circuit(id_map.clone());
    let (t2, t3) = compile_miller_circuit(id_map.clone(), q2, q3, q2, q3);
    compile_post_miller_circuit(id_map, t2, t3, q2, q3, facc, tacc);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assign_sth() {

    }


}