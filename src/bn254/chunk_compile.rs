
use std::collections::{HashMap};
use ark_bn254::g2::G2Affine;
use ark_ec::bn::BnConfig;

use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_taps::{tap_add_eval_mul_for_fixed_Qs, tap_frob_fp12, tap_hash_c2, tap_point_add, tap_sparse_dense_mul};
use crate::bn254::{ chunk_taps};

use super::chunk_config::{groth16_derivatives, groth16_params, post_miller_config_gen, post_miller_params, pre_miller_config_gen, public_params};
use super::{chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4}};

// pub const ATE_LOOP_COUNT: &'static [i8] = &[
//     0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
//     0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
//     -1, 0, 0, 0, 1, 0, 1, 1,
// ];
pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;

// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile_miller_circuit(id_to_sec: HashMap<String, u32>, t2: ark_bn254::G2Affine, t3: ark_bn254::G2Affine, q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine) -> (G2Affine, G2Affine) {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;


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
    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let bit = &ATE_LOOP_COUNT[j-1];
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
        let sec_out = id_map.get(&row.ID).unwrap().clone();
        if row.name == "T4Init" {
            tap_initT4(sec_key, sec_out,sec_in);
        } else if row.name == "PrePy" {
            // tap_precompute_P(sec_key, sec_out, sec_in);
        } else if row.name == "PrePx" {
            // tap_precompute_P(sec_key, sec_out, sec_in);
        } else if row.name == "HashC" {
            tap_hash_c(sec_key, sec_out, sec_in);
        } else if row.name == "HashC" {
            tap_hash_c2(sec_key, sec_out, sec_in);
        } else if row.name == "DD1" {
            tap_dense_dense_mul0(sec_key, sec_out, sec_in, true);
        } else if row.name == "DD2" {
            tap_dense_dense_mul1(sec_key, sec_out, sec_in, true);
        } else {
            panic!()
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

fn assign_ids_to_public_params(start_identifier: u32) -> HashMap<String, u32> {
    let pub_params = public_params();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    for i in 0..pub_params.len() {
        name_to_id.insert( pub_params[i].clone(), start_identifier + i as u32);
    }
    name_to_id
}


fn assign_ids_to_groth16_params(start_identifier: u32) -> HashMap<String, u32> {
    let g_params = groth16_params();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].clone(), start_identifier + i as u32);
    }
    name_to_id
}

fn assign_ids_to_premiller_params(start_identifier: u32) -> HashMap<String, u32> {
    let g_params = groth16_derivatives();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].clone(), start_identifier + i as u32);
    }
    name_to_id
}

fn assign_ids_to_miller_blocks(start_identifier: u32)-> (HashMap<String, u32>, String, String) {
    let g_params = miller_config_gen();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    let mut counter = 0;
    let mut last_f_block_id = String::new();
    let mut last_t4_block_id = String::new();
    for t in g_params {
        for r in t {
            name_to_id.insert(r.ID.clone(), start_identifier + counter as u32);
            counter += 1;
            if r.name.starts_with("DD") {
                last_f_block_id = r.ID;
            } else if r.name.starts_with("Dbl") {
                last_t4_block_id = r.ID;
            }
        }
    }
    (name_to_id, last_f_block_id, last_t4_block_id)
}

fn assign_ids_to_postmiller_params(start_identifier: u32) -> HashMap<String, u32> {
    let g_params = post_miller_params();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].clone(), start_identifier + i as u32);
    }
    name_to_id
}

pub(crate) fn assign_link_ids() -> (HashMap<String, u32>, String, String) {
    let mut all_ids: HashMap<String, u32> = HashMap::new();
    let pubp = assign_ids_to_public_params(0);
    let grothp = assign_ids_to_groth16_params(pubp.len() as u32);
    let premillp = assign_ids_to_premiller_params(grothp.len() as u32);
    let (millp, f_blk, t4_blk) = assign_ids_to_miller_blocks(premillp.len() as u32);
    let postmillp = assign_ids_to_postmiller_params(millp.len() as u32);
    let total_len = pubp.len() + grothp.len() + premillp.len() + millp.len() + postmillp.len();
    all_ids.extend(pubp);
    all_ids.extend(grothp);
    all_ids.extend(premillp);
    all_ids.extend(millp);
    all_ids.extend(postmillp);
    assert_eq!(total_len, all_ids.len());
    (all_ids, f_blk, t4_blk)
}

fn compile(q2: G2Affine, q3: G2Affine) {
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