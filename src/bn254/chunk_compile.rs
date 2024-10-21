
use std::collections::{HashMap, HashSet};
use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::{ chunk_taps};
use crate::treepp::*;

use super::chunk_config::{groth16_derivatives, groth16_params, post_miller_params, pre_miller_config_gen, public_params};
use super::{chunk_config::TableRow, chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4, tap_precompute_P}};


// given a groth16 verification key, generate all of the tapscripts in compile mode
fn miller(id_to_sec: HashMap<&str, u32>) {
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


    fn get_index(blk_name: &str, id_to_sec: HashMap<&str, u32>)-> u32 {
        let prekey = id_to_sec.get(blk_name);
        if prekey.is_some() {
            return prekey.unwrap().clone();
        } else if blk_name.starts_with("S") {
            return id_to_sec.len() as u32 + blk_name[1..].parse::<u32>().ok().unwrap();
        } else {
            println!("unknown blk_name {:?}", blk_name);
            panic!();
        }

    }
    fn get_deps(deps: &str, id_to_sec: HashMap<&str, u32>) -> Vec<u32> {
        let splits: Vec<u32>= deps.split(",").into_iter().map(|s| get_index(s, id_to_sec.clone())).collect();
        splits
    }

    fn get_script(blk_name: &str, sec_key_for_bitcomms: &str, self_index: u32, deps_indices: Vec<u32>, ate_bit: i8) -> Script {
        if blk_name == "Sqr" {
            chunk_taps::tap_squaring(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "DblAdd" {
            chunk_taps::tap_point_ops(sec_key_for_bitcomms, self_index, deps_indices, ate_bit);
        } else if blk_name == "Dbl" {
            chunk_taps::tap_point_dbl(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "SD1" {
            chunk_taps::tap_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, true);
        } else if blk_name == "SS1" {
            // chunk_taps::tap_double_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices);
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
            //chunk_taps::tap_add_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "DD5" {
            chunk_taps::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "DD6" {
            chunk_taps::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else {
            println!("unhandled {:?}", blk_name);
            panic!();
        }
        script!{}
    }

    println!("id_to_sec {:?}", id_to_sec);

    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        let blocks_of_a_loop = &blocks[itr];
        for block in blocks_of_a_loop {
            let self_index = get_index(&block.ID, id_to_sec.clone());
            let deps_indices = get_deps(&block.Deps, id_to_sec.clone());
            println!("{itr} ate {:?} ID {:?} deps {:?}", *bit, block.ID, block.Deps);
            println!("{itr} {} ID {:?} deps {:?}", block.name, self_index, deps_indices);
            let tap = get_script(&block.name, sec_key_for_bitcomms, self_index, deps_indices, *bit);
          
        }
        // squaring
        // point_ops
        // sparse_dense
        // sparse_sparse
        // dense_dense
        itr += 1;
    }   

}


fn compile_pre_miller_circuit() -> HashMap<String, u32> {
    let tables = pre_miller_config_gen();
    let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

    let mut id_to_sec: HashMap<String, u32> = HashMap::new();
    let groth_elems = groth16_params();
    for i in 0..groth_elems.len() {
        id_to_sec.insert(groth_elems[i].clone(), i as u32);
    }
    let groth_derives = groth16_derivatives();
    for i in 0..groth_derives.len() {
        id_to_sec.insert(groth_derives[i].clone(), (i as u32)+(groth_elems.len() as u32));
    }
    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_to_sec.get(s).unwrap().clone()).collect();
        let sec_out: Vec<u32> = row.ID.split(",").into_iter().map(|s| id_to_sec.get(s).unwrap().clone()).collect();
        if row.name == "T4Init" {
            tap_initT4(sec_key, sec_out[0],sec_in);
        } else if row.name == "PreP" {
            tap_precompute_P(sec_key, sec_out, sec_in);
        } else if row.name == "HashC" {
            tap_hash_c(sec_key, sec_out[0], sec_in);
        } else if row.name == "DD1" {
            tap_dense_dense_mul0(sec_key, sec_out[0], sec_in, true);
        } else if row.name == "DD2" {
            tap_dense_dense_mul1(sec_key, sec_out[0], sec_in, true);
        }
    }
    return id_to_sec;
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

fn assign_link_ids() -> (HashMap<String, u32>, String, String) {
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

#[cfg(test)]
mod test {
    use super::*;
    

}