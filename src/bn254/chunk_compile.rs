
use std::collections::{HashMap};
use ark_bn254::g2::G2Affine;
use ark_ec::bn::BnConfig;

use crate::bn254::chunk_config::miller_config_gen;
use crate::bn254::chunk_taps::{bitcom_add_eval_mul_for_fixed_Qs_with_frob, bitcom_dense_dense_mul0, bitcom_dense_dense_mul1, bitcom_frob_fp12, bitcom_hash_c, bitcom_hash_c2, bitcom_initT4, bitcom_point_add_with_frob, bitcom_precompute_Px, bitcom_precompute_Py, bitcom_sparse_dense_mul, tap_add_eval_mul_for_fixed_Qs, tap_add_eval_mul_for_fixed_Qs_with_frob, tap_frob_fp12, tap_hash_c2, tap_point_add_with_frob, tap_precompute_Px, tap_precompute_Py, tap_sparse_dense_mul};
use crate::bn254::{ chunk_taps};
use crate::signatures::winternitz_compact::checksig_verify_fq;
use super::chunk_config::{groth16_derivatives, groth16_params, post_miller_config_gen, post_miller_params, pre_miller_config_gen, public_params};
use super::{chunk_taps::{tap_dense_dense_mul0, tap_dense_dense_mul1, tap_hash_c, tap_initT4}};

use crate::{
    treepp::*,
};



// pub const ATE_LOOP_COUNT: &'static [i8] = &[
//     0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
//     0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
//     -1, 0, 0, 0, 1, 0, 1, 1,
// ];
pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;

// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile_miller_circuit(link_ids: &HashMap<u32, Script>, id_to_sec: HashMap<String, u32>,  q2: ark_bn254::G2Affine, q3: ark_bn254::G2Affine) -> (Vec<Script>, G2Affine, G2Affine) {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;
    let (t2, t3) = (q2.clone(), q3.clone());

    let blocks = miller_config_gen();

    let mut itr = 0;
    // println!("max id {:?}", max_id);


    fn get_index(blk_name: &str, id_to_sec: HashMap<String, u32>)-> u32 {
        id_to_sec.get(blk_name).unwrap().clone()
    }

    fn get_deps(deps: &str, id_to_sec: HashMap<String, u32>) -> Vec<u32> {
        let splits: Vec<u32>= deps.split(",").into_iter().map(|s| get_index(s, id_to_sec.clone())).collect();
        splits
    }

    let mut scripts: Vec<Script> = vec![];

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
                let sc1 = chunk_taps::tap_squaring();
                let sc2 = chunk_taps::bitcom_squaring(link_ids, self_index, deps_indices);
                scripts.push(
                    script!{
                        {sc2}
                        {sc1}
                });
            } else if blk_name == "DblAdd" {
                let sc1 = chunk_taps::tap_point_ops(*bit);
                let sc2 = chunk_taps::bitcom_point_ops(link_ids, self_index, deps_indices, *bit);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "Dbl" {
                let sc1 = chunk_taps::tap_point_dbl();
                let sc2 = chunk_taps::bitcom_point_dbl(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "SD1" {
                let sc1 = chunk_taps::tap_sparse_dense_mul(true);
                let sc2 = chunk_taps::bitcom_sparse_dense_mul(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "SS1" {
                let (sc1, a, b) = chunk_taps::tap_double_eval_mul_for_fixed_Qs(nt2, nt3);
                let sc2 = chunk_taps::bitcom_double_eval_mul_for_fixed_Qs(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD1" {
                let sc1 = chunk_taps::tap_dense_dense_mul0(false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul0(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "DD2" {
                let sc1 = chunk_taps::tap_dense_dense_mul1(false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul1(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "DD3" {
                let sc1 = chunk_taps::tap_dense_dense_mul0(false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul0(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "DD4" {
                let sc1 = chunk_taps::tap_dense_dense_mul1(false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul1(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "SD2" {
               let sc1 = chunk_taps::tap_sparse_dense_mul( false);
               let sc2 = chunk_taps::bitcom_sparse_dense_mul(link_ids, self_index, deps_indices);
               scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "SS2" {
                let (sc1, a, b) = chunk_taps::tap_add_eval_mul_for_fixed_Qs( nt2, nt3, q2, q3, *bit);
                let sc2 = chunk_taps::bitcom_add_eval_mul_for_fixed_Qs(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD5" {
                let sc1 = chunk_taps::tap_dense_dense_mul0( false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul0(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else if blk_name == "DD6" {
                let sc1 = chunk_taps::tap_dense_dense_mul1(false);
                let sc2 = chunk_taps::bitcom_dense_dense_mul1(link_ids, self_index, deps_indices);
                scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            } else {
                println!("unhandled {:?}", blk_name);
                panic!();
            }
        }
        itr += 1;
    }   
    (scripts, nt2, nt3)

}


fn compile_pre_miller_circuit(link_ids: &HashMap<u32, Script>, id_map: HashMap<String, u32>) -> Vec<Script>   {
    let tables = pre_miller_config_gen();

    let mut scripts = vec![];
    for row in tables {
        let sec_in = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.ID);
        let sec_out = id_map.get(&row.ID).unwrap().clone();
        if row.name == "T4Init" {
            let sc1 = tap_initT4();
            let sc2 = bitcom_initT4(link_ids, sec_out,sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "PrePy" {
            let sc1 = tap_precompute_Py();
            let sc2 = bitcom_precompute_Py(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "PrePx" {
            let sc1 = tap_precompute_Px();
            let sc2 = bitcom_precompute_Px(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "HashC" {
            let sc1 = tap_hash_c();
            let sc2 = bitcom_hash_c(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "HashC2" {
            let sc1 = tap_hash_c2();
            let sc2 = bitcom_hash_c2(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD1" {
            let sc1 = tap_dense_dense_mul0(true);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD2" {
            let sc1 = tap_dense_dense_mul1(true);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else {
            panic!()
        }
    }
    scripts

}

fn compile_post_miller_circuit(link_ids: &HashMap<u32, Script>, id_map: HashMap<String, u32>, t2: ark_bn254::G2Affine,  t3: ark_bn254::G2Affine,  q2: ark_bn254::G2Affine,  q3: ark_bn254::G2Affine, facc: String, tacc: String ) -> (HashMap<String, u32>, Vec<Script>) {
    let tables = post_miller_config_gen(facc,tacc);

    let mut nt2 = t2;
    let mut nt3 = t3;
    let mut scripts = vec![];
    for row in tables {
        let sec_in: Vec<u32> = row.Deps.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        println!("row ID {:?}", row.ID);
        let sec_out: Vec<u32> = row.ID.split(",").into_iter().map(|s| id_map.get(s).unwrap().clone()).collect();
        if row.name == "Frob1" {
            let sc1 = tap_frob_fp12(1);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out[0],sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "Frob2" {
            let sc1 = tap_frob_fp12(2);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out[0],sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "Frob3" {
            let sc1 = tap_frob_fp12( 3);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out[0],sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD1" {
            let sc1 = tap_dense_dense_mul0(false);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD2" {
            let sc1 = tap_dense_dense_mul1( false);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD3" {
            let sc1 = tap_dense_dense_mul0(true);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "DD4" {
            let sc1 = tap_dense_dense_mul1( true);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "Add1" {
            let sc1 = tap_point_add_with_frob(1);
            let sc2 = bitcom_point_add_with_frob(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "Add2" {
            let sc1 = tap_point_add_with_frob(-1);
            let sc2 = bitcom_point_add_with_frob(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "SD" {
            let sc1 = tap_sparse_dense_mul(false);
            let sc2 = bitcom_sparse_dense_mul(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
            });
        } else if row.name == "SS1" {
            let (sc1, a, b) = tap_add_eval_mul_for_fixed_Qs_with_frob(nt2, nt3, q2, q3, 1);
            let sc2 = bitcom_add_eval_mul_for_fixed_Qs_with_frob(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            nt2=a;
            nt3=b;
        }  else if row.name == "SS2" {
            let (sc1, a, b) = tap_add_eval_mul_for_fixed_Qs_with_frob( nt2, nt3, q2, q3, -1);
            let sc2 = bitcom_add_eval_mul_for_fixed_Qs_with_frob(link_ids, sec_out[0], sec_in);
            scripts.push(
                script!{
                    {sc2}
                    {sc1}
                });
            nt2=a;
            nt3=b;
        }
    }
    return (id_map, scripts);
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
    let mut total_len = 0;
    let pubp = assign_ids_to_public_params(0);
    total_len += pubp.len();
    let grothp = assign_ids_to_groth16_params(total_len as u32);
    total_len += grothp.len();
    let premillp = assign_ids_to_premiller_params(total_len as u32);
    total_len += premillp.len();
    let (millp, f_blk, t4_blk) = assign_ids_to_miller_blocks(total_len as u32);
    total_len += millp.len();
    let postmillp = assign_ids_to_postmiller_params(total_len as u32);
    total_len += postmillp.len();

    all_ids.extend(pubp);
    all_ids.extend(grothp);
    all_ids.extend(premillp);
    all_ids.extend(millp);
    all_ids.extend(postmillp);
    assert_eq!(total_len, all_ids.len());
    (all_ids, f_blk, t4_blk)
}

pub(crate) fn keygen(msk: &str) -> HashMap<u32, Script> {
    // given master secret key and number of links, generate pub keys
    let (links, _,_) = assign_link_ids();
    let mut scripts = HashMap::new();
    for link_id in 0..links.len() {
        let s = checksig_verify_fq(&format!("{}{:04X}", msk, link_id));
        scripts.insert(link_id as u32, s);
    }
    scripts
}

struct Vkey {
    q2: G2Affine, 
    q3: G2Affine
}

fn compile(vk: Vkey, link_ids: &HashMap<u32, Script>) -> Vec<Script> {
    let (q2, q3) = (vk.q2, vk.q3);
    let mut scrs: Vec<Script> = vec![];
    let (id_map, facc, tacc) = assign_link_ids();
    let scr = compile_pre_miller_circuit(&link_ids, id_map.clone());
    scrs.extend(scr);
    let (scr, t2, t3) = compile_miller_circuit(&link_ids, id_map.clone(), q2, q3);
    scrs.extend(scr);
    let (_, scr) = compile_post_miller_circuit(&link_ids, id_map, t2, t3, q2, q3, facc, tacc);
    scrs.extend(scr);
    scrs
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn run_compile() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

        let link_ids = keygen(sec_key);
        let vk = Vkey { q2, q3};
        let bcs = compile(vk, &link_ids);

       // let scrs= compile(sec_key, );
      //  let _bcs_to_presign: Vec<bitcoin::ScriptBuf> = scrs.iter().map(|f| f.1.clone().compile()).collect();
        // for pubs in pubss {
        //     println!("DELIM");
        //     println!("{:?}", pubs);
        // }
    }

    #[test]
    fn test_link() {
        let (hashmap, facc, tacc) = assign_link_ids();
        let mut key_value_vec: Vec<(&String, &u32)> = hashmap.iter().collect();

        // Sort the vector by value
        key_value_vec.sort_by(|a, b| a.1.cmp(b.1));
    
        // Iterate over the sorted vector and print the key-value pairs
        for (key, value) in key_value_vec {
            println!("{}: {}", key, value);
        }
    }
}