use ark_bn254::g2::G2Affine;
use ark_ec::bn::BnConfig;
use std::collections::HashMap;

use super::config::miller_config_gen;
use super::config::{
    assign_link_ids, msm_config_gen, post_miller_config_gen,
    pre_miller_config_gen,
};
use super::msm::{bitcom_msm, tap_msm};
use super::taps;
use super::taps::{
    bitcom_add_eval_mul_for_fixed_Qs_with_frob,
    bitcom_frob_fp12, bitcom_hash_c, bitcom_hash_c2, bitcom_hash_p, bitcom_initT4,
    bitcom_point_add_with_frob, bitcom_precompute_Px, bitcom_precompute_Py,
   
    tap_add_eval_mul_for_fixed_Qs_with_frob, tap_frob_fp12, tap_hash_c2, tap_hash_p,
    tap_point_add_with_frob, tap_precompute_Px, tap_precompute_Py, Link,
};
use super::taps_mul::{bitcom_dense_dense_mul0, bitcom_dense_dense_mul1,bitcom_squaring,  bitcom_sparse_dense_mul, tap_sparse_dense_mul, tap_dense_dense_mul0, tap_dense_dense_mul1,tap_squaring};
use super::taps::{tap_hash_c, tap_initT4};
use super::wots::WOTSPubKey;


use crate::chunk::taps::{bitcom_add_eval_mul_for_fixed_Qs, bitcom_point_dbl, bitcom_point_ops, tap_add_eval_mul_for_fixed_Qs, tap_double_eval_mul_for_fixed_Qs, tap_point_dbl, tap_point_ops};
use crate::treepp::*;

// pub const ATE_LOOP_COUNT: &'static [i8] = &[
//     0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
//     0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
//     -1, 0, 0, 0, 1, 0, 1, 1,
// ];
pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;

// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile_miller_circuit(
    link_ids: &HashMap<u32, WOTSPubKey>,
    id_to_sec: HashMap<String, (u32, bool)>,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
) -> (HashMap<u32, Script>, G2Affine, G2Affine) {
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

    let mut scripts = HashMap::new();

    let mut nt2 = t2.clone();
    let mut nt3 = t3.clone();
    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        let bit = &ATE_LOOP_COUNT[j - 1];
        let blocks_of_a_loop = &blocks[itr];
        for block in blocks_of_a_loop {
            let sec_out = get_index(&block.link_id, id_to_sec.clone());
            let deps_indices = get_deps(&block.dependencies, id_to_sec.clone());
            println!(
                "{itr} ate {:?} ID {:?} deps {:?}",
                *bit, block.link_id, block.dependencies
            );
            println!(
                "{itr} {} ID {:?} deps {:?}",
                block.category, sec_out, deps_indices
            );
            let blk_name = block.category.clone();
            if blk_name == "Sqr" {
                let sc1 = tap_squaring();
                let sc2 = bitcom_squaring(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                            {sc2}
                            {sc1}
                    },
                );
            } else if blk_name == "DblAdd" {
                let sc1 = tap_point_ops(*bit);
                let sc2 = bitcom_point_ops(link_ids, sec_out, deps_indices, *bit);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "Dbl" {
                let sc1 = tap_point_dbl();
                let sc2 = bitcom_point_dbl(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "SD1" {
                let sc1 = tap_sparse_dense_mul(true);
                let sc2 = bitcom_sparse_dense_mul(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "SS1" {
                let (sc1, a, b) = tap_double_eval_mul_for_fixed_Qs(nt2, nt3);
                let sc2 =
                    taps::bitcom_double_eval_mul_for_fixed_Qs(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD1" {
                let sc1 = tap_dense_dense_mul0(false);
                let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "DD2" {
                let sc1 = tap_dense_dense_mul1(false);
                let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "DD3" {
                let sc1 = tap_dense_dense_mul0(false);
                let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "DD4" {
                let sc1 = tap_dense_dense_mul1(false);
                let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "SD2" {
                let sc1 = tap_sparse_dense_mul(false);
                let sc2 = bitcom_sparse_dense_mul(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "SS2" {
                let (sc1, a, b) = tap_add_eval_mul_for_fixed_Qs(nt2, nt3, q2, q3, *bit);
                let sc2 = bitcom_add_eval_mul_for_fixed_Qs(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
                nt2 = a;
                nt3 = b;
            } else if blk_name == "DD5" {
                let sc1 = tap_dense_dense_mul0(false);
                let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else if blk_name == "DD6" {
                let sc1 = tap_dense_dense_mul1(false);
                let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, deps_indices);
                scripts.insert(
                    sec_out.0,
                    script! {
                        {sc2}
                        {sc1}
                    },
                );
            } else {
                println!("unhandled {:?}", blk_name);
                panic!();
            }
        }
        itr += 1;
    }
    (scripts, nt2, nt3)
}

fn compile_pre_miller_circuit(
    link_ids: &HashMap<u32, WOTSPubKey>,
    id_map: HashMap<String, (u32, bool)>,
) -> HashMap<u32, Script> {
    let tables = pre_miller_config_gen();

    let mut scripts = HashMap::new();
    for row in tables {
        let sec_in = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| id_map.get(s).unwrap().clone())
            .collect();
        println!("row ID {:?}", row.link_id);
        let sec_out = id_map.get(&row.link_id).unwrap().clone();
        println!(" {} ID {:?} deps {:?}", row.category, sec_out, sec_in);

        if row.category == "T4Init" {
            let sc1 = tap_initT4();
            let sc2 = bitcom_initT4(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "PrePy" {
            let sc1 = tap_precompute_Py();
            let sc2 = bitcom_precompute_Py(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "PrePx" {
            let sc1 = tap_precompute_Px();
            let sc2 = bitcom_precompute_Px(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "HashC" {
            let sc1 = tap_hash_c();
            let sc2 = bitcom_hash_c(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "HashC2" {
            let sc1 = tap_hash_c2();
            let sc2 = bitcom_hash_c2(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD1" {
            let sc1 = tap_dense_dense_mul0(true);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD2" {
            let sc1 = tap_dense_dense_mul1(true);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "P3Hash" {
            let sc1 = tap_hash_p();
            let sc2 = bitcom_hash_p(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else {
            panic!()
        }
    }
    scripts
}

fn compile_post_miller_circuit(
    link_ids: &HashMap<u32, WOTSPubKey>,
    id_map: HashMap<String, (u32, bool)>,
    t2: ark_bn254::G2Affine,
    t3: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: ark_bn254::G2Affine,
    facc: String,
    tacc: String,
) -> HashMap<u32, Script> {
    let tables = post_miller_config_gen(facc, tacc);

    let mut nt2 = t2;
    let mut nt3 = t3;
    let mut scripts = HashMap::new();
    for row in tables {
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| id_map.get(s).unwrap().clone())
            .collect();
        println!("row ID {:?}", row.link_id);
        let sec_out = id_map.get(&row.link_id).unwrap().clone();
        if row.category == "Frob1" {
            let sc1 = tap_frob_fp12(1);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "Frob2" {
            let sc1 = tap_frob_fp12(2);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "Frob3" {
            let sc1 = tap_frob_fp12(3);
            let sc2 = bitcom_frob_fp12(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD1"{
            let check_identity_in_last_elem = row.link_id == "fin";
            let sc1 = tap_dense_dense_mul0(check_identity_in_last_elem);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD2" {
            let check_identity_in_last_elem = row.link_id == "fin";
            let sc1 = tap_dense_dense_mul1(check_identity_in_last_elem);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD3" {
            let sc1 = tap_dense_dense_mul0(false);
            let sc2 = bitcom_dense_dense_mul0(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "DD4" {
            let sc1 = tap_dense_dense_mul1(false);
            let sc2 = bitcom_dense_dense_mul1(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "Add1" {
            let sc1 = tap_point_add_with_frob(1);
            let sc2 = bitcom_point_add_with_frob(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "Add2" {
            let sc1 = tap_point_add_with_frob(-1);
            let sc2 = bitcom_point_add_with_frob(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "SD" {
            let sc1 = tap_sparse_dense_mul(false);
            let sc2 = bitcom_sparse_dense_mul(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else if row.category == "SS1" {
            let (sc1, a, b) = tap_add_eval_mul_for_fixed_Qs_with_frob(nt2, nt3, q2, q3, 1);
            let sc2 = bitcom_add_eval_mul_for_fixed_Qs_with_frob(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                    {sc2}
                    {sc1}
                },
            );
            nt2 = a;
            nt3 = b;
        } else if row.category == "SS2" {
            let (sc1, a, b) = tap_add_eval_mul_for_fixed_Qs_with_frob(nt2, nt3, q2, q3, -1);
            let sc2 = bitcom_add_eval_mul_for_fixed_Qs_with_frob(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                    {sc2}
                    {sc1}
                },
            );
            nt2 = a;
            nt3 = b;
        }
    }
    return scripts;
}

fn compile_msm_circuit(
    link_ids: &HashMap<u32, WOTSPubKey>,
    id_map: HashMap<String, (u32, bool)>,
    qs: Vec<ark_bn254::G1Affine>,
) -> HashMap<u32, Script> {
    let rows = msm_config_gen(String::from("k0,k1"));

    let mut msm_tap_index = 0;
    let mut scripts = HashMap::new();
    for row in rows {
        let sec_in: Vec<Link> = row
            .dependencies
            .split(",")
            .into_iter()
            .map(|s| id_map.get(s).unwrap().clone())
            .collect();
        println!("row ID {:?}", row.link_id);
        let sec_out = id_map.get(&row.link_id).unwrap().clone();

        if row.category == "MSM" {
            let sc1 = tap_msm(8, msm_tap_index, qs.clone());
            let sc2 = bitcom_msm(link_ids, sec_out, sec_in);
            scripts.insert(
                sec_out.0,
                script! {
                        {sc2}
                        {sc1}
                },
            );
        } else {
            panic!()
        }
        msm_tap_index += 1;
    }
    scripts
}

pub(crate) struct Vkey {
    pub(crate) q2: G2Affine,
    pub(crate) q3: G2Affine,
    pub(crate) p3vk: Vec<ark_bn254::G1Affine>,
}

pub(crate) fn compile(vk: Vkey, link_ids: &HashMap<u32, WOTSPubKey>) -> HashMap<u32, Script> {
    let (q2, q3) = (vk.q2, vk.q3);
    let (id_map, facc, tacc) = assign_link_ids();
    let mut scrs: HashMap<u32, Script> = HashMap::new();
    let scr = compile_msm_circuit(&link_ids, id_map.clone(), vk.p3vk);
    scrs.extend(scr);
    let scr = compile_pre_miller_circuit(&link_ids, id_map.clone());
    scrs.extend(scr);
    let (scr, t2, t3) = compile_miller_circuit(&link_ids, id_map.clone(), q2, q3);
    scrs.extend(scr);
    let scr = compile_post_miller_circuit(&link_ids, id_map, t2, t3, q2, q3, facc, tacc);
    scrs.extend(scr);
    scrs
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::chunk::{config::keygen, test_utils::read_scripts_from_file};

    use super::*;

    #[test]
    fn run_compile() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let vka = ark_bn254::G1Affine::rand(&mut prng);
        let vkb = ark_bn254::G1Affine::rand(&mut prng);
        let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";

        let link_ids = keygen(sec_key);
        let vk = Vkey {
            q2,
            q3,
            p3vk: vec![vka, vkb],
        };
        let bcs = compile(vk, &link_ids);
    }

    #[test]
    fn print_links() {
        let compiled = read_scripts_from_file("compile.json");
        let id = 101;
        let compiled_script = compiled.get(&id).unwrap();
        for c in compiled_script {
            println!("cs len {:?}", c.len());
        }
    }
}
