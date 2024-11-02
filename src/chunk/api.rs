use std::collections::HashMap;
use std::ops::Neg;

use crate::chunk::compile::{compile, Vkey};
use crate::chunk::wots::WOTSPubKey;
use crate::groth16::g16::{WotsPublicKeys, N_TAPLEAVES};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};

pub fn api_compile(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    assert!(vk.gamma_abc_g1.len() == 4); // supports only 3 pubs

    let p1 = vk.alpha_g1;
    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );

    let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let p3vk = vec![vk.gamma_abc_g1[3], vk.gamma_abc_g1[2], vk.gamma_abc_g1[1]];
    let vky0 = vk.gamma_abc_g1[0];
    let res = compile(
        Vkey {
            q2,
            q3,
            p3vk,
            p1q1,
            vky0,
        },
        &HashMap::new(),
        false,
    );
    let mut taps: Vec<Script> = res.into_iter().map(|(_, f)| f).collect();
    let failing_taps = script! {OP_FALSE}; // this disprove node always fails to run, so no one can execute it
    let buffer_failing_taps_count = N_TAPLEAVES - taps.len(); // adding failing taps because N_TAPLEAVES can not be changed atm
    let buffer_failing_taps: Vec<Script> = (0..buffer_failing_taps_count)
        .into_iter()
        .map(|_| failing_taps.clone())
        .collect();
    taps.extend_from_slice(&buffer_failing_taps);
    taps
}


pub fn generate_tapscripts(vk: &ark_groth16::VerifyingKey<Bn254>, pubkeys: WotsPublicKeys, ops_scripts_per_link: Vec<Script>) -> Vec<Script> {

    let (p0, p1, p2) = pubkeys.0;
    let fq_arr = pubkeys.1;
    let hash_arr = pubkeys.2;

    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    pubkeys.insert(0, WOTSPubKey::P256(p0));
    pubkeys.insert(1, WOTSPubKey::P256(p1));
    pubkeys.insert(2, WOTSPubKey::P256(p2));
    let len = pubkeys.len();
    for i in 0..fq_arr.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P256(fq_arr[i]));
    }
    let len = pubkeys.len();
    for i in 0..hash_arr.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P160(hash_arr[i]));
    }

    assert!(vk.gamma_abc_g1.len() == 4); // supports only 3 pubs

    let p1 = vk.alpha_g1;
    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );

    let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let p3vk = vec![vk.gamma_abc_g1[3], vk.gamma_abc_g1[2], vk.gamma_abc_g1[1]];
    let vky0 = vk.gamma_abc_g1[0];

    let bitcom_scripts_per_link = compile(
        Vkey {
            q2,
            q3,
            p3vk,
            p1q1,
            vky0,
        },
        &pubkeys,
        true,
    );
    let mut bitcom_scripts_per_link: Vec<Script> = bitcom_scripts_per_link.into_iter().map(|(_, f)| f).collect();
    let failing_taps = script! {OP_FALSE}; // this disprove node always fails to run, so no one can execute it
    let buffer_failing_taps_count = N_TAPLEAVES - bitcom_scripts_per_link.len(); // adding failing taps because N_TAPLEAVES can not be changed atm
    let buffer_failing_taps: Vec<Script> = (0..buffer_failing_taps_count)
        .into_iter()
        .map(|_| failing_taps.clone())
        .collect();
    bitcom_scripts_per_link.extend_from_slice(&buffer_failing_taps);


    let mut taps: Vec<Script> = vec![];
    assert_eq!(ops_scripts_per_link.len(), bitcom_scripts_per_link.len());
    for i in 0..bitcom_scripts_per_link.len() {
        let sc = script!{
            {bitcom_scripts_per_link[i].clone()}
            {ops_scripts_per_link[i].clone()}
        };
        //let index = bitcom_scripts_per_link[i].0;
        //assert_eq!(index, bitcom_scripts_per_link[i].0);
        taps.push(sc);
    }
    taps
}


// fn generate_assertions(proof: ark_groth16::Groth16<Bn254>, scalars: Vec<ark_bn254::Fr>, ) {
//     let msm_scalar = vec![proof.scalars[2],proof.scalars[1],proof.scalars[0]];
//     let msm_gs = vec![vk.vk_pubs[3],vk.vk_pubs[2],vk.vk_pubs[1]]; // vk.vk_pubs[0]
//     let p3 =  vk.vk_pubs[0] * ark_bn254::Fr::ONE + vk.vk_pubs[1] * proof.scalars[0] + vk.vk_pubs[2] * proof.scalars[1] + vk.vk_pubs[3] * proof.scalars[2];

//     let p3 = p3.into_affine();

// }