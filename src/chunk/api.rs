use std::collections::HashMap;
use std::ops::Neg;

use crate::chunk::compile::{compile, Vkey};
use crate::chunk::config::keygen;
use crate::chunk::evaluate::{evaluate, extract_values_from_hints};
use crate::chunk::taps::Sig;
use crate::chunk::wots::WOTSPubKey;
use crate::groth16::g16::{WotsPublicKeys};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;

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
    let taps: Vec<Script> = res.into_iter().map(|(_, f)| f).collect();
    taps
}

pub fn generate_tapscripts(
    pubkeys: WotsPublicKeys,
    ops_scripts_per_link: Vec<Script>,
) -> Vec<Script> {
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

    let bitcom_scripts_per_link = compile(
        Vkey {
            q2: ark_bn254::G2Affine::identity(),
            q3: ark_bn254::G2Affine::identity(),
            p3vk: vec![],
            p1q1: ark_bn254::Fq12::ONE,
            vky0: ark_bn254::G1Affine::identity(),
        },
        &pubkeys,
        true,
    );
    let bitcom_scripts_per_link: Vec<Script> = bitcom_scripts_per_link.into_iter().map(|(_, f)| f).collect();
    bitcom_scripts_per_link
}


pub fn generate_assertions(proof: ark_groth16::Proof<Bn<ark_bn254::Config>>, scalars: Vec<ark_bn254::Fr>, vk: &ark_groth16::VerifyingKey<Bn254>) {
    assert_eq!(scalars.len(), 3);

    let sec = "b138982ce17ac813d505b5b40b665d404e9528e7"; // can be any random hex
    let mut sig = Sig {
        msk: Some(sec),
        cache: HashMap::new(),
    };
    let pk = keygen(sec);


    let msm_scalar = vec![scalars[2],scalars[1],scalars[0]];
    let msm_gs = vec![vk.gamma_abc_g1[3],vk.gamma_abc_g1[2],vk.gamma_abc_g1[1]]; // vk.vk_pubs[0]
    let p3 =  vk.gamma_abc_g1[0] * ark_bn254::Fr::ONE + vk.gamma_abc_g1[1] * scalars[0] + vk.gamma_abc_g1[2] * scalars[1] + vk.gamma_abc_g1[3] * scalars[2];
    let p3 = p3.into_affine();
    let ( p2, p1, p4) = ( proof.c, vk.alpha_g1, proof.a);
    let (q3, q2, q1, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );
    let f_fixed = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
   
    let (c, s) = compute_c_wi(f);


    let (aux, fault) = evaluate(
        &mut sig,
        &pk,
        p2,
        p3,
        p4,
        q2,
        q3,
        q4,
        c,
        s,
        f_fixed,
        msm_scalar.clone(),
        msm_gs.clone(),
        vk.gamma_abc_g1[0],
    );
    let assertions = extract_values_from_hints(aux);
    assert!(fault.is_none());
}
