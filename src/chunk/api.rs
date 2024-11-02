use std::collections::HashMap;
use std::ops::Neg;

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use crate::treepp::*;
use crate::chunk::compile::{compile, Vkey};
use crate::groth16::g16verifier::N_TAPLEAVES;


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
    let res = compile(Vkey { q2, q3, p3vk, p1q1, vky0 }, &HashMap::new(), false);
    let mut taps: Vec<Script> = res.into_iter().map(|(_,f)| f).collect();
    let failing_taps = script!{OP_FALSE}; // this disprove node always fails to run, so no one can execute it
    let buffer_failing_taps_count = N_TAPLEAVES - taps.len(); // adding failing taps because N_TAPLEAVES can not be changed atm
    let buffer_failing_taps: Vec<Script> = (0..buffer_failing_taps_count).into_iter().map(|_| failing_taps.clone()).collect();
    taps.extend_from_slice(&buffer_failing_taps);
    taps
}

