use std::collections::HashMap;
use std::ops::Neg;

use crate::chunk::acc::{groth16, hint_to_data, Pubs};
use crate::chunk::compile::{compile_ops, compile_taps, Vkey};
use crate::chunk::compile::{ NUM_PUBS, NUM_U160, NUM_U256};
use crate::chunk::hint_models::{ElemG1Point, EvalIns, G1PointExt};
use crate::chunk::segment::Segment;
use crate::chunk::taps::{Sig, SigData};
use crate::chunk::wots::WOTSPubKey;
use crate::groth16::g16::{
    N_VERIFIER_FQS, Assertions, PublicKeys, Signatures, N_TAPLEAVES, N_VERIFIER_HASHES,
};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::signatures::wots::{wots160, wots256};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;

use super::acc::{script_exec, get_assertions, get_intermediates, get_proof, get_pubs};


pub fn api_compile(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    assert!(vk.gamma_abc_g1.len() == NUM_PUBS + 1); // supports only 3 pubs

    let p1 = vk.alpha_g1;
    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );

    let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let mut p3vk = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    p3vk.reverse();
    let vky0 = p3vk.pop().unwrap();

    let taps = compile_ops(
        Vkey {
            q2,
            q3,
            p3vk,
            p1q1,
            vky0,
        },
    );
    // let taps: Vec<Script> = res.into_iter().map(|(_, f)| f).collect();
    taps
}

pub fn generate_tapscripts(
    inpubkeys: PublicKeys,
    ops_scripts_per_link: &[Script],
) -> Vec<Script> {
    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    for i in 0..NUM_PUBS {
        pubkeys.insert(i as u32, WOTSPubKey::P256(inpubkeys.0[i]));
    }
    let len = pubkeys.len();
    for i in 0..inpubkeys.1.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P256(inpubkeys.1[i]));
    }
    let len = pubkeys.len();
    for i in 0..inpubkeys.2.len() {
        pubkeys.insert((len + i) as u32, WOTSPubKey::P160(inpubkeys.2[i]));
    }

    let taps_per_link = compile_taps(
        Vkey {
            q2: ark_bn254::G2Affine::identity(),
            q3: ark_bn254::G2Affine::identity(),
            p3vk: (0..NUM_PUBS).map(|_| ElemG1Point::mock()).collect(),
            p1q1: ark_bn254::Fq12::ONE,
            vky0: ark_bn254::G1Affine::identity(),
        },
        pubkeys,
        ops_scripts_per_link.to_vec(),
    );
    assert_eq!(ops_scripts_per_link.len(), taps_per_link.len());
    taps_per_link
}

pub fn mock_pubkeys(mock_secret: &str) -> PublicKeys {

    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&format!("{mock_secret}{:04x}", i)));
    }
    let mut fq_arr = vec![];
    for i in 0..N_VERIFIER_FQS {
        let p256 = wots256::generate_public_key(&format!("{mock_secret}{:04x}", NUM_PUBS + i));
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let p160 = wots160::generate_public_key(&format!("{mock_secret}{:04x}", N_VERIFIER_FQS + NUM_PUBS + i));
        h_arr.push(p160);
    }
    let wotspubkey: PublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );
    wotspubkey
}

pub(crate) fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
    let mut msg_bytes = Vec::with_capacity(digits.len() / 2);

    for nibble_pair in digits.chunks(2) {
        let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
        msg_bytes.push(byte);
    }

    msg_bytes
}

pub fn generate_assertions(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Assertions {
    assert_eq!(scalars.len(), NUM_PUBS);

    let mut msm_scalar = scalars.clone();
    msm_scalar.reverse();
    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let mut p3 = vky0 * ark_bn254::Fr::ONE;
    for i in 0..NUM_PUBS {
        p3 = p3 + msm_gs[i] * msm_scalar[i];
    }
    let p3 = p3.into_affine();

    let (p2, p1, p4) = (proof.c, vk.alpha_g1, proof.a);
    let (q3, q2, q1, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );
    let f_fixed = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
    let (c, s) = compute_c_wi(f);
    let eval_ins: EvalIns = EvalIns {
        p2,
        p3,
        p4,
        q4,
        c,
        s,
        ks: msm_scalar.clone(),
        cinv: c.inverse().unwrap(),
    };

    let pubs: Pubs = Pubs {
        q2, 
        q3, 
        fixed_acc: f_fixed, 
        ks_vks: msm_gs, 
        vky0
    };

    let mut segments: Vec<Segment> = vec![];
    println!("generating assertions as prover");
    let success = groth16(false, &mut segments, eval_ins, pubs, &mut None);
    assert!(success);
    let proof_asserts = hint_to_data(segments.clone());
    proof_asserts
}

pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    inpubkeys: PublicKeys,
    disprove_scripts: &[Script; N_TAPLEAVES],
) -> Option<(usize, Script)> {
    let asserts = get_assertions(signed_asserts);
    let eval_ins = get_proof(&asserts);

    let intermediates = get_intermediates(&asserts);

    let mut segments: Vec<Segment> = vec![];
    println!("generating assertions to validate");
    let passed = groth16(false, &mut segments, eval_ins, get_pubs(vk), &mut Some(intermediates));
    if passed {
        println!("assertion passed, running full script execution now");
        let exec_result = script_exec(segments, signed_asserts, inpubkeys, disprove_scripts);
        assert!(exec_result.is_none());
        return None;
    }
    println!("assertion failed, return faulty script segments acc {:?}", segments.len());
    let exec_result = script_exec(segments, signed_asserts, inpubkeys, disprove_scripts);
    assert!(exec_result.is_some());
    return exec_result;
}

