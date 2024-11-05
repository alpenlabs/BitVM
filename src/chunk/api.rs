use std::collections::HashMap;
use std::ops::Neg;

use crate::chunk::compile::{compile, Vkey};
use crate::chunk::config::{assign_link_ids, keygen, NUM_PUBS, NUM_U160, NUM_U256};
use crate::chunk::evaluate::{evaluate, extract_values_from_hints, EvalIns};
use crate::chunk::taps::{Sig, SigData};
use crate::chunk::wots::WOTSPubKey;
use crate::groth16::g16::{
    N_VERIFIER_FQs, ProofAssertions, WotsPublicKeys, WotsSignatures, N_TAPLEAVES, N_VERIFIER_HASHES,
};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::signatures::wots::{wots160, wots256};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;


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
    inpubkeys: WotsPublicKeys,
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
    assert_eq!(ops_scripts_per_link.len(), bitcom_scripts_per_link.len());
    let mut itr = 0;
    let mut taps_per_link = vec![];
    for (_, bcs) in bitcom_scripts_per_link {
        let scr = script!(
            {bcs}
            {ops_scripts_per_link[itr].clone()}
        );
        taps_per_link.push(scr);
        itr += 1;
    }
    taps_per_link
}

pub fn mock_pubkeys(mock_secret: &str) -> WotsPublicKeys {

    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&format!("{mock_secret}{:04x}", i)));
    }
    let mut fq_arr = vec![];
    for i in 0..N_VERIFIER_FQs {
        let p256 = wots256::generate_public_key(&format!("{mock_secret}{:04x}", NUM_PUBS + i));
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let p160 = wots160::generate_public_key(&format!("{mock_secret}{:04x}", N_VERIFIER_FQs + NUM_PUBS + i));
        h_arr.push(p160);
    }
    let wotspubkey: WotsPublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );
    wotspubkey
}

fn generate_mock_pub_keys(mock_secret: &str) -> HashMap<u32, WOTSPubKey> {
    let inpubkeys = mock_pubkeys(mock_secret);
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
    pubkeys
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
) -> ProofAssertions {
    assert_eq!(scalars.len(), NUM_PUBS);

    // you do not need any secret to generate proof assertions,
    // the use of "secret" below is merely an artifact of legacy code and doesn't serve any purpse
    // will remove the need for passing it.
    pub const MOCK_KEY: &str = "b138982ce17ac813d505a5b40b665d404e9528e7";
    let random_secret = MOCK_KEY;
    let mut sig = Sig {
        msk: Some(random_secret),
        cache: HashMap::new(),
    };


    let pk = generate_mock_pub_keys(MOCK_KEY);

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
    let eval_ins: EvalIns = EvalIns { p2, p3, p4, q4, c, s, ks: msm_scalar.clone() };

    let (aux, fault) = evaluate(
        &mut sig,
        &pk,
        Some(eval_ins),
        q2,
        q3,
        f_fixed,
        msm_gs.clone(),
        vky0,
    );
    let assertions = extract_values_from_hints(aux);
    println!(
        "{} and {}",
        assertions.len(),
        NUM_PUBS + NUM_U160 + NUM_U256
    );
    let mut batch1 = vec![];
    for i in 0..NUM_PUBS {
        let val = assertions.get(&(i as u32)).unwrap();
        let bal: [u8; 32] = nib_to_byte_array(val).try_into().unwrap();
        batch1.push(bal);
    }
    let batch1: [[u8; 32]; NUM_PUBS] = batch1.try_into().unwrap();

    let len = batch1.len();
    let mut batch2 = vec![];
    for i in 0..NUM_U256 {
        let val = assertions.get(&((i + len) as u32)).unwrap();
        let bal: [u8; 32] = nib_to_byte_array(val).try_into().unwrap();
        batch2.push(bal);
    }
    let batch2: [[u8; 32]; N_VERIFIER_FQs] = batch2.try_into().unwrap();

    let len = batch1.len() + batch2.len();
    let mut batch3 = vec![];
    for i in 0..NUM_U160 {
        let val = assertions.get(&((i + len) as u32)).unwrap();
        let bal: [u8; 32] = nib_to_byte_array(val).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        batch3.push(bal);
    }
    let batch3: [[u8; 20]; N_VERIFIER_HASHES] = batch3.try_into().unwrap();

    (batch1, batch2, batch3)
}

pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: WotsSignatures,
    inpubkeys: WotsPublicKeys,
) -> Option<(usize, Script)> {
    let mut sigcache: HashMap<u32, SigData> = HashMap::new();

    assert_eq!(signed_asserts.0.len(), NUM_PUBS);

    for i in 0..NUM_PUBS {
        sigcache.insert(i as u32, SigData::Sig256(signed_asserts.0[i]));
    }

    for i in 0..N_VERIFIER_FQs {
        sigcache.insert((NUM_PUBS + i) as u32, SigData::Sig256(signed_asserts.1[i]));
    }

    for i in 0..N_VERIFIER_HASHES {
        sigcache.insert((NUM_PUBS + N_VERIFIER_FQs + i) as u32, SigData::Sig160(signed_asserts.2[i]));
    }

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

    let mut sig = Sig {
        msk: None,
        cache: sigcache,
    };

    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );
    let f_fixed = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;

    let (_, fault) = evaluate(
        &mut sig,
        &pubkeys,
        None,
        q2,
        q3,
        f_fixed,
        msm_gs.clone(),
        vky0,
    );
    if fault.is_none() {
        return None;
    }
    let (fault_index, hint_scr) = fault.unwrap();
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
    let mut script_index = 0; // tapleaf index
    for arr_index in 0..bitcom_scripts_per_link.len() {
        let (k, _) = bitcom_scripts_per_link[arr_index];
        if k == fault_index {
            script_index = arr_index;
        }
    }
    Some((script_index, hint_scr))
}

