use std::collections::HashMap;
use std::ops::Neg;

use crate::chunk::compile::{compile, Vkey};
use crate::chunk::config::{assign_link_ids, keygen, NUM_PUBS, NUM_U160, NUM_U256};
use crate::chunk::evaluate::{evaluate, extract_values_from_hints};
use crate::chunk::taps::Sig;
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
    ops_scripts_per_link: &[Script],
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

fn mock_pubkeys() -> WotsPublicKeys {
    let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";

    let pub0 = wots256::generate_public_key(&format!("{secret}{:04x}", 0));
    let pub1 = wots256::generate_public_key(&format!("{secret}{:04x}", 1));
    let pub2 = wots256::generate_public_key(&format!("{secret}{:04x}", 2));
    let mut fq_arr = vec![];
    for i in 0..N_VERIFIER_FQs {
        let p256 = wots256::generate_public_key(&format!("{secret}{:04x}", 3 + i));
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let p160 = wots160::generate_public_key(&format!("{secret}{:04x}", N_VERIFIER_FQs + 3 + i));
        h_arr.push(p160);
    }
    let wotspubkey: WotsPublicKeys = (
        (pub0, pub1, pub2),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );
    wotspubkey
}

fn generate_mock_pub_keys() -> HashMap<u32, WOTSPubKey> {
    let pubkeys = mock_pubkeys();
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
    // println!("pklen {:?}", pubkeys.len());

    //     let (ret, _,_)  = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
    //     for (k, (index, ty)) in ret {
    //         let r = pubkeys.get(&index).unwrap();
    //         let mut is_field = false;
    //         match r {
    //             WOTSPubKey::P160(_) => is_field = false,
    //             WOTSPubKey::P256(_) => is_field = true,
    //         }
    //         if is_field != ty {
    //             println!("problem here {}", index)
    //         } else {
    //             println!("good")
    //         }
    //     }

    pubkeys
}

fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
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
    assert_eq!(scalars.len(), 3);

    let sec = "b138982ce17ac813d505b5b40b665d404e9528e7"; // can be any random hex
    let mut sig = Sig {
        msk: Some(sec),
        cache: HashMap::new(),
    };
    let pk = generate_mock_pub_keys();

    let msm_scalar = vec![scalars[2], scalars[1], scalars[0]];
    let msm_gs = vec![vk.gamma_abc_g1[3], vk.gamma_abc_g1[2], vk.gamma_abc_g1[1]]; // vk.vk_pubs[0]
    let p3 = vk.gamma_abc_g1[0] * ark_bn254::Fr::ONE
        + vk.gamma_abc_g1[1] * scalars[0]
        + vk.gamma_abc_g1[2] * scalars[1]
        + vk.gamma_abc_g1[3] * scalars[2];
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
    let batch1: [[u8; 32]; 3] = batch1.try_into().unwrap();

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

fn get_script_from_sig256(signature: wots256::Signature) -> Vec<Script> {
    let mut sigs: Vec<Script> = vec![];

    for (sig, digit) in signature {
        sigs.push(script!({ sig.to_vec() }));
        sigs.push(script!({ digit }));
    }
    sigs
}

fn get_script_from_sig160(signature: wots160::Signature) -> Vec<Script> {
    let mut sigs: Vec<Script> = vec![];

    for (sig, digit) in signature {
        sigs.push(script!({ sig.to_vec() }));
        sigs.push(script!({ digit }));
    }
    sigs
}

pub fn validate_assertions(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: WotsSignatures,
    pubkeys: WotsPublicKeys,
    verifier_scripts: &[Script; N_TAPLEAVES],
) -> Option<(u32, Script, Script)> {
    assert_eq!(scalars.len(), 3);
    let mut sigcache: HashMap<u32, Vec<Script>> = HashMap::new();
    let (sa0, sa1, sa2) = (signed_asserts.0, signed_asserts.1, signed_asserts.2);
    sigcache.insert(0, get_script_from_sig256(sa0.0));
    sigcache.insert(1, get_script_from_sig256(sa0.1));
    sigcache.insert(2, get_script_from_sig256(sa0.2));

    for i in 0..N_VERIFIER_FQs {
        sigcache.insert((3 + i) as u32, get_script_from_sig256(sa1[i]));
    }

    for i in 0..N_VERIFIER_HASHES {
        sigcache.insert(
            (3 + i + N_VERIFIER_FQs) as u32,
            get_script_from_sig160(sa2[i]),
        );
    }

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

    let mut sig = Sig {
        msk: None,
        cache: sigcache,
    };

    let msm_scalar = vec![scalars[2], scalars[1], scalars[0]];
    let msm_gs = vec![vk.gamma_abc_g1[3], vk.gamma_abc_g1[2], vk.gamma_abc_g1[1]]; // vk.vk_pubs[0]
    let p3 = vk.gamma_abc_g1[0] * ark_bn254::Fr::ONE
        + vk.gamma_abc_g1[1] * scalars[0]
        + vk.gamma_abc_g1[2] * scalars[1]
        + vk.gamma_abc_g1[3] * scalars[2];
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

    let (_, fault) = evaluate(
        &mut sig,
        &pubkeys,
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
    Some((
        script_index as u32,
        hint_scr,
        verifier_scripts[script_index].clone(),
    ))
}

#[cfg(test)]
mod test {
    use super::generate_mock_pub_keys;

    #[test]
    fn test_it() {
        generate_mock_pub_keys();
    }
}
