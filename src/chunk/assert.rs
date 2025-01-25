use std::{collections::HashMap, ops::Neg};

use ark_bn254::{Bn254};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use bitcoin_script::script;
use num_bigint::BigUint;

use crate::{bn254::utils::Hint, chunk::{primitves::{tup_to_scr, HashBytes, Sig, SigData}, segment::*, taps_point_eval::get_hint_for_add_with_frob}, execute_script, groth16::g16::{Assertions, PublicKeys, Signatures, N_TAPLEAVES, N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS}, treepp};


use super::{api::nib_to_byte_array, compile::{ATE_LOOP_COUNT, NUM_PUBS, NUM_U160, NUM_U256}, element::*, primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles},  wots::WOTSPubKey};



#[derive(Debug)]
pub struct Pubs {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq12,
    pub ks_vks: Vec<ark_bn254::G1Affine>,
    pub vky0: ark_bn254::G1Affine,
}


fn compare(hint_out: &Element, claimed_assertions: &mut Option<Intermediates>) -> Option<bool> {
    if claimed_assertions.is_none() {
        return None;
    }
    
    fn get_hash(claimed_assertions: &mut Option<Intermediates>) -> HashBytes {
        if let Some(claimed_assertions) = claimed_assertions {
            claimed_assertions.pop().unwrap()
        } else {
            panic!()
        }
    }
    assert!(!hint_out.output_is_field_element());
    let matches = get_hash(claimed_assertions) == hint_out.hashed_output();
    return Some(matches) 
}

pub(crate) fn groth16(
    is_compile_mode: bool,
    all_output_hints: &mut Vec<Segment>,
    eval_ins: InputProofRaw,
    pubs: Pubs,
    claimed_assertions: &mut Option<Intermediates>,
) -> bool {
    macro_rules! push_compare_or_return {
        ($seg:ident) => {{
            all_output_hints.push($seg.clone());
            if $seg.is_validation {
                if let Element::U256(felem) = $seg.result.0 {
                    if felem != ark_ff::BigInt::<4>::one() {
                        return false;
                    }
                } else {
                    panic!();
                }
            } else {
                let matches = compare(&$seg.result.0, claimed_assertions);
                if matches.is_some() && matches.unwrap() == false {
                    return false;
                }
            }
        }};
    }
    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;

    let pub_scalars: Vec<Segment> = eval_ins.ks.iter().enumerate().map(|(idx, f)| Segment {
        is_validation: false,
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::ScalarElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
    }).collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = vec![
        eval_ins.p4[1], eval_ins.p4[0], eval_ins.p2[1], eval_ins.p2[0]
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3]);

    let gc: Vec<Segment> = eval_ins.c.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&gc);

    let gs: Vec<Segment> = eval_ins.s.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&gs);

    let temp_q4: Vec<Segment> = vec![
        eval_ins.q4[0], eval_ins.q4[1], eval_ins.q4[2], eval_ins.q4[3]
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic
    }).collect();
    all_output_hints.extend_from_slice(&temp_q4);

    let (q4xc0, q4xc1, q4yc0, q4yc1) = (&temp_q4[0], &temp_q4[1], &temp_q4[2], &temp_q4[3]);

    let verify_gp4 = wrap_verify_g1_is_on_curve(is_compile_mode, all_output_hints.len(), &gp4y, &gp4x);
    push_compare_or_return!(verify_gp4);
    let p4 = wrap_hints_precompute_p(is_compile_mode, all_output_hints.len(), &gp4y, &gp4x);
    push_compare_or_return!(p4);

    let verify_gp2 = wrap_verify_g1_is_on_curve(is_compile_mode, all_output_hints.len(), &gp2y, &gp2x);
    push_compare_or_return!(verify_gp2);
    let p2 = wrap_hints_precompute_p(is_compile_mode, all_output_hints.len(), &gp2y, &gp2x);
    push_compare_or_return!(p2);

    let msms = wrap_hint_msm(is_compile_mode, all_output_hints.len(), pub_scalars.clone(), vky.clone());
    for msm in &msms {
        push_compare_or_return!(msm);
    }

    let p_vk0 = wrap_hint_hash_p(is_compile_mode, all_output_hints.len(), &msms[msms.len()-1], vky0);
    push_compare_or_return!(p_vk0);

    let valid_p_vky0 = wrap_verify_g1_hash_is_on_curve(is_compile_mode, all_output_hints.len(), &p_vk0);
    push_compare_or_return!(valid_p_vky0);
    let p3 = wrap_hints_precompute_p_from_hash(is_compile_mode, all_output_hints.len(), &p_vk0);
    push_compare_or_return!(p3);

    let valid_gc = wrap_verify_fq12_is_on_field(is_compile_mode, all_output_hints.len(), gc.clone());
    push_compare_or_return!(valid_gc);
    let c = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gc);
    push_compare_or_return!(c);

    let valid_gs = wrap_verify_fq12_is_on_field(is_compile_mode, all_output_hints.len(), gs.clone());
    push_compare_or_return!(valid_gs);
    let s = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gs);
    push_compare_or_return!(s);

    let dmul0 = wrap_inv0(is_compile_mode, all_output_hints.len(), &c);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_inv1(is_compile_mode, all_output_hints.len(), &dmul0);
    push_compare_or_return!(dmul1);

    let gcinv = wrap_inv2(is_compile_mode, all_output_hints.len(), &dmul1, &c);
    push_compare_or_return!(gcinv);

    let valid_t4 = wrap_verify_g2_is_on_curve(is_compile_mode, all_output_hints.len(), &q4yc1, &q4yc0, &q4xc1, &q4xc0);
    push_compare_or_return!(valid_t4);

    let mut t4 = wrap_hint_init_t4(is_compile_mode, all_output_hints.len(), &q4yc1, &q4yc0, &q4xc1, &q4xc0);
    push_compare_or_return!(t4);

    let (mut t2, mut t3) = (pubs.q2, pubs.q3);
    let mut f_acc = gcinv.clone();

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        if !is_compile_mode {
            println!("itr {:?}", j);
        }
        let ate = ATE_LOOP_COUNT[j - 1];
        let sq = wrap_hint_squaring(is_compile_mode, all_output_hints.len(), &f_acc);
        push_compare_or_return!(sq);
        f_acc = sq;

        if ate == 0 {
            let dbl = wrap_hint_point_dbl(is_compile_mode, all_output_hints.len(), &t4, &p4);
            push_compare_or_return!(dbl);
            t4 = dbl;
        } else {
            let dbladd = wrap_hint_point_ops(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4, ate);
            push_compare_or_return!(dbladd);
            t4 = dbladd;
        }

        let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, true);
        push_compare_or_return!(sdmul);
        f_acc = sdmul;

        let leval = wrap_hint_multiply_point_evals_on_tangent_for_fixed_g2(is_compile_mode, all_output_hints.len(), &p3, &p2,  t2, t3);
        push_compare_or_return!(leval);
        (t2, t3) = ((t2 + t2).into_affine(), (t3 + t3).into_affine());


        let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;

        if ate == 0 {
            continue;
        }

        let c_or_cinv = if ate == -1 { c.clone() } else { gcinv.clone() };

        let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &c_or_cinv);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &c_or_cinv, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;

        let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
        push_compare_or_return!(sdmul);
        f_acc = sdmul;

        let leval = wrap_hint_multiply_point_evals_on_chord_for_fixed_g2(is_compile_mode, all_output_hints.len(), &p3, &p2,  t2, t3, pubs.q2, pubs.q3, ate);
        push_compare_or_return!(leval);
        if ate == 1 {
            (t2, t3) = ((t2 + pubs.q2).into_affine(), (t3 + pubs.q3).into_affine());
        } else {
            (t2, t3) = ((t2 - pubs.q2).into_affine(), (t3 - pubs.q3).into_affine());
        }

        let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
        push_compare_or_return!(dmul0);

        let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
        push_compare_or_return!(dmul1);
        f_acc = dmul1;
    }

    let cp = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 1);
    push_compare_or_return!(cp);

    let cp2 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &c, 2);
    push_compare_or_return!(cp2);

    let cp3 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 3);
    push_compare_or_return!(cp3);

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp2);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp2, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &cp3);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &cp3, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let dmul0 = wrap_hints_dense_dense_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &s);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_dense_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &s, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let addf = wrap_hint_point_add_with_frob(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4, 1);
    push_compare_or_return!(addf);
    t4 = addf;

    let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
    push_compare_or_return!(sdmul);
    f_acc = sdmul;

    let leval = wrap_multiply_point_evals_on_chord_for_fixed_g2_with_frob(is_compile_mode, all_output_hints.len(), &p3, &p2,  t2, t3, pubs.q2, pubs.q3, 1);
    push_compare_or_return!(leval);
    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, 1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, 1);


    let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let addf = wrap_hint_point_add_with_frob(is_compile_mode, all_output_hints.len(), &t4, &q4yc1, &q4yc0, &q4xc1, &q4xc0, &p4, -1);
    push_compare_or_return!(addf);
    t4 = addf;

    let sdmul = wrap_hint_sparse_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &t4, false);
    push_compare_or_return!(sdmul);
    f_acc = sdmul;

    let leval = wrap_multiply_point_evals_on_chord_for_fixed_g2_with_frob(is_compile_mode, all_output_hints.len(), &p3, &p2,  t2, t3, pubs.q2, pubs.q3, -1);
    push_compare_or_return!(leval);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, -1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, -1);

    let dmul0 = wrap_hints_dense_le_mul0(is_compile_mode, all_output_hints.len(), &f_acc, &leval);
    push_compare_or_return!(dmul0);

    let dmul1 = wrap_hints_dense_le_mul1(is_compile_mode, all_output_hints.len(), &f_acc, &leval, &dmul0);
    push_compare_or_return!(dmul1);
    f_acc = dmul1;

    let valid_facc = wrap_verify_fp12_is_unity(is_compile_mode, all_output_hints.len(), &f_acc, pubs.fixed_acc);
    push_compare_or_return!(valid_facc);

    true
}

pub(crate) fn hint_to_data(segments: Vec<Segment>) -> Assertions {
    let mut vs: Vec<[u8; 64]> = vec![];
    for v in segments {
        if v.is_validation {
            continue;
        }
        let x = v.result.0.hashed_output();
        vs.push(x);
    }
    let mut batch1 = vec![];
    for i in 0..NUM_PUBS {
        let val = vs[i];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch1.push(bal);
    }
    let batch1: [[u8; 32]; NUM_PUBS] = batch1.try_into().unwrap();

    let len = batch1.len();
    let mut batch2 = vec![];
    for i in 0..NUM_U256 {
        let val = vs[i + len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch2.push(bal);
    }
    let batch2: [[u8; 32]; N_VERIFIER_FQS] = batch2.try_into().unwrap();

    let len = batch1.len() + batch2.len();
    let mut batch3 = vec![];
    for i in 0..NUM_U160 {
        let val = vs[i+len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        batch3.push(bal);
    }
    let batch3: [[u8; 20]; N_VERIFIER_HASHES] = batch3.try_into().unwrap();

    (batch1, batch2, batch3)
}

type TypedAssertions = (
    [ark_bn254::Fr; N_VERIFIER_PUBLIC_INPUTS],
    [ark_bn254::Fq; N_VERIFIER_FQS],
    [HashBytes; N_VERIFIER_HASHES],
);

fn assertions_to_nibbles(tass: TypedAssertions) -> Vec<[u8;64]> {
    let mut nibvec: Vec<[u8;64]> = vec![];
    for fq in tass.0 {
        nibvec.push(extern_fr_to_nibbles(fq));
    }
    for fq in tass.1 {
        nibvec.push(extern_fq_to_nibbles(fq));
    }
    for fq in tass.2 {
        nibvec.push(fq);
    }
    nibvec
}

type Intermediates = Vec<HashBytes>;
pub(crate) fn get_proof(asserts: &TypedAssertions) -> InputProof { // EvalIns
    let numfqs = asserts.1;
    let p4 = ark_bn254::G1Affine::new_unchecked(numfqs[1], numfqs[0]);
    let p2 = ark_bn254::G1Affine::new_unchecked(numfqs[3], numfqs[2]);
    let step = 4;
    let c = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
            ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
            ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+6], numfqs[step+7]),
            ark_bn254::Fq2::new(numfqs[step+8], numfqs[step+9]),
            ark_bn254::Fq2::new(numfqs[step+10], numfqs[step+11]),
        ),
    );
    let step = step + 12;
    let s = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
            ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
            ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(numfqs[step+6], numfqs[step+7]),
            ark_bn254::Fq2::new(numfqs[step+8], numfqs[step+9]),
            ark_bn254::Fq2::new(numfqs[step+10], numfqs[step+11]),
        ),
    );

    let step = step + 12;
    let q4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(numfqs[step + 0], numfqs[step + 1]), ark_bn254::Fq2::new(numfqs[step + 2], numfqs[step + 3]));

    let eval_ins: InputProof = InputProof { p2, p4, q4, c, s, ks: asserts.0.to_vec() };
    eval_ins
}

pub(crate) fn get_intermediates(asserts: &TypedAssertions) -> Intermediates { // Intermediates
    let mut hashes= asserts.2.to_vec();
    hashes.reverse();
    hashes
}

pub(crate) fn get_assertions(signed_asserts: Signatures) -> TypedAssertions {
    let mut ks: Vec<ark_bn254::Fr> = vec![];
    for i in 0..N_VERIFIER_PUBLIC_INPUTS {
        let sc = signed_asserts.0[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fr =  ark_bn254::Fr::from_le_bytes_mod_order(&nibs);
        ks.push(fr);
    }

    let mut numfqs: Vec<ark_bn254::Fq> = vec![];
    for i in 0..N_VERIFIER_FQS {
        let sc = signed_asserts.1[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fq =  ark_bn254::Fq::from_le_bytes_mod_order(&nibs);
        numfqs.push(fq);
    }

    let mut numhashes: Vec<HashBytes> = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let sc = signed_asserts.2[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..40].to_vec();
        nibs.reverse();
        let nibs: [u8; 40] = nibs.try_into().unwrap();
        let mut padded_nibs = [0u8; 64]; // initialize with zeros
        padded_nibs[24..64].copy_from_slice(&nibs[0..40]);
        numhashes.push(padded_nibs);
    }
    (ks.try_into().unwrap(), numfqs.try_into().unwrap(), numhashes.try_into().unwrap())
}

pub(crate) fn get_pubs(vk: &ark_groth16::VerifyingKey<Bn254>) -> Pubs {
    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );
    let fixed_acc = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;

    let pubs: Pubs = Pubs { q2, q3, fixed_acc, ks_vks: msm_gs.clone(), vky0 };
    pubs
}

pub(crate) fn script_exec(
    segments: Vec<Segment>, 
    signed_asserts: Signatures,
    disprove_scripts: &[treepp::Script; N_TAPLEAVES],
) -> Option<(usize, treepp::Script)> {
    let mut scalar_sigs = signed_asserts.0.to_vec();
    scalar_sigs.reverse();
    let mut felts_sigs = signed_asserts.1.to_vec();
    felts_sigs.reverse();
    let mut hash_sigs = signed_asserts.2.to_vec();
    hash_sigs.reverse();
    let mock_felt_sig = signed_asserts.0[0].clone();

    let mut sigcache: HashMap<u32, SigData> = HashMap::new();
    for si  in 0..segments.len() {
        let s = &segments[si];
        if s.is_validation {
            let mock_fld_pub_key = SigData::Sig256(mock_felt_sig);
            sigcache.insert(si as u32, mock_fld_pub_key);
        } else {
            if s.result.1 == ElementType::FieldElem {
                sigcache.insert(si as u32, SigData::Sig256(felts_sigs.pop().unwrap()));
            } else if s.result.1 == ElementType::ScalarElem {
                sigcache.insert(si as u32, SigData::Sig256(scalar_sigs.pop().unwrap()));
            } else {
                sigcache.insert(si as u32, SigData::Sig160(hash_sigs.pop().unwrap()));
            }
        }
    }
    
    let mut sig = Sig { cache: sigcache };

    let aux_hints: Vec<Vec<Hint>> = segments.iter().map(|seg| {
        let mut hints = seg.hints.clone();
        seg.parameter_ids.iter().rev().for_each(|(param_seg_id, param_seg_type)| {
            let param_seg = &segments[*(param_seg_id) as usize];
            let preimage_hints = param_seg.result.0.get_hash_preimage_as_hints(*param_seg_type);
            hints.extend_from_slice(&preimage_hints);
        });
        hints
    }).collect();

    let mut bc_hints = vec![];
    for i in 0..segments.len() {
        let mut tot: Vec<(u32, bool)> = vec![];

        let seg = &segments[i];
        let sec_in: Vec<(u32, bool)> = seg.parameter_ids.iter().rev().map(|(k, _)| {
            let v = &segments[*(k) as usize];
            let v = v.result.0.output_is_field_element();
            (*k, v)
        }).collect();
        tot.extend_from_slice(&sec_in);

        if !seg.is_validation {
            let sec_out = (seg.id, segments[seg.id as usize].result.0.output_is_field_element());
            tot.push(sec_out);
        }

        let bcelems = tup_to_scr(&mut sig, tot);
        bc_hints.push(bcelems);
    }


    let mut tap_script_index = 0;
    for i in 0..aux_hints.len() {
        if segments[i].scr_type == ScriptType::NonDeterministic  {
            continue;
        }
        let hint_script = script!{
            for h in &aux_hints[i] {
                {h.push()}
            }
            {bc_hints[i].clone()}
        };
        let total_script = script!{
            {hint_script.clone()}
            {disprove_scripts[tap_script_index].clone()}
        };
        let exec_result = execute_script(total_script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
        if !exec_result.success {
            if exec_result.final_stack.len() != 1 {
                println!("final {:?}", i);
                println!("final {:?}", segments[i].scr_type);
                assert!(false);
            }
        } else {
            println!("disprove script {}: tapindex {}, {:?}",i,tap_script_index, segments[i].scr_type);
            let disprove_hint = (
                tap_script_index,
                hint_script,
            );
            return Some(disprove_hint);
        }
        tap_script_index += 1;
    }
    None
}
