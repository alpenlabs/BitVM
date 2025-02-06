use std::collections::HashMap;

use ark_ec::CurveGroup;
use bitcoin_script::script;

use crate::{bn254::utils::Hint, chunk::{norm_fp12::get_hint_for_add_with_frob, primitves::{tup_to_scr, HashBytes, Sig, SigData}, segment::*}, execute_script, groth16::g16::{Signatures, N_TAPLEAVES}, treepp};


use super::{compile::ATE_LOOP_COUNT, element::*, assigner::*};



#[derive(Debug)]
pub struct Pubs {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq6,
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

    let (gp2, gp4, gq4, gc, gs, pub_scalars) = raw_input_proof_to_segments(eval_ins, all_output_hints);
    let (gp2x, gp2y) = (gp2[0].clone(), gp2[1].clone());
    let (gp4x, gp4y) = (gp4[0].clone(), gp4[1].clone());
    let (q4xc0, q4xc1, q4yc0, q4yc1) = (gq4[0].clone(), gq4[1].clone(), gq4[2].clone(), gq4[3].clone());
    let gc = gc.to_vec();
    let gs = gs.to_vec();
    let pub_scalars = pub_scalars.to_vec();

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
    let c = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gc.clone());
    push_compare_or_return!(c);

    let valid_gs = wrap_verify_fq12_is_on_field(is_compile_mode, all_output_hints.len(), gs.clone());
    push_compare_or_return!(valid_gs);
    let s = wrap_hint_hash_c(is_compile_mode, all_output_hints.len(), gs);
    push_compare_or_return!(s);

    let gcinv = wrap_hint_hash_c_inv(is_compile_mode, all_output_hints.len(),gc);
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

        t4 = wrap_hint_point_ops(
            is_compile_mode, all_output_hints.len(), true, None, None,
            &t4, &p4, None, &p3, t3, None, &p2, t2, None
        );
        push_compare_or_return!(t4);
        (t2, t3) = ((t2 + t2).into_affine(), (t3 + t3).into_affine());

        let lev = wrap_complete_point_eval_and_mul(is_compile_mode, all_output_hints.len(), &t4);
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);

        if ate == 0 {
            continue;
        }

        let c_or_cinv = if ate == -1 { c.clone() } else { gcinv.clone() };
        f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &c_or_cinv);
        push_compare_or_return!(f_acc);


        t4 = wrap_hint_point_ops(
            is_compile_mode, all_output_hints.len(), false, Some(false), Some(ate),
            &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
        );
        push_compare_or_return!(t4);
        if ate == 1 {
            (t2, t3) = ((t2 + pubs.q2).into_affine(), (t3 + pubs.q3).into_affine());
        } else {
            (t2, t3) = ((t2 - pubs.q2).into_affine(), (t3 - pubs.q3).into_affine());
        }

        let lev = wrap_complete_point_eval_and_mul(is_compile_mode, all_output_hints.len(), &t4);
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);
    }

    let cp = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 1);
    push_compare_or_return!(cp);

    let cp2 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &c, 2);
    push_compare_or_return!(cp2);

    let cp3 = wrap_hints_frob_fp12(is_compile_mode, all_output_hints.len(), &gcinv, 3);
    push_compare_or_return!(cp3);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &cp);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &cp2);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &cp3);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &s);
    push_compare_or_return!(f_acc);



    t4 = wrap_hint_point_ops(
        is_compile_mode, all_output_hints.len(), false, Some(true), Some(1),
        &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
    );
    push_compare_or_return!(t4);

    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, 1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, 1);
    let lev = wrap_complete_point_eval_and_mul(is_compile_mode, all_output_hints.len(), &t4);
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);


    t4 = wrap_hint_point_ops(
        is_compile_mode, all_output_hints.len(), false, Some(true), Some(-1),
        &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
    );
    push_compare_or_return!(t4);

    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, -1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, -1);
    let lev = wrap_complete_point_eval_and_mul(is_compile_mode, all_output_hints.len(), &t4);
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(is_compile_mode, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);


    let valid_facc = wrap_chunk_final_verify(is_compile_mode, all_output_hints.len(), &f_acc, pubs.fixed_acc);
    push_compare_or_return!(valid_facc);

    let is_valid: ark_ff::BigInt::<4> = valid_facc.result.0.try_into().unwrap();
    let is_valid = is_valid == ark_ff::BigInt::<4>::one();
    
    is_valid
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


