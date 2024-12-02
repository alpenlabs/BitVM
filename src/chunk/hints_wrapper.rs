use std::collections::HashMap;

use ark_ff::{AdditiveGroup, Field};

use super::{hint_models::*, msm::{hint_hash_p, hint_msm, HintInMSM}, primitves::extern_hash_fps, segment::Segment, taps::*, taps_mul::*};


fn wrap_hint_msm(
    inputs: Vec<(usize, HintOut)>, msm_tap_index: usize, qs: Vec<ark_bn254::G1Affine>
) {

}

fn wrap_hint_hash_p(inputs: Vec<(usize, HintOut)>, vky0: ark_bn254::G1Affine) {

}

fn wrap_hint_hash_c(inputs: Vec<(usize, HintOut)>) {

}



fn wrap_hints_precompute_Px(inputs: Vec<(usize, HintOut)>) {

}

fn wrap_hints_precompute_Py(inputs: Vec<(usize, HintOut)>) {
}

fn wrap_hint_hash_c2(inputs: Vec<(usize, HintOut)>) {

}

fn wrap_hints_dense_dense_mul0_by_hash(inputs: Vec<(usize, HintOut)>) {
 
}

fn wrap_hints_dense_dense_mul1_by_hash(inputs: Vec<(usize, HintOut)>) {

}

fn wrap_hint_init_T4(inputs: Vec<(usize, HintOut)>) {

}

fn wrap_hint_squaring(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

}

fn wrap_hint_point_dbl(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_point_ops(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_sparse_dense_mul(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_double_eval_mul_for_fixed_Qs(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul0(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wraphints_dense_dense_mul1(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_add_eval_mul_for_fixed_Qs(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_frob_fp12(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_point_add_with_frob(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hint_add_eval_mul_for_fixed_Qs_with_frob(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul0_by_constant(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };


}

fn wrap_hints_dense_dense_mul1_by_constant(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    
}