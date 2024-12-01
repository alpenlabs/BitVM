use std::collections::HashMap;

use ark_ff::{AdditiveGroup, Field};

use super::{hint_models::*, msm::{hint_hash_p, hint_msm, HintInMSM}, primitves::extern_hash_fps, segment::Segment, taps::*, taps_mul::*};


fn wrap_hint_msm(inputs: Vec<(usize, HintOut)>, msm_tap_index: usize, qs: Vec<ark_bn254::G1Affine>) {
    // acc
    // scalars
    let mut indices = vec![];
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut t4 = ark_bn254::G1Affine::identity();
    if let (index, HintOut::MSM(hout)) = &inputs[0] {
        t4 = hout.t;
        if msm_tap_index != 0 {
            indices.push(*index);
        }
    }
    let mut scalars: Vec<ark_bn254::Fr> = vec![];
    for i in 1..inputs.len() {
        if let (index, HintOut::ScalarElem(scalar)) = &inputs[i] {
            scalars.push(*scalar);
            indices.push(*index);
        }
    }

    let (temp, _, _) = hint_msm(sig, (0, false), vec![(1, true), (0, false)], HintInMSM { t: t4, scalars: scalars }, msm_tap_index, qs);
}

fn wrap_hint_hash_p(inputs: Vec<(usize, HintOut)>, vky0: ark_bn254::G1Affine) {
    let mut indices = vec![];
    let mut r = ark_bn254::G1Affine::identity();
    if let (index, HintOut::FieldElem(rx)) = &inputs[0] {
        indices.push(*index);
        r.x = *rx
    }
    if let (index, HintOut::FieldElem(ry)) = &inputs[1] {
        indices.push(*index);
        r.y = *ry;
    }
    let mut t4 = ark_bn254::G1Affine::identity();
    if let (index, HintOut::MSM(hout)) = &inputs[0] {
        t4 = hout.t;
        indices.push(*index);
    }
    let hint_in = HintInHashP  { rx: r.x, ry: r.y, tx: t4.x, qx: vky0.x, ty: t4.y, qy: vky0.y };
    // validate gp3 = t + q
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let (h, _, _) = hint_hash_p(sig, (0, false), vec![(1, false), (2, true), (3, true)], hint_in);
}

fn wrap_hint_hash_c(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut indices = vec![];
    let mut scalars: Vec<ark_bn254::Fq> = vec![];
    for i in 1..inputs.len() {
        if let (index, HintOut::FieldElem(scalar)) = &inputs[i] {
            scalars.push(*scalar);
            indices.push(*index);
        }
    }

    let c = ark_bn254::Fq12::new(
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(scalars[11], scalars[10]),
            ark_bn254::Fq2::new(scalars[9], scalars[8]),
            ark_bn254::Fq2::new(scalars[7], scalars[6]),
        ),
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(scalars[5], scalars[4]),
            ark_bn254::Fq2::new(scalars[3], scalars[2]),
            ark_bn254::Fq2::new(scalars[1], scalars[0]),
        ),
    );
    let hashc = extern_hash_fps(scalars, false);

    let (c, _, _) = hint_hash_c(sig, (0, false), (0..12).map(|i| (i+1, true)).collect(), HintInHashC { c: c, hashc:hashc });

}



fn wrap_hints_precompute_Px(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut gp4 = ark_bn254::G1Affine::identity();
    let mut indices = vec![];

    if let (index, HintOut::FieldElem(rx)) = &inputs[0] {
        indices.push(*index);
        gp4.x = *rx
    }
    if let (index, HintOut::FieldElem(ry)) = &inputs[1] {
        indices.push(*index);
        gp4.y = *ry;
    }

    let (p4x, _, _) = hints_precompute_Px(sig, (0, true), vec![(1, true), (2, true), (3, true)], HintInPrecomputePx { p: ark_bn254::G1Affine::new_unchecked(gp4.x, gp4.y) });
}

fn wrap_hints_precompute_Py(inputs: Vec<(usize, HintOut)>) {

    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    let mut gp4y = ark_bn254::Fq::ZERO;
    let mut indices = vec![];

    if let (index, HintOut::FieldElem(ry)) = &inputs[0] {
        indices.push(*index);
        gp4y = *ry
    }
    let (p4y, _, _) = hints_precompute_Py(sig, (0, true), vec![(1, true)], HintInPrecomputePy { p: gp4y });
}

fn wrap_hint_hash_c2(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };
    
    let mut indices = vec![];

    if let (index, HintOut::HashC(f)) = &inputs[0] {
        indices.push(*index);

        let (c2, _, _) = hint_hash_c2(sig, (0, false), vec![(1, false)], HintInHashC { c: f.f, hashc: f.hash });        
    }

}

fn wrap_hints_dense_dense_mul0_by_hash(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let mut indices = vec![];

    let mut c2 = ark_bn254::Fq12::ZERO;
    if let (index, HintOut::HashC(f)) = &inputs[0] {
        c2 = f.f;
        indices.push(*index);
    }

    let mut cinvhash = [0u8; 64];
    if let (index, HintOut::GrothC(f)) = &inputs[1] {
        cinvhash = f.hash;
        indices.push(*index);
    }

    let (dmul0, _, _) = hints_dense_dense_mul0_by_hash(sig, (0, false), vec![(1, false), (2, false)], HintInDenseMulByHash0 {a: c2, bhash: cinvhash});
    


}

fn wrap_hints_dense_dense_mul1_by_hash(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let mut indices = vec![];

    let mut c2 = ark_bn254::Fq12::ZERO;
    if let (index, HintOut::HashC(f)) = &inputs[0] {
        c2 = f.f;
        indices.push(*index);
    }

    let mut cinvhash = [0u8; 64];
    if let (index, HintOut::GrothC(f)) = &inputs[0] {
        cinvhash = f.hash;
        indices.push(*index);
    }

    let (dmul1, _, _) = hints_dense_dense_mul1_by_hash(sig, (0, false), vec![(1, false), (2, false), (3, false)], HintInDenseMulByHash1 {a: c2, bhash: cinvhash});

}

fn wrap_hint_init_T4(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let mut indices = vec![];
    let mut scalars: Vec<ark_bn254::Fq> = vec![];

    for i in 0..inputs.len() {
        if let (index, HintOut::FieldElem(scalar)) = &inputs[i] {
            scalars.push(*scalar);
            indices.push(*index);
        }
    }
    
    let (tmpt4, _, _) = hint_init_T4(sig, (0, false), vec![(1, true), (2, true), (3, true), (4, true)], HintInInitT4 { t4: ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(scalars[0], scalars[1]), ark_bn254::Fq2::new(scalars[2], scalars[3])) }); 

}

fn wrap_hint_squaring(inputs: Vec<(usize, HintOut)>) {
    let sig = &mut Sig { msk: None, cache: HashMap::new() };

    let mut indices = vec![];

    if let (index, HintOut::HashC(f)) = &inputs[0] {
        indices.push(*index);
        let (sq, _, _) = hint_squaring(sig, (0, false), vec![(1, false)], HintInSquaring { a: f.f, ahash: f.hash });
    }
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