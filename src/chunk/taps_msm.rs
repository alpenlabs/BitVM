use std::ops::{AddAssign, Div, Neg, Rem};
use std::str::FromStr;

use crate::bn254;
use crate::bn254::fr::Fr;
use crate::bn254::utils::{fq_push_not_montgomery, fr_push_not_montgomery};
use crate::chunk::primitves::{
    extern_hash_fps, unpack_limbs_to_nibbles
};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed};

use super::hint_models::{ElemFq, ElemFr, ElemG1Point};
use super::primitves::{hash_fp2, HashBytes};
use crate::bn254::fq2::Fq2;
use crate::bn254::utils::Hint;

pub(crate) fn tap_msm(window: usize, msm_tap_index: usize, qs: Vec<ark_bn254::G1Affine>) -> Script {
    assert!(qs.len() > 0);
    let (hinted_check_tangent, _) = bn254::curves::G1Affine::hinted_check_tangent_line(
        ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::one(), ark_bn254::Fq::one()),
        ark_bn254::Fq::one(),
    );
    let (hinted_double_line, _) = bn254::curves::G1Affine::hinted_double(
        ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        ark_bn254::Fq::one(),
    );

    let (hinted_check_chord_t, _) = bn254::curves::G1Affine::hinted_check_line_through_point(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_check_chord_q, _) = bn254::curves::G1Affine::hinted_check_line_through_point(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_add_line, _) = bn254::curves::G1Affine::hinted_add(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );

    let doubling_loop = script! {
        // [alpha, bias, tx, ty]
        for _ in 0..window {
            {Fq2::copy(2)}
            {Fq2::copy(2)}
            {hinted_check_tangent.clone()} 
            OP_VERIFY
            {Fq::drop()}
            {Fq::toaltstack()}
            {Fq::fromaltstack()}
            {hinted_double_line.clone()}
        }
    };

    let ops_script = script! {

        // reverse scalar order
        for _ in 0..qs.len() {
            {Fq::fromaltstack()}
        }
        for i in 0..qs.len() {
            {Fq::roll(i as u32)}
        }
        for _ in 0..qs.len() {
            {Fq::toaltstack()}
        }

        {msm_tap_index} 0 OP_NUMEQUAL
        OP_IF
            {Fq2::copy(0)}
            {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
            {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
            {Fq2::equalverify()}
        OP_ENDIF


        //[t]
        {Fq::copy(0)}
        {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
        {Fq::equal(1, 0)} OP_NOT // ty == 0 ?
        OP_IF // doubling step only if not zero
            {Fq2::copy(0)}
            {Fq2::toaltstack()}
            {doubling_loop.clone()}
            {Fq2::fromaltstack()}
            {Fq2::roll(2)}
        OP_ELSE
            {Fq2::copy(0)}
        OP_ENDIF
        //[t,nt]

        // [z, 16z]
        // addition step: assign new_t = q if t = 0 given q != 0
        {Fq::fromaltstack()} // scalar
        {tap_extract_window_segment_from_scalar(msm_tap_index as usize)}
        OP_DUP 0 OP_NUMEQUAL
        OP_IF
            OP_DROP
        OP_ELSE
            {tap_bake_precompute(qs[0], window)}
            // [a, b, tx, ty, ntx, nty, qx, qy]
            {Fq2::roll(2)}
            // [tx, ty, qx, qy, ntx, nty]
            {Fq::copy(0)}
            {fq_push_not_montgomery(ark_bn254::Fq::ZERO)} // ty == 0 ?
            {Fq::equal(1, 0)}
            OP_IF
                {Fq2::drop()}
                // [ntx,nty] = [qx,qy]
            OP_ELSE
                //[alpha, bias, tx, ty, qx, qy, ntx, nty]
                {Fq2::copy(6)}
                // [alpha, bias,tx,ty, qx, qy, ntx, nty, alpha, bias]
                {Fq2::copy(2)}
                {hinted_check_chord_t.clone()} OP_VERIFY
                //[alpha, bias, qx, qy, ntx, nty]
                {Fq2::copy(6)}
                {Fq2::copy(4)}
                {hinted_check_chord_q.clone()} OP_VERIFY
                //[alpha, bias,tx,ty, qx, qy, ntx, nty]
                {Fq::drop()}
                {Fq::roll(1)} {Fq::drop()}
                //[alpha, bias, tx, ty, qx, ntx]
                {Fq::roll(5)} {Fq::roll(5)}
                //[tx, ty, qx, ntx, alpha, bias]
                {Fq::roll(2)} {Fq::roll(3)}
                //[tx, ty, alpha, bias, ntx, qx]
                {hinted_add_line.clone()}
                // [t,nt]
            OP_ENDIF
        OP_ENDIF


        for i in 1..qs.len() {
            {Fq::fromaltstack()} // scalar
            {tap_extract_window_segment_from_scalar(msm_tap_index as usize)}
            OP_DUP 0 OP_NUMEQUAL
            OP_IF
                OP_DROP
            OP_ELSE
                {tap_bake_precompute(qs[i], window)}
                {Fq2::roll(2)}
                //[alpha, bias, tx, ty, qx, qy, ntx, nty]
                {Fq::copy(0)}
                {fq_push_not_montgomery(ark_bn254::Fq::ZERO)} // ty == 0 ?
                {Fq::equal(1, 0)}
                OP_IF
                    {Fq2::drop()}
                    // [ntx,nty] = [qx,qy]
                OP_ELSE
                    {Fq2::copy(6)}
                    // [alpha, bias,tx,ty, qx, qy, ntx, nty, alpha, bias]
                    {Fq2::copy(2)}
                    {hinted_check_chord_t.clone()}
                    //[alpha, bias, qx, qy, ntx, nty]
                    {Fq2::copy(6)}
                    {Fq2::copy(4)}
                    {hinted_check_chord_q.clone()}
                    //[alpha, bias,tx,ty, qx, qy, ntx, nty]
                    {Fq::drop()}
                    {Fq::roll(1)} {Fq::drop()}
                    //[alpha, bias, tx, ty, qx, ntx]
                    {Fq::roll(4)} {Fq::roll(5)}
                    //[tx, ty, qx, ntx, bias, alpha]
                    {Fq::roll(2)} {Fq::roll(3)}
                    //[tx, ty, bias, alpha, ntx, qx]
                    {hinted_add_line.clone()}
                OP_ENDIF
            OP_ENDIF
        }

    };

    let hash_script = script! {
        // [t, nt]
        {Fq2::roll(2)} // [nt, t]
        {msm_tap_index} 0 OP_NUMEQUAL
        OP_IF
            {Fq2::drop()}
        OP_ELSE
            {Fq2::roll(2)} {Fq2::toaltstack()}
            {hash_fp2()} {Fq2::fromaltstack()}// [t_hash, nt]
            {Fq::roll(2)} // [nt, t_hash]
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}
        OP_ENDIF
        {hash_fp2()} // [nt]
        {Fq::fromaltstack()}
        {Fq::equal(1,0)} OP_NOT OP_VERIFY
    };

    let sc = script! {
        {ops_script}
        {hash_script}
        OP_TRUE
    };
    sc
}

fn tap_bake_precompute(q: ark_bn254::G1Affine, window: usize) -> Script {
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << window) {
        p_mul.push((p_mul.last().unwrap().clone() + q.clone()).into_affine());
    }
    script! {
        for i in 0..(1 << window) {
            OP_DUP {i} OP_NUMEQUAL
            OP_IF
                {fq_push_not_montgomery(p_mul[i].x)}
                {fq_push_not_montgomery(p_mul[i].y)}
            OP_ENDIF
        }
        {18} OP_ROLL OP_DROP
        // OP_DEPTH OP_1SUB OP_ROLL OP_DROP
    }
}

fn tap_extract_window_segment_from_scalar(index: usize) -> Script {
    const N: usize = 32;
    script! {
        {unpack_limbs_to_nibbles()}
        {N-1-index} OP_DUP OP_ADD // double
        OP_1ADD // +1
        OP_DUP OP_TOALTSTACK
        OP_ROLL
        OP_FROMALTSTACK OP_ROLL
        OP_TOALTSTACK OP_TOALTSTACK
        for _ in 0..N-1 {
            OP_2DROP
        }
        OP_FROMALTSTACK
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_FROMALTSTACK
        OP_ADD
    }
}

// #[derive(Debug, Clone)]
// pub(crate) struct HintInMSM {
//     pub(crate) t: ark_bn254::G1Affine,
//     pub(crate) scalars: Vec<ark_bn254::Fr>,
//     //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
// }

fn get_byte_mul_g1(
    scalar: ark_bn254::Fr,
    window: u8,
    index: usize,
    base: ark_bn254::G1Affine,
) -> ark_bn254::G1Affine {
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << window) {
        p_mul.push((p_mul.last().unwrap().clone() + base.clone()).into_affine());
    }

    let chunks = scalar
        .into_bigint()
        .to_bits_be()
        .iter()
        .map(|b| if *b { 1_u8 } else { 0_u8 })
        .collect::<Vec<_>>()
        .chunks(window as usize)
        .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
        .collect::<Vec<u32>>();

    let item = chunks[index];
    let precomputed_q = p_mul[item as usize];
    return precomputed_q;
}

pub(crate) fn hint_msm(
    hint_in_t: ElemG1Point,
    hint_in_scalars: Vec<ElemFr>,
    msm_tap_index: usize,
    qs: Vec<ark_bn254::G1Affine>,
) -> (ElemG1Point, Script) {
    const WINDOW_LEN: u8 = 8;
    const MAX_SUPPORTED_PUBS: usize = 3;

    // hint_in
    let mut t = hint_in_t.clone();
    assert!(qs.len() <= MAX_SUPPORTED_PUBS);
    assert_eq!(qs.len(), hint_in_scalars.len());

    // constants
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;

    let mut aux_tangent = vec![];

    let mut hints_tangent: Vec<Hint> = Vec::new();

    if t.y != ark_bn254::Fq::ZERO {
        for _ in 0..WINDOW_LEN {
            let mut alpha = t.x.square();
            alpha /= t.y;
            alpha *= three_div_two;
            let bias_minus = alpha * t.x - t.y;
            let new_tx = alpha.square() - t.x.double();
            let new_ty = bias_minus - alpha * new_tx;

            let (_, hints_check_tangent) = bn254::curves::G1Affine::hinted_check_tangent_line(t, alpha);
            let (_, hints_double_line) = bn254::curves::G1Affine::hinted_double(t, alpha);

            t.x = new_tx;
            t.y = new_ty;

            for hint in hints_check_tangent {
                hints_tangent.push(hint);
            }
            for hint in hints_double_line {
                hints_tangent.push(hint);
            }

            aux_tangent.push(bias_minus);
            aux_tangent.push(alpha);
        }
    }
    let mut hints_chord: Vec<Hint> = Vec::new();
    let mut aux_chord = vec![];
    let mut q = ark_bn254::G1Affine::identity();
    for (qi, qq) in qs.iter().enumerate() {
        q = get_byte_mul_g1(hint_in_scalars[qi], WINDOW_LEN, msm_tap_index, *qq);
        if t.y == ark_bn254::Fq::ZERO {
            t = q.clone();
            continue;
        } else if q == ark_bn254::G1Affine::zero() {
            continue;
        } else {
            let alpha = (t.y - q.y) / (t.x - q.x);
            let bias_minus = alpha * t.x - t.y;

            let new_tx = alpha.square() - t.x - q.x;
            let new_ty = bias_minus - alpha * new_tx;

            let (_, hints_check_chord_t) =
                bn254::curves::G1Affine::hinted_check_line_through_point(t.x, alpha);
            let (_, hints_check_chord_q) =
                bn254::curves::G1Affine::hinted_check_line_through_point(q.x, alpha);
            let (_, hints_add_line) = bn254::curves::G1Affine::hinted_add(t.x, q.x, alpha);

            t.x = new_tx;
            t.y = new_ty;

            for hint in hints_check_chord_t {
                hints_chord.push(hint)
            }
            for hint in hints_check_chord_q {
                hints_chord.push(hint)
            }
            for hint in hints_add_line {
                hints_chord.push(hint)
            }
            aux_chord.push(bias_minus);
            aux_chord.push(alpha);
        }
    }

    let simulate_stack_input = script! {
        // // tmul hints
        for hint in hints_tangent { // check_tangent then double line
            {hint.push()}
        }
        for hint in hints_chord { // check chord q, t, add line
            {hint.push()}
        }
        for i in 0..aux_chord.len() { //
            {fq_push_not_montgomery(aux_chord[aux_chord.len()-1-i])}
        }
        for i in 0..aux_tangent.len() {
            {fq_push_not_montgomery(aux_tangent[aux_tangent.len()-1-i])}
        }

        // accumulator
        {fq_push_not_montgomery(hint_in_t.x)}
        {fq_push_not_montgomery(hint_in_t.y)}

    };
    let hint_out = t;

    (hint_out, simulate_stack_input)
}

// Hash P
//vk0: G1Affine
pub(crate) fn tap_hash_p(q: G1Affine) -> Script {
    let (hinted_add_line, _) = bn254::curves::G1Affine::hinted_add(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_line_pt, _) = bn254::curves::G1Affine::hinted_check_line_through_point(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );

    let ops_script = script!{
        // Altstack:[identity, th, gpy, gpx]
        {Fq::fromaltstack()} {Fq::fromaltstack()} {Fq::fromaltstack()}
        // Stack:[..gpx, gpy, th]
        {Fq::roll(1)} {Fq::roll(2)}
        // Stack:[..th, gpy, gpx]
        {Fq::toaltstack()} {Fq::toaltstack()} {Fq::toaltstack()}
        // Altstack:[identity, gpx, gpy, th]

        //[hinttqa, alpha, bias, tx, ty]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias,tx, ty] 
        { hinted_line_pt.clone() } OP_VERIFY
        //[hinttqa, alpha, bias, tx, ty

        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        {fq_push_not_montgomery(q.x)}
        {fq_push_not_montgomery(q.y)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias, qx, qy]
        { hinted_line_pt.clone() } OP_VERIFY

        //[hinttqa, alpha, bias, tx, ty
        {Fq2::copy(0)}
        {Fq2::toaltstack()}
        {Fq::drop()} {Fq::toaltstack()}
        {Fq::fromaltstack()}

        // //[hinttqa, alpha, bias, tx]
        {fq_push_not_montgomery(q.x)}
        { hinted_add_line.clone() }

        // Altstack:[identity, gpx, gpy, th]
        //[ntx, nty, tx, ty]

        {Fq2::fromaltstack()} {Fq::fromaltstack()}
        {Fq2::roll(3)} {Fq2::toaltstack()} {Fq::toaltstack()}
        { hash_fp2() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)} {Fq2::fromaltstack()} 
        {Fq2::fromaltstack()} {Fq::roll(1)}
        // // [ntx, nty, gpx, gpy]
        {Fq::fromaltstack()}
        {fq_push_not_montgomery(ark_bn254::Fq::ZERO)}
        // [ntx, nty, gpx, gpy, zero, 0]
        {Fq::equal(1, 0)}
        OP_IF 
            // equal so, continue verify rest
            {Fq2::equal()}
            OP_NOT OP_VERIFY
        OP_ELSE
            // not equal, disproven, so drop and exit
            {Fq2::drop()}
            {Fq2::drop()}
            {1} OP_VERIFY
        OP_ENDIF
    };

    let sc = script! {
        {ops_script}
        OP_TRUE
    };
    sc
}


pub(crate) fn hint_hash_p(
    hint_in_t: ElemG1Point,
    hint_in_ry: ElemFq,
    hint_in_rx: ElemFq,
    hint_in_q: ark_bn254::G1Affine,
) -> (HashBytes, Script) {
    // r (gp3) = t(msm) + q(vk0)
    let (tx, qx, ty, qy) = (hint_in_t.x, hint_in_q.x, hint_in_t.y, hint_in_q.y);
    
    let (rx, ry) = (hint_in_rx, hint_in_ry);
    let thash = extern_hash_fps(vec![hint_in_t.x, hint_in_t.y], false);

    let zero_nib = [0u8;64];

    let alpha_chord = (ty - qy) / (tx - qx);
    let bias_minus_chord = alpha_chord * tx - ty;
    assert_eq!(alpha_chord * tx - ty, bias_minus_chord);

    let (_, hints_check_chord_t) = bn254::curves::G1Affine::hinted_check_line_through_point(tx, alpha_chord);
    let (_, hints_check_chord_q) = bn254::curves::G1Affine::hinted_check_line_through_point(qx, alpha_chord);
    let (_, hints_add_line) = bn254::curves::G1Affine::hinted_add(tx, qx, alpha_chord);



    let simulate_stack_input = script! {
        // bit commits raw
        for hint in hints_check_chord_t {
            {hint.push()}
        }
        for hint in hints_check_chord_q {
            {hint.push()}
        }
        for hint in hints_add_line {
            {hint.push()}
        }

        {fq_push_not_montgomery(alpha_chord)}
        {fq_push_not_montgomery(bias_minus_chord)}

        {fq_push_not_montgomery(tx)}
        {fq_push_not_montgomery(ty)}
    };
    (zero_nib, simulate_stack_input)
}


/// Decomposes a scalar s into k1, k2, s.t. s = k1 + lambda k2,
fn calculate_scalar_decomposition(
    k: ark_bn254::Fr,
) -> ((u8, ark_bn254::Fr), (u8, ark_bn254::Fr)) {
    let scalar: BigInt = k.into_bigint().into();

    let scalar_decomp_coeffs: [(bool, BigUint); 4] = [
        (false, BigUint::from_str("147946756881789319000765030803803410728").unwrap()),
        (true, BigUint::from_str("9931322734385697763").unwrap()),
        (false, BigUint::from_str("9931322734385697763").unwrap()),
        (false, BigUint::from_str("147946756881789319010696353538189108491").unwrap()),
    ];
    
    let coeff_bigints: [BigInt; 4] = scalar_decomp_coeffs.map(|x| {
        BigInt::from_biguint(x.0.then_some(Sign::Plus).unwrap_or(Sign::Minus), x.1)
    });

    let [n11, n12, n21, n22] = coeff_bigints;

    let r = BigInt::from_biguint(Sign::Plus, BigUint::from(ark_bn254::Fr::MODULUS));

    // beta = vector([k,0]) * self.curve.N_inv
    // The inverse of N is 1/r * Matrix([[n22, -n12], [-n21, n11]]).
    // so β = (k*n22, -k*n12)/r

    let beta_1 = {
        let mut div = (&scalar * &n22).div(&r);
        let rem = (&scalar * &n22).rem(&r);
        if (&rem + &rem) > r {
            div.add_assign(BigInt::one());
        }
        div
    };
    let beta_2 = {
        let mut div = (&scalar * &n12.clone().neg()).div(&r);
        let rem = (&scalar * &n12.clone().neg()).rem(&r);
        if (&rem + &rem) > r {
            div.add_assign(BigInt::one());
        }
        div
    };

    // b = vector([int(beta[0]), int(beta[1])]) * self.curve.N
    // b = (β1N11 + β2N21, β1N12 + β2N22) with the signs!
    //   = (b11   + b12  , b21   + b22)   with the signs!

    // b1
    let b11 = &beta_1 * &n11;
    let b12 = &beta_2 * &n21;
    let b1 = b11 + b12;

    // b2
    let b21 = &beta_1 * &n12;
    let b22 = &beta_2 * &n22;
    let b2 = b21 + b22;

    let k1 = &scalar - b1;
    let k1_abs = BigUint::try_from(k1.abs()).unwrap();

    // k2
    let k2 = -b2;
    let k2_abs = BigUint::try_from(k2.abs()).unwrap();

    let k1signr = k1.sign();
    let k2signr = k2.sign();


    let mut k1sign: u8 = 0;
    if k1signr == Sign::Plus {
        k1sign = 1;
    } else if k1signr == Sign::Minus {
        k1sign = 2;
    } else {
        k1sign = 0;
    }

    let mut k2sign: u8 = 0;
    if k2signr == Sign::Plus {
        k2sign = 1;
    } else if k2signr == Sign::Minus {
        k2sign = 2;
    } else {
        k2sign = 0;
    }

    (
        (k1sign , ark_bn254::Fr::from(k1_abs)),
        (k2sign , ark_bn254::Fr::from(k2_abs)),
    )
}

fn hinted_scalar_mul_by_constant(a: ark_bn254::Fr, constant: &ark_bn254::Fr) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let x = BigInt::from_str(&a.to_string()).unwrap();
    let y = BigInt::from_str(&constant.to_string()).unwrap();
    let modulus = &Fr::modulus_as_bigint();
    let q = (x * y) / modulus;

    let script = script! {
        for _ in 0..bn254::fr::Fr::N_LIMBS {
            OP_DEPTH OP_1SUB OP_ROLL // hints
        }
        { Fr::roll(1) }
        { fr_push_not_montgomery(*constant) }
        { Fr::tmul() }
    };
    hints.push(Hint::BigIntegerTmulLC1(q));
    (script, hints)
}

fn hinted_scalar_decomposition(k: ark_bn254::Fr) -> (Script, Vec<Hint>) {
    const LAMBDA: ark_bn254::Fr = MontFp!("21888242871839275217838484774961031246154997185409878258781734729429964517155");
    let (_, (_, k1)) = calculate_scalar_decomposition(k);
    let (mul_scr, mul_hints) = hinted_scalar_mul_by_constant(k1, &LAMBDA);
    let scr = script!{
        // [s0, s1, k0, k1, k]
        {Fr::toaltstack()}
        // [s0, s1, k0, k1]
        {mul_scr}
        // [s0, s1, k0, k1 * lambda]
        {Fr::N_LIMBS * 2} OP_ROLL
        // [s0, k0, k1 * lambda, s1]
        {2} OP_EQUAL
        OP_IF
            {Fr::neg(0)}
        OP_ENDIF
        {Fr::toaltstack()}

        // [k, s0, k0]
        {Fr::N_LIMBS} OP_ROLL
        // [k, k0, s0]
        {2} OP_EQUAL
        OP_IF
            {Fr::neg(0)}
        OP_ENDIF
        {Fr::fromaltstack()}
        // [k0, k1]
        {Fr::add(1, 0)}
        {Fr::fromaltstack()}
        // [k', k]
        {Fr::equalverify(1, 0)}
    };
    (scr, mul_hints)
}

fn hinted_endomorphoism(a: ark_bn254::G1Affine) -> (Script, Vec<Hint>) {
    let endo_coeffs = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616"
    ).unwrap();
    let endo_coeffs = ark_bn254::Fq::from(endo_coeffs);

    let (mul_scr, mul_hints) = Fq::hinted_mul_by_constant(a.x, &endo_coeffs);

    let scr = script!{
        // [tmul_hints, a.x, a.y]
        {Fq::roll(1)}
        {mul_scr}
        {Fq::roll(1)}
        // [e*a.x, a.y]
    };
    (scr, mul_hints)
}

#[cfg(test)]
mod test {

    use crate::{
        bn254::{fq2::Fq2, utils::fr_push_not_montgomery}, chunk::{primitves::extern_nibbles_to_limbs},
    };
    use super::*;
    use ark_bn254::{G1Affine};
    use ark_ff::{MontFp, UniformRand};
    use bitcoin::opcodes::OP_TRUE;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::chunk::hint_models::ElemTraitExt;

    #[test]
    fn test_precompute_table() {
        let window = 8;
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        let q = G1Affine::rand(&mut prng);
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << window) {
            p_mul.push((p_mul.last().unwrap().clone() + q.clone()).into_affine());
        }

        let scr = tap_bake_precompute(q, window);
        let index = u32::rand(&mut prng) % (1 << window);
        println!("script len {:?}", scr.len());
        let script = script! {
            {index}
            {scr}
            {fq_push_not_montgomery(p_mul[index as usize].y)}
            {Fq::equalverify(1, 0)}
            {fq_push_not_montgomery(p_mul[index as usize].x)}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

    #[test]
    fn test_extract_window_from_scalar() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let scalar = ark_bn254::Fr::rand(&mut prng);

        let index = u32::rand(&mut prng) % 32;
        let window = 8;

        let chunks = scalar
            .into_bigint()
            .to_bits_be()
            .iter()
            .map(|b| if *b { 1_u8 } else { 0_u8 })
            .collect::<Vec<_>>()
            .chunks(window as usize)
            .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
            .collect::<Vec<u32>>();
        let chunk_match = chunks[index as usize];
        println!("chunk_match {:?}", chunk_match);
        let script = script! {
            {fr_push_not_montgomery(scalar)}
            {tap_extract_window_segment_from_scalar(index as usize)}
            {chunk_match}
            OP_EQUALVERIFY
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("max stat {:?}", res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_hinted_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha *= three_div_two;
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let nx = alpha.square() - t.x.double();
        let ny = bias_minus - alpha * nx;

        let (hinted_check_line, hints) = bn254::curves::G1Affine::hinted_check_tangent_line(t, alpha);
        let (hinted_double_line, hintsd) = bn254::curves::G1Affine::hinted_double(t, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { fq_push_not_montgomery(t.y) }
            { hinted_check_line.clone() }
            OP_VERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        let script = script! {
            for hint in hintsd {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { hinted_double_line.clone() }
            {fq_push_not_montgomery(nx)}
            {fq_push_not_montgomery(ny)}
            {Fq2::equalverify()}
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_double_line: {} @ {} stack",
            hinted_double_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        // doubling check
    }

    #[test]
    fn test_hinted_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add_line, hints) = bn254::curves::G1Affine::hinted_add(t.x, q.x, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { fq_push_not_montgomery(q.x) }
            { hinted_add_line.clone() }
            { fq_push_not_montgomery(x) }
            { fq_push_not_montgomery(y) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_add_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_tap_hash_p() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let r = (t + q).into_affine();
        let thash = extern_hash_fps(vec![t.x, t.y], false);

        let hash_c_scr = tap_hash_p(q);

        let (hint_out, hint_script) = hint_hash_p( t, r.y, r.x,q);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(thash) {
                {i}
            }
            {Fq::toaltstack()}
            {fq_push_not_montgomery(r.y)}
            {Fq::toaltstack()}   
            {fq_push_not_montgomery(r.x)}
            {Fq::toaltstack()}   
        };


        let tap_len = hash_c_scr.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {hash_c_scr}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let scalars = vec![ark_bn254::Fr::ONE, ark_bn254::Fr::ONE, ark_bn254::Fr::ONE + ark_bn254::Fr::ONE];
        let qs = vec![q, q, (q+ q).into_affine()];
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let t: ElemG1Point = t;
        let msm_tap_index = 1;

        let hash_c_scr = tap_msm(8, msm_tap_index, qs.clone());

        let (hint_out, hint_script) = hint_msm( t, scalars.clone(), msm_tap_index, qs.clone());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(t.out()) {
                {i}
            }
            {Fq::toaltstack()}

            for scalar in scalars {
                {fr_push_not_montgomery(scalar)}
                {Fq::toaltstack()}  
            }
        };


        let tap_len = hash_c_scr.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {hash_c_scr}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }



    #[test]
    fn test_hinted_scalar_decomposition() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        const LAMBDA: ark_bn254::Fr = MontFp!("21888242871839275217838484774961031246154997185409878258781734729429964517155");
        let k = ark_bn254::Fr::rand(&mut prng);

        let dec = calculate_scalar_decomposition(k);
        let  ((is_k1_positive, k1), (is_k2_positive, k2)) = dec;
        let (is_k1_positive, is_k2_positive) = (is_k1_positive != 2, is_k2_positive != 2);

        if is_k1_positive && is_k2_positive {
            assert_eq!(k1 + k2 * LAMBDA, k);
        }
        if is_k1_positive && !is_k2_positive {
            assert_eq!(k1 - k2 * LAMBDA, k);
        }
        if !is_k1_positive && is_k2_positive {
            assert_eq!(-k1 + k2 * LAMBDA, k);
        }
        if !is_k1_positive && !is_k2_positive {
            assert_eq!(-k1 - k2 * LAMBDA, k);
        }
        // check if k1 and k2 are indeed small.
        let expected_max_bits = (ark_bn254::Fr::MODULUS_BIT_SIZE + 1) / 2;
        assert!(
            k1.into_bigint().num_bits() <= expected_max_bits,
            "k1 has {} bits",
            k1.into_bigint().num_bits()
        );
        assert!(
            k2.into_bigint().num_bits() <= expected_max_bits,
            "k2 has {} bits",
            k2.into_bigint().num_bits()
        );

        let (dec_scr, hints) = hinted_scalar_decomposition(k);
        let scr = script!{
            for hint in hints {
                {hint.push()}
            }
            {is_k1_positive as u32}
            {is_k2_positive as u32}
            {fr_push_not_montgomery(k1)}
            {fr_push_not_montgomery(k2)}
            {fr_push_not_montgomery(k)}
            {dec_scr}
            OP_TRUE
        };

        let res = execute_script(scr);
        assert!(res.final_stack.len() == 1);
        assert!(res.success);
    }

    #[test]
    fn test_hinted_endomorphoism() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (scr, hints) = hinted_endomorphoism(p);
        const LAMBDA: ark_bn254::Fr = MontFp!("21888242871839275217838484774961031246154997185409878258781734729429964517155");
        let lambda_p = (p * LAMBDA).into_affine();

        // phi(p) = lambda * P
        let scrp = script!{
            for hint in hints {
                {hint.push()}
            }
            {fq_push_not_montgomery(p.x)}
            {fq_push_not_montgomery(p.y)}
            {scr}
            {fq_push_not_montgomery(lambda_p.y)}
            {Fq::equalverify(1, 0)}
            {fq_push_not_montgomery(lambda_p.x)}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };

        let res = execute_script(scrp);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

}
