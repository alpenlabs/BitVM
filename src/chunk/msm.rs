use std::collections::HashMap;

use crate::bn254::utils::fq_push_not_montgomery;
use crate::chunk::primitves::{
    emulate_extern_hash_fps, emulate_fr_to_nibbles, unpack_limbs_to_nibbles,
};
use crate::chunk::taps::{tup_to_scr, wots_locking_script};
use crate::signatures::winternitz_compact::{self, WOTSPubKey};
use crate::signatures::winternitz_compact_hash;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use bitcoin::opcodes::all::{OP_DROP, OP_ELSE, OP_ENDIF, OP_NUMEQUAL, OP_VERIFY};
use num_traits::One;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::primitves::hash_fp2;
use super::taps::{HashBytes, Link, Sig};
use crate::bn254::fq2::Fq2;
use crate::bn254::utils::Hint;

pub(crate) fn tap_msm(window: usize, msm_tap_index: usize, qs: Vec<ark_bn254::G1Affine>) -> Script {
    assert!(qs.len() > 0);
    let (hinted_check_tangent, _) = hinted_check_line_through_point_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_double_line, _) = hinted_affine_double_line_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );

    let (hinted_check_chord_t, _) = hinted_check_line_through_point_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_check_chord_q, _) = hinted_check_line_through_point_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_add_line, _) = hinted_affine_add_line_g1(
        ark_bn254::Fq::one(),
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
            {Fq::drop()}
            {Fq::toaltstack()}
            {Fq::roll(1)}
            {Fq::fromaltstack()}
            {hinted_double_line.clone()}
        }
    };

    let ops_script = script! {
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
        }

    };

    let hash_script = script! {
        // [t, nt]
        {Fq2::roll(2)} // [nt, t]
        {msm_tap_index} 0 OP_NUMEQUAL
        OP_IF
            {Fq2::drop()}
        OP_ELSE
            {hash_fp2()} // [nt, t_hash]
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

#[derive(Debug, Clone)]
pub(crate) struct HintInMSM {
    pub(crate) t: ark_bn254::G1Affine,
    pub(crate) scalars: Vec<ark_bn254::Fr>,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutMSM {
    pub(crate) t: ark_bn254::G1Affine,
    pub(crate) hasht: HashBytes,
}

fn hinted_affine_add_line_g1(
    tx: ark_bn254::Fq,
    qx: ark_bn254::Fq,
    c3: ark_bn254::Fq,
    c4: ark_bn254::Fq,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hsc, hts) = Fq::hinted_square(c3);
    let (hinted_script1, hint1) = Fq::hinted_mul(2, c3, 0, c3.square() - tx - qx);

    let script_lines = vec![
        // [b, a, T.x, Q.x]
        Fq::neg(0),
        // [T.x, -Q.x]
        Fq::roll(1),
        // [-Q.x, T.x]
        Fq::neg(0),
        // [-T.x - Q.x]
        Fq::add(1, 0),
        // [-T.x - Q.x]
        Fq::roll(1),
        Fq::copy(0),
        // [-T.x - Q.x, alpha, alpha]
        hsc,
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        Fq::add(2, 0),
        // [b, alpha, x']
        Fq::copy(0),
        // [b, alpha, x', x']
        hinted_script1,
        // [b, x', alpha * x']
        Fq::neg(0),
        // [b, x', -alpha * x']
        // fq2_push_not_montgomery(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        Fq::add(2, 0),
        // [x', y']
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hts);
    hints.extend(hint1);

    (script, hints)
}

fn hinted_affine_double_line_g1(
    tx: ark_bn254::Fq,
    c3: ark_bn254::Fq,
    c4: ark_bn254::Fq,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hsc, hts) = Fq::hinted_square(c3);
    let (hinted_script1, hint1) = Fq::hinted_mul(2, c3, 0, c3.square() - tx - tx);

    let script_lines = vec![
        Fq::double(0),
        Fq::neg(0),
        // [bias, alpha, - 2 * T.x]
        Fq::roll(1),
        Fq::copy(0),
        // [bias, - 2 * T.x, alpha, alpha]
        hsc,
        // fq2_push_not_montgomery(c3.square()),
        // [bias, - 2 * T.x, alpha, alpha^2]
        Fq::add(2, 0),
        // [bias, alpha, x']
        Fq::copy(0),
        // [bias, alpha, x', x']
        hinted_script1,
        // [bias, x', alpha * x']
        Fq::neg(0),
        // [bias, x', -alpha * x']
        Fq::add(2, 0),
        // [x', y']
    ];

    let mut script = script! {};

    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hts);
    hints.extend(hint1);

    (script, hints)
}

fn hinted_check_line_through_point_g1(
    x: ark_bn254::Fq,
    c3: ark_bn254::Fq,
    c4: ark_bn254::Fq,
) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();

    let (hinted_script1, hint1) = Fq::hinted_mul(1, x, 0, c3);

    let script_lines = vec![
        // [alpha, bias, x, y ]
        Fq::roll(1),
        // [alpha, bias, y, x ]
        Fq::roll(3),
        // [bias, y, x, alpha ]
        hinted_script1,
        // [bias, y, alpha * x]
        Fq::neg(0),
        // [bias, y, -alpha * x]
        Fq::add(1, 0),
        // [bias, y - alpha * x]
        Fq::add(1, 0),
        // [y - alpha * x - bias]
        Fq::push_zero(),
        // [y - alpha * x - bias, 0]
        Fq::equalverify(1, 0),
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}

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
    sig: &mut Sig,
    sec_out: Link,
    sec_in: Vec<Link>,
    hint_in: HintInMSM,
    msm_tap_index: usize,
    qs: Vec<ark_bn254::G1Affine>,
) -> (HintOutMSM, Script) {
    const window: u8 = 8;
    const num_pubs: usize = 4;

    // hint_in
    let mut t = hint_in.t.clone();
    assert!(qs.len() <= num_pubs);
    assert_eq!(qs.len(), hint_in.scalars.len());

    // constants
    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;

    let mut aux_tangent = vec![];

    let mut hints_tangent: Vec<Hint> = Vec::new();

    if t.y != ark_bn254::Fq::ZERO {
        for _ in 0..window {
            let mut alpha = t.x.square();
            alpha /= t.y;
            alpha *= three_div_two;
            let bias_minus = alpha * t.x - t.y;
            let new_tx = alpha.square() - t.x.double();
            let new_ty = bias_minus - alpha * new_tx;

            let (_, hints_check_tangent) =
                hinted_check_line_through_point_g1(t.x, alpha, bias_minus);
            let (_, hints_double_line) = hinted_affine_double_line_g1(t.x, alpha, bias_minus);

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
        q = get_byte_mul_g1(hint_in.scalars[qi], window, msm_tap_index, *qq);
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
                hinted_check_line_through_point_g1(t.x, alpha, bias_minus);
            let (_, hints_check_chord_q) =
                hinted_check_line_through_point_g1(q.x, alpha, bias_minus);
            let (_, hints_add_line) = hinted_affine_add_line_g1(t.x, q.x, alpha, bias_minus);

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

    let mut tup = vec![];

    let mut hash_scalars = vec![];
    for i in 0..hint_in.scalars.len() {
        let tup = (sec_in[i], emulate_fr_to_nibbles(hint_in.scalars[i]));
        hash_scalars.push(tup);
    }
    tup.extend_from_slice(&hash_scalars);

    if msm_tap_index != 0 {
        assert!(sec_in.len() == hint_in.scalars.len() + 1);
        tup.push((
            sec_in[sec_in.len() - 1],
            emulate_extern_hash_fps(vec![hint_in.t.x, hint_in.t.y], true),
        ))
    }
    let outhash = emulate_extern_hash_fps(vec![t.x, t.y], true);
    tup.push((sec_out, outhash));
    let bc_elems = tup_to_scr(sig, tup);

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
        {fq_push_not_montgomery(hint_in.t.x)}
        {fq_push_not_montgomery(hint_in.t.y)}

        for bc in bc_elems {
            {bc}
        }
    };

    let hint_out = HintOutMSM { t, hasht: outhash };

    (hint_out, simulate_stack_input)
}

pub(crate) fn bitcom_msm(
    link_ids: &HashMap<u32, WOTSPubKey>,
    sec_out: Link,
    sec_in: Vec<Link>,
) -> Script {
    // if i == 0, sec_in.len() == num_pubs
    // if i > 0, sec_in.len() == num_pubs + 1
    script! {
        {wots_locking_script(sec_out, link_ids)} // hash_acc_out
        {Fq::toaltstack()}
        for i in 0..sec_in.len() { // scalars, hash_acc_in
            {wots_locking_script(sec_in[sec_in.len()-1-i], link_ids)}
            {Fq::toaltstack()}
        }
    }
    // altstack: [hash_acc_out, hash_acc_in, k2, k1, k0]
    // stack: []
}

pub fn try_msm(qs: Vec<ark_bn254::G1Affine>, scalars: Vec<ark_bn254::Fr>) {
    // constants
    let num_bits: usize = 256;
    let window = 8;
    let pub_ins = 2;
    let msk = "b138982ce17ac813d505b5b40b665d404e9528e7";
    let mut sec_in: Vec<u32> = (0..pub_ins).collect();
    let mut sec_out = pub_ins;
    let mut sig = Sig {
        msk: Some(msk),
        cache: HashMap::new(),
    };
    let qs: Vec<G1Affine> = qs;
    // run time
    let mut hint_in = HintInMSM {
        t: G1Affine::identity(),
        scalars: scalars,
    };

    for i in 0..num_bits / window {
        println!("index {:?}", i);
        if i == 1 {
            sec_in.push(sec_out);
        } else if i > 1 {
            sec_in.pop();
            sec_in.push(sec_out);
        }
        sec_out = sec_in.last().unwrap() + 1;
        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = winternitz_compact_hash::get_pub_key(&format!("{}{:04X}", msk, sec_out));
        pub_scripts.insert(sec_out, pk);
        for j in 0..sec_in.len() {
            let i = &sec_in[j];
            if j == pub_ins as usize {
                let pk = winternitz_compact_hash::get_pub_key(&format!("{}{:04X}", msk, i));
                pub_scripts.insert(*i, pk);
            } else {
                let pk = winternitz_compact::get_pub_key(&format!("{}{:04X}", msk, i));
                pub_scripts.insert(*i, pk);
            }
        }
        let msec_out = (sec_out, false);
        let mut msec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();
        if msec_in.len() == pub_ins as usize + 1 {
            let last = msec_in.pop().unwrap();
            msec_in.push((last.0, false));
        }
        let bitcomms_tapscript = bitcom_msm(&pub_scripts, msec_out, msec_in.clone());
        let msm_ops = tap_msm(window, i, qs.clone());

        let (aux, stack_data) = hint_msm(
            &mut sig,
            msec_out,
            msec_in.clone(),
            hint_in.clone(),
            i as usize,
            qs.clone(),
        );

        let script = script! {
            {stack_data}
            {bitcomms_tapscript}
            {msm_ops}
        };
        println!("script len {:?}", script.len());
        hint_in.t = aux.t;
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!("ts len {}", exec_result.stats.max_nb_stack_items);
        if i == num_bits / window - 1 {
            println!(
                "check valid {:?}",
                qs[0] * hint_in.scalars[0] + qs[1] * hint_in.scalars[1] == aux.t
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{
        bn254::{fq2::Fq2, utils::fr_push_not_montgomery},
        signatures::{winternitz_compact, winternitz_compact_hash},
    };

    use super::*;
    use ark_bn254::G1Affine;
    use ark_ff::UniformRand;
    use bitcoin::opcodes::{all::OP_EQUALVERIFY, OP_TRUE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::HintInMSM;

    #[test]
    fn test_try_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        let qs = vec![
            ark_bn254::G1Affine::rand(&mut prng),
            ark_bn254::G1Affine::rand(&mut prng),
        ];
        let scalars = vec![ark_bn254::Fr::rand(&mut prng), ark_bn254::Fr::ONE];
        try_msm(qs, scalars);
    }

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

        let (hinted_check_line, hints) = hinted_check_line_through_point_g1(t.x, alpha, bias_minus);
        let (hinted_double_line, hintsd) = hinted_affine_double_line_g1(t.x, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(alpha)}
            {fq_push_not_montgomery(bias_minus)}
            { fq_push_not_montgomery(t.x) }
            { fq_push_not_montgomery(t.y) }
            { hinted_check_line.clone() }
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
            {fq_push_not_montgomery(bias_minus)}
            {fq_push_not_montgomery(alpha)}
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
        let (hinted_add_line, hints) = hinted_affine_add_line_g1(t.x, q.x, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {fq_push_not_montgomery(bias_minus)}
            {fq_push_not_montgomery(alpha)}
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
}
