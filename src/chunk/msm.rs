use std::collections::HashMap;

use crate::bn254::utils::fq_push_not_montgomery;
use crate::chunk::primitves::{
    extern_hash_fps, extern_fq_to_nibbles, extern_fr_to_nibbles, unpack_limbs_to_nibbles
};
use crate::chunk::taps::{tup_to_scr, wots_locking_script};
use crate::chunk::wots::{wots_p256_get_pub_key, wots_p160_get_pub_key};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use bitcoin::opcodes::all::OP_ENDIF;
use num_traits::One;

use super::hint_models::HintInHashP;
use super::primitves::hash_fp2;
use super::taps::{HashBytes, Link, Sig};
use super::wots::WOTSPubKey;
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
    pub(crate) hash: HashBytes,
}

impl HintOutMSM {
    pub(crate) fn out(&self) -> HashBytes {
        self.hash
    }
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
) -> (HintOutMSM, Script, bool) {
    const WINDOW_LEN: u8 = 8;
    const MAX_SUPPORTED_PUBS: usize = 3;

    // hint_in
    let mut t = hint_in.t.clone();
    assert!(qs.len() <= MAX_SUPPORTED_PUBS);
    assert_eq!(qs.len(), hint_in.scalars.len());

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
        q = get_byte_mul_g1(hint_in.scalars[qi], WINDOW_LEN, msm_tap_index, *qq);
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
        let tup = (sec_in[i], extern_fr_to_nibbles(hint_in.scalars[i]));
        hash_scalars.push(tup);
    }
    tup.extend_from_slice(&hash_scalars);

    if msm_tap_index != 0 {
        assert!(sec_in.len() == hint_in.scalars.len() + 1);
        tup.push((
            sec_in[sec_in.len() - 1],
            extern_hash_fps(vec![hint_in.t.x, hint_in.t.y], true),
        ))
    }
    let outhash = extern_hash_fps(vec![t.x, t.y], true);
    tup.push((sec_out, outhash));
    let (bc_elems, should_validate) = tup_to_scr(sig, tup);

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

        { bc_elems }
    };
    let hint_out = HintOutMSM { t: t, hash: outhash };

    (hint_out, simulate_stack_input, should_validate)
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
    let pub_ins = 3;
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
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", msk, sec_out));
        pub_scripts.insert(sec_out, pk);
        for j in 0..sec_in.len() {
            let i = &sec_in[j];
            if j == pub_ins as usize {
                let pk = wots_p160_get_pub_key(&format!("{}{:04X}", msk, i));
                pub_scripts.insert(*i, pk);
            } else {
                let pk = wots_p256_get_pub_key(&format!("{}{:04X}", msk, i));
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

        let (aux, stack_data, maybe_wrong) = hint_msm(
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


// Hash P
//vk0: G1Affine
pub(crate) fn tap_hash_p(q: G1Affine) -> Script {
    let (hinted_add_line, _) = hinted_affine_add_line_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );
    let (hinted_line_pt, _) = hinted_check_line_through_point_g1(
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
        ark_bn254::Fq::one(),
    );

    let ops_script = script!{
        //[hinttqa, alpha, bias, tx, ty]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias,tx, ty] 
        { hinted_line_pt.clone() }
        //[hinttqa, alpha, bias, tx, ty

        { Fq2::copy(2)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias]
        {fq_push_not_montgomery(q.x)}
        {fq_push_not_montgomery(q.y)}
        //[hinttqa, alpha, bias, tx, ty, alpha, bias, qx, qy]
        { hinted_line_pt.clone() }

        //[hinttqa, alpha, bias, tx, ty
        {Fq2::copy(0)}
        {Fq2::toaltstack()}
        {Fq::drop()} {Fq::toaltstack()}
        {Fq::roll(1)} {Fq::fromaltstack()}

        // //[hinttqa, alpha, bias, tx]
        {fq_push_not_montgomery(q.x)}
        { hinted_add_line.clone() }

        // Altstack:[identity, gpx, gpy, th]
        //[ntx, nty, tx, ty]

        {Fq2::fromaltstack()}
        { hash_fp2() }
        {Fq::fromaltstack()}
        {Fq::equalverify(1, 0)}
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

pub(crate) fn bitcom_hash_p(
    link_ids: &HashMap<u32, WOTSPubKey>,
    sec_out: Link,
    sec_in: Vec<Link>,
) -> Script {
    assert_eq!(sec_in.len(), 3);

    let bitcom_scr = script! {

        {wots_locking_script(sec_out, link_ids)} // zeroth
        {Fq::toaltstack()}
        {wots_locking_script(sec_in[2], link_ids)} // gp3x // R
        {Fq::toaltstack()}
        {wots_locking_script(sec_in[1], link_ids)} // gp3y
        {Fq::toaltstack()}
        {wots_locking_script(sec_in[0], link_ids)} // msm_P_hash // T
        {Fq::toaltstack()}
        // P + vkY0 ?= gp3

        // Altstack:[identity, gpx, gpy, th]
    };
    bitcom_scr
}

pub(crate) fn hint_hash_p(
    sig: &mut Sig,
    sec_out: Link,
    sec_in: Vec<Link>,
    hint_in: HintInHashP,
) -> (HashBytes, Script, bool) {
    // r (gp3) = t(msm) + q(vk0)
    let (tx, qx, ty, qy) = (hint_in.tx, hint_in.qx, hint_in.ty, hint_in.qy);
    
    let (rx, ry) = (hint_in.rx, hint_in.ry);
    let thash = extern_hash_fps(vec![hint_in.tx, hint_in.ty], false);

    let zero_nib = [0u8;64];

    let mut tups = vec![];
    tups.push((sec_in[0], thash));
    tups.push((sec_in[1], extern_fq_to_nibbles(ry)));
    tups.push((sec_in[2], extern_fq_to_nibbles(rx)));
    tups.push((sec_out, zero_nib));

    let (bc_elems, mut should_validate) = tup_to_scr(sig, tups);
    if bc_elems.len() > 0 {
        should_validate = true;  // intermediate fix to force validate
    }
    let alpha_chord = (ty - qy) / (tx - qx);
    let bias_minus_chord = alpha_chord * tx - ty;
    assert_eq!(alpha_chord * tx - ty, bias_minus_chord);

    let (_, hints_check_chord_t) = hinted_check_line_through_point_g1(tx, alpha_chord, bias_minus_chord);
    let (_, hints_check_chord_q) = hinted_check_line_through_point_g1(qx, alpha_chord, bias_minus_chord);
    let (_, hints_add_line) = hinted_affine_add_line_g1(tx, qx, alpha_chord, bias_minus_chord);


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

        { bc_elems }
    };
    (zero_nib, simulate_stack_input, should_validate)
}


#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{
        bn254::{fq2::Fq2, utils::fr_push_not_montgomery}, chunk::{api::nib_to_byte_array, taps::SigData}, signatures::wots::{wots160, wots256},
    };

    use self::mock::{compile_circuit, generate_proof};

    use super::*;
    use ark_bn254::{Bn254, G1Affine};
    use ark_ff::UniformRand;
    use bitcoin::opcodes::{all::OP_EQUALVERIFY, OP_TRUE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::HintInMSM;

    #[test]
    fn test_try_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);

        let (proof, scalars, vk) = generate_new_mock_proof();
        assert!(scalars.len() == 3);
        let scalars = vec![scalars[2], scalars[1], scalars[0]];
        let qs = vec![
            vk.gamma_abc_g1[3],
            vk.gamma_abc_g1[2],
            vk.gamma_abc_g1[1],
        ];

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



    #[test]
    fn test_tap_hash_p() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1, 2, 3];
        let sec_out = 0;
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);


        let hash_c_scr = tap_hash_p(q);

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        pub_scripts.insert(sec_out, wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, 0)));
        for j in 0..sec_in.len() {
            let i = &sec_in[j];
            if j == 0 {
                let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
                pub_scripts.insert(*i, pk);
            } else {
                let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
                pub_scripts.insert(*i, pk);
            }
        }

        // let sec_out = (sec_out, false);

        let sec_in_arr = vec![(sec_in[0],false), (sec_in[1], true), (sec_in[2], true)];
        let bitcom_scr = bitcom_hash_p(&pub_scripts, (sec_out, false), sec_in_arr.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);

        let r = (t + q).into_affine();

        let thash = extern_hash_fps(vec![t.x, t.y], false);

        let mut sig_cache: HashMap<u32, SigData> = HashMap::new();
        let bal: [u8; 32] = nib_to_byte_array(&thash).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in_arr[0].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in_arr[0].0), &bal)));

        let bal = extern_fq_to_nibbles(r.y);
        let bal: [u8; 32] = nib_to_byte_array(&bal).try_into().unwrap();
        sig_cache.insert(sec_in_arr[1].0, SigData::Sig256(wots256::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in_arr[1].0), &bal)));


        let bal = extern_fq_to_nibbles(r.x);
        let bal: [u8; 32] = nib_to_byte_array(&bal).try_into().unwrap();
        sig_cache.insert(sec_in_arr[2].0, SigData::Sig256(wots256::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in_arr[2].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&[0u8;64]).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_out, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out), &bal)));


        let hint_in = HintInHashP { tx:t.x, qx: q.x, ty: t.y, qy:  q.y, rx: r.x, ry: r.y };
        let mut sig = Sig {
            msk: None,
            cache: sig_cache,
        };
        let (_, simulate_stack_input, maybe_wrong) = hint_hash_p(&mut sig, (sec_out, false), sec_in_arr, hint_in);

        let tap_len = hash_c_scr.len();
        let script = script! {
            {simulate_stack_input}
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



    pub mod mock {
        use ark_bn254::{Bn254, Fr as F};
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ff::AdditiveGroup;
        use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
        use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
        use ark_std::test_rng;
        use rand::{RngCore, SeedableRng};
        use super::*;

        #[derive(Clone)]
        pub struct DummyCircuit {
            pub a: Option<F>, // Private input a
            pub b: Option<F>, // Private input b
            pub c: F,         // Public output: a * b
            pub d: F,         // Public output: a + b
            pub e: F,         // Public output: a - b
        }

        impl ConstraintSynthesizer<F> for DummyCircuit {
            fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                // Allocate private inputs a and b as witnesses
                let a = FpVar::new_witness(cs.clone(), || {
                    self.a.ok_or(SynthesisError::AssignmentMissing)
                })?;
                let b = FpVar::new_witness(cs.clone(), || {
                    self.b.ok_or(SynthesisError::AssignmentMissing)
                })?;

                // Allocate public outputs c, d, and e
                let c = FpVar::new_input(cs.clone(), || Ok(self.c))?;
                let d = FpVar::new_input(cs.clone(), || Ok(self.d))?;
                let e = FpVar::new_input(cs.clone(), || Ok(self.e))?;

                // Enforce the constraints: c = a * b, d = a + b, e = a - b
                let computed_c = &a * &b;
                let computed_d = &a + &b;
                let computed_e = &a - &b;

                computed_c.enforce_equal(&c)?;
                computed_d.enforce_equal(&d)?;
                computed_e.enforce_equal(&e)?;

                Ok(())
            }
        }

        pub fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
            type E = Bn254;
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let circuit = DummyCircuit {
                a: None,
                b: None,
                c: F::ZERO,
                d: F::ZERO,
                e: F::ZERO,
            };
            let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
            (pk, vk)
        }


            pub struct Proof {
                pub proof: ark_groth16::Proof<Bn254>,
                pub public_inputs: Vec<ark_bn254::Fr>,
            }


        pub fn generate_proof() -> Proof {
            let (a, b) = (5, 3);
            let (c, d, e) = (a * b, a + b, a - b);

            let circuit = DummyCircuit {
                a: Some(F::from(a)),
                b: Some(F::from(b)),
                c: F::from(c),
                d: F::from(d),
                e: F::from(e),
            };

            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

            let (pk, _) = compile_circuit();

            let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            let public_inputs = vec![circuit.c, circuit.d, circuit.e];

            Proof {
                proof,
                public_inputs,
            }
        }

    }

    fn generate_new_mock_proof() -> (
        ark_groth16::Proof<Bn254>,
        Vec<ark_bn254::Fr>,
        ark_groth16::VerifyingKey<Bn254>,
    )  {
        let (_, vk) = compile_circuit();
        let proof = generate_proof();
        (
            proof.proof,
            proof.public_inputs,
            vk
        )
    }

}
