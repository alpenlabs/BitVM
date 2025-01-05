use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use bitcoin_script::script;
use crate::treepp::Script;

use super::{curves::G2Affine, fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, utils::{hinted_affine_add_line, hinted_affine_double_line, hinted_check_chord_line, hinted_check_tangent_line, Hint}};

fn split_scalar(window: usize, x0: u64) -> Vec<Vec<u8>> {
    // const scalar
    // convert scalar into bit form or naf form
    // spit out segments
    // Vec<[usize; window]>
    //let x0: u64 = 4965661367192848881;
    //x0.to_bigint()
    fn u64_to_bits(x: u64) -> Vec<u8> {
        let mut bits = Vec::with_capacity(64);
        for i in 0..64 {
            // Shift so that we're checking the (63 - i)-th bit from the right.
            // That puts the most significant bit at i = 0.
            let bit = ((x >> (63 - i)) & 1) as u8;
            if bit == 0 {
                bits.push(0); // dbl
            } else if bit == 1 {
                bits.push(0); // dbl
                bits.push(1); // add
            }
        }
        bits
    }
    let x0_bits: Vec<Vec<u8>> = u64_to_bits(x0).chunks(window as usize).map(|c| c.to_vec()).collect();
    x0_bits
}

fn hinted_check_double_and_add(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine, bits: Vec<u8>) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = vec![];
    let mut acc = t.clone();
    let mut script = script!();
    for bit in bits {
        if bit == 0 {
            let (scr, hint) = hinted_check_double(acc);
            hints.extend_from_slice(&hint);
            script = script.push_script(script!(
                {Fq2::toaltstack()} {Fq2::toaltstack()} // move q to altstack
                {scr}
                {Fq2::fromaltstack()} {Fq2::fromaltstack()} // bring q to altstack
            ).compile());
            acc = (acc + acc).into_affine(); // double
            
        } else if bit == 1 {
            let (scr, hint) = hinted_check_add(acc, q);
            hints.extend_from_slice(&hint);
            script = script.push_script(script!(
                {Fq2::copy(2)} {Fq2::copy(2)}
                {Fq2::toaltstack()} {Fq2::toaltstack()} // move q to altstack
                {scr}
                {Fq2::fromaltstack()} {Fq2::fromaltstack()} // bring q to altstack
            ).compile());
            acc = (acc + q).into_affine();   // add
        }
    }
    // drop q
    script = script.push_script(script!(
        {Fq2::drop()}     
        {Fq2::drop()}
    ).compile());
    (script, hints)
}

fn hinted_check_double(t: ark_bn254::G2Affine) -> (Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let (alpha, bias) = if t_is_zero {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    } else {
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    };

    let (hinted_script1, hint1) = hinted_check_tangent_line(t,alpha, bias);
    let (hinted_script2, hint2) = hinted_affine_double_line(t.x,alpha, bias);

    if !t_is_zero { 
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
    }

    let script = script! {       
        { G2Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
        OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // -bias, ...,  x, y, alpha
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // x, y, alpha, -bias
            { Fq2::copy(2) }                          // x, y, alpha, -bias, alpha
            { Fq2::copy(2) }                          // x, y, alpha, -bias, alpha, -bias
            { Fq2::copy(10) }                          // x, y, alpha, -bias, alpha, -bias, x
            { Fq2::roll(10) }                          // x, alpha, -bias, alpha, -bias, x, y
            { hinted_script1 }                       // x, alpha, -bias, is_tangent_line_correct 
            { Fq2::roll(4) }                          // alpha, -bias, x
            { hinted_script2 }                       // x', y'
        OP_ENDIF
    };
    (script, hints)
}

fn hinted_check_add(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine) -> (Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let q_is_zero = q.is_zero() || (q == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // q is none or Some(0)
    
    let (alpha, bias) = if !t_is_zero && !q_is_zero { // todo: add if t==q and if t == -q
        let alpha = (t.y - q.y) / (t.x - q.x);
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    } else {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    };

    let (hinted_script1, hint1) = hinted_check_chord_line(t, q, alpha, bias); // todo: remove unused arg: bias
    let (hinted_script2, hint2) = hinted_affine_add_line(t.x, q.x, alpha, bias);

    if !t.is_zero() && !q.is_zero() {
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
    }

    let script = script! {        // tx ty qx qy
        { G2Affine::is_zero_keep_element() }
        OP_IF
            { G2Affine::drop() }
        OP_ELSE
            { G2Affine::roll(1) }
            { G2Affine::is_zero_keep_element() }
            OP_IF
                { G2Affine::drop() }
            OP_ELSE                                // qx qy tx ty
                for _ in 0..Fq::N_LIMBS * 2 {
                    OP_DEPTH OP_1SUB OP_ROLL 
                }
                for _ in 0..Fq::N_LIMBS * 2 {
                    OP_DEPTH OP_1SUB OP_ROLL 
                }                                  // qx qy tx ty c3 c4
                { Fq2::copy(2) }
                { Fq2::copy(2) }                    // qx qy tx ty c3 c4 c3 c4
                { Fq2::copy(10) }
                { Fq2::roll(10) }                    // qx qy tx c3 c4 c3 c4 tx ty
                { Fq2::copy(16) }
                { Fq2::roll(16) }                    // qx tx c3 c4 c3 c4 tx ty qx qy
                { hinted_script1 }                 // qx tx c3 c4 0/1
                { Fq2::roll(4) }
                { Fq2::roll(6) }                    // c3 c4 tx qx
                { hinted_script2 }                 // x' y'
            OP_ENDIF
        OP_ENDIF
    };
    (script, hints)
}


fn hinted_msm(scalar: u64, q: ark_bn254::G2Affine, window: usize) -> Vec<(Script, Vec<Hint>)> {
    let scalar_splits = split_scalar(window, scalar);
    let mut acc = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
    let mut chunks = vec![];
    for bits in scalar_splits {
        let chunk = hinted_check_double_and_add(acc, q, bits.clone());
        for bit in &bits {
            if *bit == 0 {
                acc = (acc + acc).into_affine();
            } else if *bit == 1 {
                acc = (acc + q).into_affine();
            }
        }
        chunks.push(chunk);
    }
    chunks
}

#[cfg(test)]
mod test {
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fq2::Fq2, g2_subgroup_check::{hinted_check_add, hinted_check_double, hinted_check_double_and_add}, utils::{fq2_push_not_montgomery, Hint}}, execute_script, execute_script_without_stack_limit, treepp};

    use super::{hinted_msm, split_scalar};

    #[test]
    fn test_g2_affine_hinted_check_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_add, hints) = hinted_check_add(t, q);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { hinted_check_add.clone() }
            // [x']
            { fq2_push_not_montgomery(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push_not_montgomery(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_g2_affine_hinted_check_double() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - t.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_double, hints) = hinted_check_double(t);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { hinted_check_double.clone() }
            { fq2_push_not_montgomery(y) }
            { Fq2::equalverify() }
            { fq2_push_not_montgomery(x) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_check_double: {} @ {} stack",
            hinted_check_double.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_g2_affine_hinted_check_double_and_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let bits = vec![0, 1, 0, 1];
        let mut acc = t.clone();
        for bit in &bits {
            if *bit == 0 {
                acc = (acc + acc).into_affine();
            } else if *bit == 1 {
                acc = (acc + q).into_affine();
            }
        }

        let (hinted_check_dbl_add, hints) = hinted_check_double_and_add(t, q, bits);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { hinted_check_dbl_add.clone() }
            // [x']
            { fq2_push_not_montgomery(acc.y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push_not_montgomery(acc.x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script_without_stack_limit(script);
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_check_dbl_add: {} @ {} stack",
            hinted_check_dbl_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_hinted_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let scalar = 4965661367192848881;
        let window = 4;
        let chunks = hinted_msm(scalar, q, window);
        let chunk_hints: Vec<Vec<Hint>> = chunks.iter().map(|c| c.1.clone()).collect();
        let chunk_scripts: Vec<treepp::Script> = chunks.iter().map(|c| c.0.clone()).collect();
        
        let scalar_splits = split_scalar(window, scalar);
        let mut accs = vec![];
        let mut acc = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
        for bits in &scalar_splits {
            for bit in bits {
                if *bit == 0 {
                    acc = (acc + acc).into_affine();
                } else if *bit == 1 {
                    acc = (acc + q).into_affine();
                }
            }
            accs.push(acc);
        }
        let expected = (q * ark_bn254::Fr::from(scalar)).into_affine();
        assert_eq!(expected, accs[accs.len()-1]);

        for i in 0..chunk_scripts.len() {
            let scr = script!(
                for hint in &chunk_hints[i] {
                    {hint.push()}
                }
                // [t]
                if i == 0 {
                    { fq2_push_not_montgomery(ark_bn254::Fq2::ZERO) }
                    { fq2_push_not_montgomery(ark_bn254::Fq2::ZERO) }
                } else {
                    { fq2_push_not_montgomery(accs[i-1].x) }
                    { fq2_push_not_montgomery(accs[i-1].y) }
                }
                // [t, q]
                { fq2_push_not_montgomery(q.x) }
                { fq2_push_not_montgomery(q.y) }
                { chunk_scripts[i].clone() }
                // [nt]
                { fq2_push_not_montgomery(accs[i].y) }
                { Fq2::equalverify() }
                { fq2_push_not_montgomery(accs[i].x) }
                { Fq2::equalverify() }
                OP_TRUE
            );
            let exec_result = execute_script_without_stack_limit(scr);
            assert!(exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            println!(
                "hinted_msm {}: {} @ {} stack",
                i,
                chunk_scripts[i].len(),
                exec_result.stats.max_nb_stack_items
            );
        }

        
    }

}