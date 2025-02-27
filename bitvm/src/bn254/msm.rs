use std::str::FromStr;

use super::utils::Hint;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::{g1::G1Affine, fr::Fr};
use crate::treepp::*;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField};
use std::ops::{AddAssign, Div, Neg, Rem};
use num_traits::Signed;

pub fn hinted_msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    println!("use hinted_msm_with_constant_bases_affine");
    assert_eq!(bases.len(), scalars.len());

    let mut hints = Vec::new();

    let mut trivial_bases = vec![];
    let mut msm_bases = vec![];
    let mut msm_scalars = vec![];
    let mut msm_acc = ark_bn254::G1Affine::identity();
    for (itr, s) in scalars.iter().enumerate() {
        if *s == ark_bn254::Fr::ONE {
            trivial_bases.push(bases[itr]);
        } else {
            msm_bases.push(bases[itr]);
            msm_scalars.push(*s);
            msm_acc = (msm_acc + (bases[itr] * *s).into_affine()).into_affine();
        }
    }    

    // parameters
    let mut window = 4;
    if msm_scalars.len() == 1 {
        window = 7;
    } else if msm_scalars.len() == 2 {
        window = 5;
    }

    // MSM
    let mut acc = ark_bn254::G1Affine::zero();
    let msm_chunks = G1Affine::hinted_scalar_mul_by_constant_g1(
        msm_scalars.clone(),
        msm_bases.clone(),
        window,
    );
    let msm_chunk_hints: Vec<Hint> = msm_chunks.iter().flat_map(|f| f.2.clone()).collect();
    let msm_chunk_scripts: Vec<Script> = msm_chunks.iter().map(|f| f.1.clone()).collect();
    let msm_chunk_results: Vec<ark_bn254::G1Affine> = msm_chunks.iter().map(|f| f.0).collect();
    hints.extend_from_slice(&msm_chunk_hints);

    acc = (acc + msm_acc).into_affine();

    let mut dec_hints = vec![];
    msm_scalars.iter().for_each(|s| {
        let ((s0, k0), (s1, k1)) = G1Affine::calculate_scalar_decomposition(*s);
        dec_hints.push(Hint::U32(s0 as u32));
        dec_hints.push(Hint::Fr(k0));
        dec_hints.push(Hint::U32(s1 as u32));
        dec_hints.push(Hint::Fr(k1));
    });

    // Additions
    let mut add_scripts = Vec::new();
    for i in 0..trivial_bases.len() {
        // check coeffs before using
        let (add_script, hint) =
            G1Affine::hinted_check_add(acc, trivial_bases[i]); // outer_coeffs[i - 1].1
        add_scripts.push(add_script);
        hints.extend(hint);
        acc = (acc + trivial_bases[i]).into_affine();
    }

    // Gather scripts
    let script = script! {
        for i in 0..msm_chunk_scripts.len() {
            // G1Acc preimage
            if i == 0 {
                {G1Affine::push( ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO))}
            } else {
                {G1Affine::push(msm_chunk_results[i-1])}
            }

            // Scalar_i: groth16 public inputs bitcommited input irl
            for msm_scalar in &msm_scalars {
                {Fr::push(*msm_scalar)}
            }
            for h in &dec_hints {
                {h.push()}
            }
            // [ScalarDecomposition_0, ScalarDecomposition_1,.., ScalarDecomposition_i,    G1Acc, Scalar_0, Scalar_1,..Scalar_i, ]
            {msm_chunk_scripts[i].clone()}

            {G1Affine::push(msm_chunk_results[i])}
            {G1Affine::equalverify()}
        }
        {G1Affine::push(msm_chunk_results[msm_chunk_results.len()-1])}
        // tx, ty
        for i in 0..add_scripts.len() {
            {G1Affine::push(trivial_bases[i])}
            {add_scripts[i].clone()}
        }
    };
    //println!("msm is divided into {} chunks ", msm_scripts.len() + add_scripts.len());

    (script, hints)
    // into_affine involving extreem expensive field inversion, X/Z^2 and Y/Z^3, fortunately there's no need to do into_affine any more here
}


pub(crate) struct ScalarDecomposition {
    s0: ark_bn254::Fr,
    k0: ark_bn254::Fr,
    s1: ark_bn254::Fr,
    k1: ark_bn254::Fr
}

pub(crate) fn calculate_scalar_decomposition(
    k: ark_bn254::Fr,
) -> ScalarDecomposition {
    let scalar: num_bigint::BigInt = k.into_bigint().into();

    let scalar_decomp_coeffs: [(bool, num_bigint::BigUint); 4] = [
        (false, num_bigint::BigUint::from_str("147946756881789319000765030803803410728").unwrap()),
        (true, num_bigint::BigUint::from_str("9931322734385697763").unwrap()),
        (false, num_bigint::BigUint::from_str("9931322734385697763").unwrap()),
        (false, num_bigint::BigUint::from_str("147946756881789319010696353538189108491").unwrap()),
    ];
    
    let coeff_bigints: [num_bigint::BigInt; 4] = scalar_decomp_coeffs.map(|x| {
        num_bigint::BigInt::from_biguint(if x.0 { num_bigint::Sign::Plus } else { num_bigint::Sign::Minus }, x.1)
    });

    let [n11, n12, n21, n22] = coeff_bigints;

    let r = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, num_bigint::BigUint::from(ark_bn254::Fr::MODULUS));

    // beta = vector([k,0]) * self.curve.N_inv
    // The inverse of N is 1/r * Matrix([[n22, -n12], [-n21, n11]]).
    // so β = (k*n22, -k*n12)/r

    let beta_1 = {
        let mut div = (&scalar * &n22).div(&r);
        let rem = (&scalar * &n22).rem(&r);
        if (&rem + &rem) > r {
            div.add_assign(num_bigint::BigInt::one());
        }
        div
    };
    let beta_2 = {
        let mut div = (&scalar * &n12.clone().neg()).div(&r);
        let rem = (&scalar * &n12.clone().neg()).rem(&r);
        if (&rem + &rem) > r {
            div.add_assign(num_bigint::BigInt::one());
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
    let k1_abs = num_bigint::BigUint::try_from(k1.abs()).unwrap();

    // k2
    let k2 = -b2;
    let k2_abs = num_bigint::BigUint::try_from(k2.abs()).unwrap();

    let k1signr = k1.sign();
    let k2signr = k2.sign();


    let mut k1sign = ark_bn254::Fr::ONE;
    if k1signr == num_bigint::Sign::Minus {
        k1sign = ark_bn254::Fr::ZERO;
    }

    let mut k2sign = ark_bn254::Fr::ONE;
    if k2signr == num_bigint::Sign::Minus {
        k2sign = ark_bn254::Fr::ZERO;
    }

    ScalarDecomposition {
        s0: k1sign,
        k0: ark_bn254::Fr::from(k1_abs),
        s1: k2sign,
        k1: ark_bn254::Fr::from(k2_abs)
    }
}


fn hinted_fr_mul_by_constant(a: ark_bn254::Fr, constant: &ark_bn254::Fr) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let x = num_bigint::BigInt::from_str(&a.to_string()).unwrap();
    let y = num_bigint::BigInt::from_str(&constant.to_string()).unwrap();
    let modulus = &Fr::modulus_as_bigint();
    let q = (x * y) / modulus;

    let script = script! {
        for _ in 0..Fr::N_LIMBS {
            OP_DEPTH OP_1SUB OP_ROLL // hints
        }
        { Fr::roll(1) }
        { Fr::push(*constant) }
        { Fr::tmul() }
    };
    hints.push(Hint::BigIntegerTmulLC1(q));
    (script, hints)
}

fn verify_glv_scalar_decomposition_is_valid(k: ark_bn254::Fr) -> (Script, Vec<Hint>) {
    let lambda: ark_bn254::Fr = ark_bn254::Fr::from(num_bigint::BigUint::from_str("21888242871839275217838484774961031246154997185409878258781734729429964517155").unwrap());
    let decomposition = calculate_scalar_decomposition(k);
    let k1 = decomposition.k1;
    let (mul_scr, mul_hints) = hinted_fr_mul_by_constant(k1, &lambda);
    let scr = script!{
        // [s0, k0, s1, k1, k]
        {Fr::toaltstack()}
        // [s0, k0, s1, k1] [k]
        {Fr::copy(0)}
        {mul_scr}
        // [s0, k0, s1, k1, k1.l] [k]
        {Fr::copy(2)}
        // [s0, k0, s1, k1, k1.l, s1] [k]
        {Fr::is_zero(0)}
        OP_IF
            {Fr::neg(0)}
        OP_ENDIF
        // [s0, k0, s1, k1, s1.k1.l] [k]
        {Fr::toaltstack()}
        // [s0, k0, s1, k1] [k, s1.k1.l]
        {Fr::copy(2)}
        // [s0, k0, s1, k1, k0] [k, s1.k1.l]
        {Fr::copy(4)}
        // [s0, k0, s1, k1, k0, s0] [k, s1.k1.l]
        {Fr::is_zero(0)}
        OP_IF
            {Fr::neg(0)}
        OP_ENDIF
        // [s0, k0, s1, k1, s0.k0] [k, s1.k1.l]
        {Fr::fromaltstack()}
        // [s0, k0, s1, k1, s0.k0, s1.k1.l] [k]
        {Fr::add(1, 0)}
        // [s0, k0, s1, k1, k'] [k]
        {Fr::fromaltstack()}
        {Fr::equal(1, 0)}
    };
    (scr, mul_hints)
}



#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::g1::G1Affine;
    use crate::execute_script_without_stack_limit;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_hinted_msm_with_constant_bases_affine_script() {
        let n = 2;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases_affine(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            for hint in hints {
                { hint.push() }
            } 

            { msm.clone() }
            { G1Affine::push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        assert!(exec_result.success);
    }



    #[test]
    fn test_hinted_scalar_decomposition() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let lambda: ark_bn254::Fr = ark_bn254::Fr::from(num_bigint::BigUint::from_str("21888242871839275217838484774961031246154997185409878258781734729429964517155").unwrap());
        let k = ark_bn254::Fr::rand(&mut prng);

        let dec = calculate_scalar_decomposition(k);
        let (is_s0_positive, is_s1_positive) = (dec.s0 == ark_bn254::Fr::ONE, dec.s1 == ark_bn254::Fr::ONE);
        let (k0, k1) = (dec.k0, dec.k1);

        if is_s0_positive && is_s1_positive {
            assert_eq!(k0 + k1 * lambda, k);
        }
        if is_s0_positive && !is_s1_positive {
            assert_eq!(k0 - k1 * lambda, k);
        }
        if !is_s0_positive && is_s1_positive {
            assert_eq!(-k0 + k1 * lambda, k);
        }
        if !is_s0_positive && !is_s1_positive {
            assert_eq!(-k0 - k1 * lambda, k);
        }
        // check if k1 and k2 are indeed small.
        let expected_max_bits = (ark_bn254::Fr::MODULUS_BIT_SIZE + 1) / 2;
        assert!(
            k0.into_bigint().num_bits() <= expected_max_bits,
            "k1 has {} bits",
            k0.into_bigint().num_bits()
        );
        assert!(
            k1.into_bigint().num_bits() <= expected_max_bits,
            "k2 has {} bits",
            k1.into_bigint().num_bits()
        );

        let (dec_scr, hints) = verify_glv_scalar_decomposition_is_valid(k);
        let scr = script!{
            for hint in hints {
                {hint.push()}
            }
            for v in vec![dec.s0, dec.k0, dec.s1, dec.k1, k] {
                {Fr::push(v)}
            }
            {dec_scr}
            OP_VERIFY
            for v in vec![dec.s0, dec.k0, dec.s1, dec.k1].iter().rev() {
                {Fr::push(*v)}
                {Fr::equalverify(1, 0)}
            }
            OP_TRUE
        };

        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("max stack {:?}", res.stats.max_nb_stack_items);
        assert!(res.final_stack.len() == 1);
        assert!(res.success);
    }


}
