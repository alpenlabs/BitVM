use crate::bigint::BigIntImpl;
use crate::bigint::U256;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::bigint_to_u32_limbs;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::*;
use ark_ff::BigInt;
use ark_ff::PrimeField;
use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub enum Hint {
    U32(u32),
    Fq(ark_bn254::Fq),
    Fr(ark_bn254::Fr),
    Hash([u32; 9]),
    U256(num_bigint::BigInt),
    BigIntegerTmulLC1(num_bigint::BigInt),
    BigIntegerTmulLC2(num_bigint::BigInt),
    BigIntegerTmulLC4(num_bigint::BigInt),
}

impl Hint {
    pub fn push(&self) -> Script {
        const K1: (u32, u32) = Fq::bigint_tmul_lc_1();
        const K2: (u32, u32) = Fq::bigint_tmul_lc_2();
        const K4: (u32, u32) = Fq::bigint_tmul_lc_4();
        pub type T1 = BigIntImpl<{ K1.0 }, { K1.1 }>;
        pub type T2 = BigIntImpl<{ K2.0 }, { K2.1 }>;
        pub type T4 = BigIntImpl<{ K4.0 }, { K4.1 }>;
        match self {
            Hint::U32(f)  => script!{
                {*f}
            },
            Hint::Fq(fq) => script! {
                { Fq::push(*fq) }
            },
            Hint::Fr(fr) => script! {
                { Fr::push(*fr) }
            },
            Hint::Hash(hash) => script! {
                for h in hash {
                    {*h}
                }
            },
            Hint::U256(num) => {
                let u32s = bigint_to_u32_limbs(num.clone(), 256);
                script! {
                    { U256::push_u32_le(&u32s) }
                }
            },
            Hint::BigIntegerTmulLC1(a) => script! {
                { T1::push_u32_le(&bigint_to_u32_limbs(a.clone(), T1::N_BITS)) }
            },
            Hint::BigIntegerTmulLC2(a) => script! {
                { T2::push_u32_le(&bigint_to_u32_limbs(a.clone(), T2::N_BITS)) }
            },
            Hint::BigIntegerTmulLC4(a) => script! {
                { T2::push_u32_le(&bigint_to_u32_limbs(a.clone(), T4::N_BITS)) }
            },
        }
    }

    pub fn as_witness(&self) -> Vec<Vec<u8>> {

        
        fn bigint_to_u32_limbs(n: num_bigint::BigInt, n_bits: u32) -> Vec<u32> {
            const LIMB_SIZE: u64 = 29;
            let mut limbs = vec![];
            let mut limb: u32 = 0;
            for i in 0..n_bits as u64 {
                if i > 0 && i % LIMB_SIZE == 0 {
                    limbs.push(limb);
                    limb = 0;
                }
                if n.bit(i) {
                    limb += 1 << (i % LIMB_SIZE);
                }
            }
            limbs.push(limb);
            limbs.reverse();
            limbs
        }

        
        const K1: (u32, u32) = Fq::bigint_tmul_lc_1();
        const K2: (u32, u32) = Fq::bigint_tmul_lc_2();
        const K4: (u32, u32) = Fq::bigint_tmul_lc_4();
        pub type T1 = BigIntImpl<{ K1.0 }, { K1.1 }>;
        pub type T2 = BigIntImpl<{ K2.0 }, { K2.1 }>;
        pub type T4 = BigIntImpl<{ K4.0 }, { K4.1 }>;
        let mut wit = match self {
            Hint::U32(f) => {
                let fu8 = f.to_le_bytes();
                vec![fu8.to_vec()]
            },

            Hint::Fq(fq) => {
                let u32s = bigint_to_u32_limbs(fq.into_bigint().into(), Fq::N_BITS);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::Fr(fr) => {
                let u32s = bigint_to_u32_limbs(fr.into_bigint().into(), Fr::N_BITS);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::Hash(hash) => {
                let u32s_vec = hash.to_vec().iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::U256(num) => {
                let u32s = bigint_to_u32_limbs(num.clone(), 256);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::BigIntegerTmulLC1(a) => {
                let u32s = bigint_to_u32_limbs(a.clone(), T1::N_BITS);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::BigIntegerTmulLC2(a) => {
                let u32s = bigint_to_u32_limbs(a.clone(), T2::N_BITS);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
            Hint::BigIntegerTmulLC4(a) => {
                let u32s = bigint_to_u32_limbs(a.clone(), T4::N_BITS);
                let u32s_vec = u32s.iter().map(|f| f.to_le_bytes().to_vec()).collect();
                u32s_vec
            },
        };
        fn remove_trailing_zeros(mut v: Vec<u8>) -> Vec<u8> {
            while v.last() == Some(&0) {
                v.pop();
            }
            v
        }
        // wit = wit.iter().map(|w| remove_trailing_zeros(w.clone())).collect();
        wit
    }
}

pub fn fq_to_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let mut bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).skip(2).collect();
    bits.reverse();

    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
            let res = chunk.iter().fold(0, |acc, &x| {
                let r = acc + if x { factor } else { 0 };
                factor *= 2;
                r
            });
            res
        })
        .collect()
}


#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, chunker::common::extract_witness_from_stack, execute_raw_script_with_inputs, execute_script, execute_script_with_inputs};

    use super::Hint;


    #[test]
    fn test_serialize() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let fq = ark_bn254::Fr::rand(&mut prng);
        let fqh = Hint::Fr(fq);
        let scr = script!(
            {fqh.push()}
        );

        let res = execute_script(scr);
        let scrs = extract_witness_from_stack(res);
        assert_eq!(scrs, fqh.as_witness());
    }


    #[test]
    fn test_serialize_u2() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let fq = ark_ff::BigInt::<4>::rand(&mut prng).into();
        let fqh = Hint::U256(fq);
        let scr = script!(
            {fqh.push()}
        );
        let scrs = extract_witness_from_stack(execute_script(scr));

        let scrs2 = extract_witness_from_stack(execute_script_with_inputs(script!(), fqh.as_witness()));

        assert_eq!(scrs, scrs2);
    }
}
