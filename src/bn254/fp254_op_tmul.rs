use crate::{bigint::BigIntImpl, treepp::*};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use std::str::FromStr;

fn limb_doubling_initial_carry() -> Script {
    script! {
        OP_SWAP // {base} {limb}
        { crate::pseudo::OP_2MUL() } // {base} {2*limb}
        OP_2DUP // {base} {2*limb} {base} {2*limb}
        OP_LESSTHANOREQUAL // {base} {2*limb} {base<=2*limb}
        OP_TUCK // {base} {base<=2*limb} {2*limb} {base<=2*limb}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_doubling_step() -> Script {
    script! {
        OP_ROT // {base} {carry} {limb}
        { crate::pseudo::OP_2MUL() } // {base} {carry} {2*limb}
        OP_ADD // {base} {2*limb + carry}
        OP_2DUP // {base} {2*limb + carry} {base} {2*limb + carry}
        OP_LESSTHANOREQUAL // {base} {2*limb + carry} {base<=2*limb + carry}
        OP_TUCK // {base} {base<=2*limb+carry} {2*limb+carry} {base<=2*limb+carry}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_doubling_nocarry(head_offset: u32) -> Script {
    script! {
        OP_SWAP // {carry} {limb}
        { crate::pseudo::OP_2MUL() } // {carry} {2*limb}
        OP_ADD // {carry + 2*limb}
        // The rest is calculating carry + 2*limb - head_offset if carry+2*limb exceeds the head_offset
        { head_offset } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    }
}

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    // double the item on top of the stack
    pub fn dbl() -> Script {
        script! {
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            limb_doubling_initial_carry OP_TOALTSTACK

            for _ in 0..Self::N_LIMBS - 2 {
                // Since we have {limb} {base} {carry} in the stack, we need
                // to double the limb and add an old carry to it.
                limb_doubling_step OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            { limb_doubling_nocarry(Self::HEAD_OFFSET) } // Calculating {2*limb+carry}, ensuring it does not exceed the head size

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn stack_copy() -> Script {
        script! {
            OP_DUP
            {crate::pseudo::OP_4MUL()}
            {crate::pseudo::OP_2MUL()} // Multiplying depth by 8
            OP_ADD // Adding depth to 8*depth to get 9*depth
            { Self::N_LIMBS }
            OP_ADD
            for _ in 0..Self::N_LIMBS - 1 {
                OP_DUP OP_PICK OP_SWAP
            }
            OP_1SUB OP_PICK
        }
    }

    pub fn is_negative(depth: u32) -> Script {
        script! {
            { (1 + depth) * Self::N_LIMBS - 1 } OP_PICK
            { Self::HEAD_OFFSET >> 1 }
            OP_GREATERTHANOREQUAL
        }
    }

    pub fn is_positive(depth: u32) -> Script {
        script! {
            { (1 + depth) * Self::N_LIMBS - 1 } OP_PICK
            { Self::HEAD_OFFSET >> 1 }
            OP_LESSTHAN
        }
    }

    // resizing positive numbers; does not work for negative
    pub fn resize<const T_BITS: u32>() -> Script {
        let n_limbs_self = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
        let n_limbs_target = (T_BITS + LIMB_SIZE - 1) / LIMB_SIZE;

        if n_limbs_target == n_limbs_self {
            return script! {};
        } else if n_limbs_target > n_limbs_self {
            let n_limbs_to_add = n_limbs_target - n_limbs_self;
            script! {
                if n_limbs_to_add > 0 {
                    {0} {crate::pseudo::OP_NDUP((n_limbs_to_add - 1) as usize)} // Pushing zeros to the stack
                }
                for _ in 0..n_limbs_self {
                    { n_limbs_target - 1 } OP_ROLL
                }
            }
        } else {
            let n_limbs_to_remove = n_limbs_self - n_limbs_target;
            script! {
                for _ in 0..n_limbs_to_remove {
                    { n_limbs_target } OP_ROLL OP_DROP
                }
            }
        }
    }
}

// Finite field multiplication impl
pub struct Fq<const N_BITS: u32, const LIMB_SIZE: u32, const VAR_WIDTH: u32, const MOD_WIDTH: u32>
{}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const VAR_WIDTH: u32, const MOD_WIDTH: u32>
    Fq<N_BITS, LIMB_SIZE, VAR_WIDTH, MOD_WIDTH>
{
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;

    // N_BITS for the extended number used during intermediate computation
    pub const EXT_N_BITS: u32 = {
        let n_bits_mod_width = ((N_BITS + MOD_WIDTH - 1) / MOD_WIDTH) * MOD_WIDTH;
        let n_bits_var_width = ((N_BITS + VAR_WIDTH - 1) / VAR_WIDTH) * VAR_WIDTH;
        let mut u = n_bits_mod_width;
        if n_bits_var_width > u {
            u = n_bits_var_width;
        }
        while !(u % MOD_WIDTH == 0 && u % VAR_WIDTH == 0) {
            u += 1;
        }
        u
    };

    // pre-computed lookup table allows us to skip initial few doublings
    pub const EXT_N_BITS_SKIP: u32 = {
        if MOD_WIDTH < VAR_WIDTH {
            MOD_WIDTH
        } else {
            VAR_WIDTH
        }
    };

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type T = LookupTable<{ Self::EXT_N_BITS }, LIMB_SIZE> where [(); { Self::EXT_N_BITS } as usize]:;

    pub fn modulus() -> BigUint {
        BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .expect("modulus: should not fail")
    }

    fn get_mod_window(index: u32) -> u32 {
        let n_window = Self::EXT_N_BITS / MOD_WIDTH;
        let shift_by = MOD_WIDTH * (n_window - index - 1);
        let bit_mask = BigUint::from_i32((1 << MOD_WIDTH) - 1).unwrap() << shift_by;
        ((Self::modulus() & bit_mask) >> shift_by).to_u32().unwrap()
    }

    fn get_var_window_script_generator() -> impl FnMut() -> Script
    where
        [(); { Self::EXT_N_BITS } as usize]:,
    {
        let n_window = Self::EXT_N_BITS / VAR_WIDTH;
        let limb_size = Self::LIMB_SIZE;

        let mut iter = n_window + 1;

        move || {
            let n_limbs = Self::T::W::N_LIMBS;

            let stack_top = n_limbs;

            iter -= 1;

            let s_bit = iter * VAR_WIDTH - 1; // start bit
            let e_bit = (iter - 1) * VAR_WIDTH; // end bit

            let s_limb = s_bit / limb_size; // start bit limb
            let e_limb = e_bit / limb_size; // end bit limb

            script! {
                { 0 }
                if iter == n_window { // initialize accumulator to track reduced limb

                    { stack_top + s_limb + 1 } OP_PICK

                } else if (s_bit + 1) % limb_size == 0  { // drop current and initialize next accumulator

                    OP_FROMALTSTACK OP_DROP
                    { stack_top + s_limb + 1 } OP_PICK

                } else {

                    OP_FROMALTSTACK // load accumulator from altstack
                }
                for i in 0..VAR_WIDTH {
                    if s_limb > e_limb {
                        if i % limb_size == (s_bit % limb_size) + 1 {
                            // window is split between multiple limbs
                            OP_DROP
                            { stack_top + e_limb + 1 } OP_PICK
                        }
                    }
                    OP_TUCK
                    { (1 << ((s_bit - i) % limb_size)) - 1 }
                    OP_GREATERTHAN
                    OP_TUCK
                    OP_ADD
                    if i < VAR_WIDTH - 1 {
                        { crate::pseudo::OP_2MUL() }
                    }
                    OP_ROT OP_ROT
                    OP_IF
                        { 1 << ((s_bit - i) % limb_size) }
                        OP_SUB
                    OP_ENDIF
                }
                if iter == 1 { OP_DROP } else { OP_TOALTSTACK }
            }
        }
    }

    pub fn OP_TMUL() -> Script
    where
        [(); { Self::EXT_N_BITS } as usize]:,
    {
        let mut get_var_window = Self::get_var_window_script_generator();

        script! {
                // stack: {q} {x} {y}
                // pre-compute tables
                { Self::U::toaltstack() }    // {q} {x} -> {y}
                { Self::U::toaltstack() }    // {q} -> {x} {y}
                { Self::U::resize::<{ Self::EXT_N_BITS }>() }
                { Self::T::W::push_zero() } // {q} {0} -> {x} {y}
                { Self::T::W::sub(0, 1) }   // {-q} -> {x} {y}
                { Self::T::initialize(MOD_WIDTH) }   // {-q_table} -> {x} {y}
                { Self::U::fromaltstack() }  // {-q_table} {x} -> {y}
                { Self::U::resize::<{ Self::EXT_N_BITS }>() }
                { Self::T::initialize(VAR_WIDTH) }   // {-q_table} {x_table} -> {y}
                { Self::U::fromaltstack() } // {-q_table} {x_table} {y}
                { Self::U::resize::<{ Self::EXT_N_BITS }>() }

                { Self::T::W::push_zero() } // {-q_table} {x_table} {y} {0}

                // main loop
                for i in Self::EXT_N_BITS_SKIP..=Self::EXT_N_BITS {
                    // z -= q*p[i]
                    if i % MOD_WIDTH == 0 && Self::get_mod_window(i/MOD_WIDTH - 1) != 0  {
                        { Self::T::W::copy((1 << VAR_WIDTH) + (1 << MOD_WIDTH) - Self::get_mod_window(i/MOD_WIDTH - 1)) }
                        { Self::T::W::add(0, 1) }
                    }
                    // z += x*y[i]
                    if i % VAR_WIDTH == 0 {
                        { get_var_window() }
                        OP_DUP OP_NOT
                        OP_IF
                            OP_DROP
                        OP_ELSE
                            { 1 + (1 << VAR_WIDTH)  }
                            OP_SWAP
                            OP_SUB
                            { Self::T::W::stack_copy() }
                            { Self::T::W::add(0, 1) }
                        OP_ENDIF
                    }
                    if i < Self::EXT_N_BITS {
                        // TODO: ensure res.num_bits() <= N_BITS
                        { Self::T::W::dbl() }
                    }
                }

                { Self::T::W::toaltstack() } // {-q_table} {x_table} {y} -> {r}

                // cleanup
                { Self::T::W::drop() }       // {-q_table} {x_table} -> {r}
                { Self::T::drop(VAR_WIDTH) }  // {-q_table} -> {r}
                { Self::T::drop(MOD_WIDTH) }  // -> {r}

                // validation: r = if r < 0 { r + p } else { r }; assert(r < p)
                { Self::T::W::fromaltstack() } // {r}
                { Self::T::W::copy(0) }                                       // {r} {r}
                { Self::T::W::push_u32_le(&Self::modulus().to_u32_digits()) } // {r} {r} {p}
                { Self::T::W::greaterthan(0, 1) } OP_VERIFY                   // {r}

                // resize res back to N_BITS
                { Self::T::W::resize::<N_BITS>() } // {r}
        }
    }
}

struct LookupTable<const N_BITS: u32, const LIMB_SIZE: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32> LookupTable<N_BITS, LIMB_SIZE> {
    pub type W = BigIntImpl<N_BITS, LIMB_SIZE>;

    // drop table on top of the stack
    fn drop(window: u32) -> Script {
        script! {
            for _ in 1..1<<window {
                { Self::W::drop() }
            }
        }
    }

    pub fn initialize(window: u32) -> Script {
        assert!(
            1 <= window && window <= 6,
            "expected 1<=window<=5; got window={}",
            window
        );
        script! {
            for i in 2..=window {
                for j in 1 << (i - 1)..1 << i {
                    if j % 2 == 0 {
                        { Self::W::copy(j/2 - 1) }
                        { Self::W::dbl() }
                    } else {
                        { Self::W::copy(0) }
                        { Self::W::copy(j - 1) }
                        { Self::W::add(0, 1) }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, RandBigInt, ToBigInt};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use seq_macro::seq;

    use super::*;

    pub fn print_script_size(name: &str, script: Script) {
        println!("{} script is {} bytes in size", name, script.len());
    }

    fn bigint_to_u32_limbs(n: BigInt, n_bits: u32) -> Vec<u32> {
        const limb_size: u64 = 32;
        let mut limbs = vec![];
        let mut limb: u32 = 0;
        for i in 0..n_bits as u64 {
            if i > 0 && i % limb_size == 0 {
                limbs.push(limb);
                limb = 0;
            }
            if n.bit(i) {
                limb += 1 << (i % limb_size);
            }
        }
        limbs.push(limb);
        limbs
    }

    fn bigint_to_uXu8_limbs(n: BigInt, n_bits: u32, limb_size: u32) -> Vec<Vec<u8>> {
        let mut limbs = vec![];
        let mut limb: u32 = 0;
        for i in 0..n_bits {
            if i > 0 && i % limb_size == 0 {
                limbs.push(limb.to_le_bytes().to_vec());
                limb = 0;
            }
            if n.bit(i as u64) {
                limb += 1 << (i % limb_size);
            }
        }
        limbs.push(limb.to_le_bytes().to_vec());
        limbs
    }

    fn print_bigint_in_stack(n: BigInt, n_bits: u32) {
        let mut limbs = bigint_to_uXu8_limbs(n.clone(), n_bits, 30);
        limbs.reverse();
        for limb in &mut limbs {
            while limb.len() > 0 && limb[limb.len() - 1] == 0 {
                limb.pop();
            }
        }
        for limb in limbs {
            println!("{:?}", limb);
        }
    }

    #[test]
    fn test_multi_window_mul() {
        fn get_window_decomps(b: &BigInt, window: u32, n_bits: u32) -> Vec<usize> {
            let mut res = vec![];
            let n_window = (n_bits + window - 1) / window;
            for index in 0..n_window {
                let shift_by = window * (n_window - index - 1);
                let bit_mask = BigInt::from_u32((1 << window) - 1).unwrap() << shift_by;
                res.push(((b.clone() & bit_mask) >> shift_by).to_usize().unwrap());
            }
            res
        }

        fn precompute_lookup_table(b: &BigInt, window: u32) -> Vec<BigInt> {
            let mut res = vec![];
            for i in 0..1 << window {
                res.push(b.clone() * BigInt::from(i));
            }
            res
        }

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let modulus = &Fq::<254, 30, 1, 1>::modulus().to_bigint().unwrap();
        let x = prng.gen_bigint_range(&BigInt::ZERO, modulus);
        let y = prng.gen_bigint_range(&BigInt::ZERO, modulus);
        let c = &x * &y;
        let q = &c / modulus;
        let r = &c % modulus;

        seq!(VAR_WIDTH in 1..=6 {
            seq!(MOD_WIDTH in 1..=6 { {
                type F = Fq<254, 30, VAR_WIDTH, MOD_WIDTH>;

                let y_window = get_window_decomps(&y, VAR_WIDTH, F::EXT_N_BITS);
                let qp_table = precompute_lookup_table(&q, MOD_WIDTH);
                let xy_table = precompute_lookup_table(&x, VAR_WIDTH);

                let mut z = BigInt::ZERO;
                for i in F::EXT_N_BITS_SKIP..=F::EXT_N_BITS {
                    if i % MOD_WIDTH == 0 {
                        z -= &qp_table[F::get_mod_window(i / MOD_WIDTH - 1) as usize];
                    }

                    if i % VAR_WIDTH == 0 {
                        z += &xy_table[y_window[(i / VAR_WIDTH - 1) as usize]];
                    }
                    if i < F::EXT_N_BITS {
                        z *= 2;
                    }
                }
                assert!(z == r);
            } });
        });
    }

    #[test]
    fn test_multi_window_op_tmul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let modulus = Fq::<254, 30, 1, 1>::modulus();
        let x = prng.gen_biguint_below(&modulus);
        let y = prng.gen_biguint_below(&modulus);
        let c = &x * &y;
        let q = &c / &modulus;
        let r = &c % &modulus;

        let mut stats = vec![];

        // seq!(VAR_WIDTH in 3..=3 {
        //     seq!(MOD_WIDTH in 3..=3 { {
        seq!(VAR_WIDTH in 1..=6 {
            seq!(MOD_WIDTH in 1..=6 { {
                type F = Fq<254, 30, VAR_WIDTH, MOD_WIDTH>;
                let script = script! {
                    { F::U::push_u32_le(&q.to_u32_digits()) }
                    { F::U::push_u32_le(&x.to_u32_digits()) }
                    { F::U::push_u32_le(&y.to_u32_digits()) }
                    { F::OP_TMUL() }
                    { F::U::push_u32_le(&r.to_u32_digits()) }
                    { F::U::equalverify(0, 1) }
                    OP_TRUE
                };
                // fs::write("~/fq_op_tmul_script.txt", script.clone().compile().to_string()).unwrap();
                let res = execute_script(script);
                if VAR_WIDTH == 6 && VAR_WIDTH == MOD_WIDTH { // skip stack limit exceeding muls
                    stats.push((format!("{}Y-{}P", VAR_WIDTH, MOD_WIDTH), F::OP_TMUL().len(), 1000));
                } else {
                    assert!(res.success);
                    stats.push((format!("{}Y-{}P", VAR_WIDTH, MOD_WIDTH), F::OP_TMUL().len(), res.stats.max_nb_stack_items));
                }
            } });
        });

        // sort stats by low to high stack usage
        stats.sort_by(|a, b| {
            if a.2 != b.2 {
                a.2.cmp(&b.2)
            } else {
                a.1.cmp(&b.1)
            }
        });
        for stat in stats {
            println!(
                "254-bit-{}: script: {:6}, stack: {:3}",
                stat.0, stat.1, stat.2
            );
        }
    }
}
