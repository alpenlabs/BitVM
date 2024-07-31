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

    pub fn resize<const T_BITS: u32>() -> Script {
        assert!(T_BITS >= N_BITS, "T_BITS should >= N_BITS");

        let n_limbs_self = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
        let n_limbs_target = (T_BITS + LIMB_SIZE - 1) / LIMB_SIZE;

        if n_limbs_target == n_limbs_self {
            return script! {};
        }
        let n_limbs_to_add = n_limbs_target - n_limbs_self;
        script! {
            if n_limbs_to_add > 0 {
                {0} {crate::pseudo::OP_NDUP((n_limbs_to_add - 1) as usize)} // Pushing zeros to the stack
            }
            for _ in 0..n_limbs_self {
                { n_limbs_target - 1 } OP_ROLL
            }
        }
    }
}

// Finite field multiplication impl
pub struct Fp<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32> Fp<N_BITS, LIMB_SIZE, WINDOW> {
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
    pub const N_WINDOW: u32 = (N_BITS + WINDOW - 1) / WINDOW; // num coefficients in w-width form

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type S = BigIntImpl<{ N_BITS + 1 }, LIMB_SIZE> where [(); { N_BITS + 1 } as usize]:; // signed BigInt (1-bit for sign)
    type P = PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW>; // pre-compute table

    pub fn modulus() -> BigUint {
        BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .expect("modulus: should not fail")
    }

    fn bit_decomp_modulus(index: u32) -> u32 {
        let shift_by = WINDOW * (Self::N_WINDOW - index - 1);
        let mut bit_mask =
            BigUint::from_u32((1 << WINDOW) - 1).expect("bit_decomp:bit_mask: should not fail");
        bit_mask <<= shift_by;
        ((Self::modulus() & bit_mask) >> shift_by)
            .to_u32()
            .expect("bit_decomp_modulus: should not fail")
    }

    fn bit_decomp_script_generator() -> impl FnMut(u32) -> Script {
        let n_limbs = Self::N_LIMBS;
        let n_window = Self::N_WINDOW;
        let limb_size = Self::LIMB_SIZE;

        let mut index = n_window + 1;

        move |src_depth: u32| {
            index -= 1;

            let lookup_offset = n_limbs * src_depth;

            let s_bit = index * WINDOW - 1; // start bit
            let e_bit = (index - 1) * WINDOW; // end bit

            let s_limb = s_bit / limb_size; // start bit limb
            let e_limb = e_bit / limb_size; // end bit limb

            script! {
                { 0 }
                if index == n_window { // initialize accumulator to track reduced limb

                    { lookup_offset + s_limb + 1 } OP_PICK

                } else if (s_bit + 1) % limb_size == 0  { // drop current and initialize next accumulator

                    OP_FROMALTSTACK OP_DROP
                    { lookup_offset + s_limb + 1 } OP_PICK

                } else {
                    OP_FROMALTSTACK // load accumulator from altstack
                }

                for i in 0..WINDOW {
                    if s_limb > e_limb {
                        if i % limb_size == (s_bit % limb_size) + 1 {
                            // window is split between multiple limbs
                            OP_DROP
                            { lookup_offset + e_limb + 1 } OP_PICK
                        }
                    }
                    OP_TUCK
                    { (1 << ((s_bit - i) % limb_size)) - 1 }
                    OP_GREATERTHAN
                    OP_TUCK
                    OP_ADD
                    if i < WINDOW - 1 {
                        { crate::pseudo::OP_2MUL() }
                    }
                    OP_ROT OP_ROT
                    OP_IF
                        { 1 << ((s_bit - i) % limb_size) }
                        OP_SUB
                    OP_ENDIF
                }

                if index == 1 {
                    OP_DROP       // last index, drop the accumulator
                } else {
                    OP_TOALTSTACK
                }
            }
        }
    }

    pub fn OP_TMUL() -> Script
    where
        [(); { N_BITS + 1 } as usize]:,
        [(); { N_BITS + WINDOW } as usize]:,
    {
        const fn loop_offset(i: u32) -> u32 {
            if i == 0 {
                0
            } else {
                1
            }
        }

        let mut bit_decomp_script_y = Self::bit_decomp_script_generator();

        script! {
            // stack: {q} {x} {y}
            { Self::U::toaltstack() }   // move y to altstack
            { Self::U::toaltstack() }   // move x to altstack
            { Self::P::initialize() }   // q: {0*z, 1*z, ..., ((1<<WINDOW)-1)*z}
            { Self::U::fromaltstack() } // move x back to stack
            { Self::P::initialize() }   // x: {0*z, 1*z, ..., ((1<<WINDOW)-1)*z}
            { Self::U::fromaltstack() } // move y back to stack
            { Self::U::resize::<{ N_BITS + WINDOW }>() } // resize for stack alignment

            // main loop
            for i in 0..Self::N_WINDOW {
                if i != 0 {
                    // TODO: ensure res.num_bits() <= N_BITS
                    for _ in 0..WINDOW { // z <<= WINDOW
                        { Self::P::W::dbl() }
                    }
                }

                // q*p[i]
                { Self::P::W::copy(2 * (1 << WINDOW) - Self::bit_decomp_modulus(i) + loop_offset(i)) }

                // x*y[i]
                { bit_decomp_script_y(1 + loop_offset(i)) }
                { (1 << WINDOW) + 1 + loop_offset(i) }
                OP_SWAP
                OP_SUB
                { Self::P::W::stack_copy() }

                // x*y[i] - q*p[i]
                { Self::P::W::sub(0, 1) }

                // z += x*y[i] - q*p[i]
                if i != 0 {
                    { Self::P::W::add(0, 1) }
                }
            }

            // assert 0 <= res < modulus
            { Self::U::copy(0) }
            { Self::U::push_zero() }
            { Self::U::lessthanorequal(0, 1) }
            OP_VERIFY
            { Self::U::copy(0) }
            { Self::U::push_u32_le(&Self::modulus().to_u32_digits()) }
            { Self::U::greaterthan(0, 1)}
            OP_VERIFY

            // cleanup
            { Self::U::toaltstack() }   // move res to altstack
            { Self::U::drop() }         // drop y
            { Self::P::drop() }         // drop table x*y[i]
            { Self::P::drop() }         // drop table q*p[i]
            { Self::U::fromaltstack() } // move res back to stack
        }
    }
}

struct PrecomputeTable<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32>
    PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW>
{
    pub type U = BigIntImpl<N_BITS, LIMB_SIZE>; // original N_BITS number
    pub type W = BigIntImpl<{ N_BITS + WINDOW }, LIMB_SIZE> where [(); { N_BITS + WINDOW } as usize]:; // windowed multiple

    // drop table on top of the stack
    fn drop() -> Script
    where
        [(); { N_BITS + WINDOW } as usize]:,
    {
        script! {
            for _ in 0..1<<WINDOW {
                { Self::W::drop() }
            }
        }
    }

    pub fn initialize() -> Script
    where
        [(); { N_BITS + WINDOW } as usize]:,
    {
        assert!(WINDOW < 7, "WINDOW > 6 (exceeds stack limit: 1000)");
        script! {
            for i in 1..=WINDOW {
                if i == 1 {
                    { Self::U::resize::<{ N_BITS + WINDOW }>() } // resize to target bits
                    { Self::W::push_zero() } // {z, 0}
                    { Self::W::roll(1) }     // {0, z}
                } else {
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
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use seq_macro::seq;

    use super::*;

    pub fn print_script_size(name: &str, script: Script) {
        println!("{} script is {} bytes in size", name, script.len());
    }

    #[test]
    fn test_254_bit_windowed_op_tmul() {
        type F = Fp<254, 30, 4>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p = F::modulus();
        let x = prng.gen_biguint_below(&p);
        let y = prng.gen_biguint_below(&p);
        let c = &x * &y;
        let q = &c / &p;
        let r = &c % &p;

        let script = script! {
            { F::U::push_u32_le(&q.to_u32_digits()) }
            { F::U::push_u32_le(&x.to_u32_digits()) }
            { F::U::push_u32_le(&y.to_u32_digits()) }
            { F::OP_TMUL() }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equalverify(0, 1) }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_invalid_q() {
        type F = Fp<254, 30, 3>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p = F::modulus();
        let x = prng.gen_biguint_below(&p);
        let y = prng.gen_biguint_below(&p);
        let c = &x * &y;
        let q = &c / &p;
        let r = &c % &p;

        let q_invalid = loop {
            let rnd = prng.gen_biguint_below(&p);
            if rnd != q {
                break rnd;
            }
        };

        let script = script! {
            { F::U::push_u32_le(&q_invalid.to_u32_digits()) }
            { F::U::push_u32_le(&x.to_u32_digits()) }
            { F::U::push_u32_le(&y.to_u32_digits()) }
            { F::OP_TMUL() }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equal(0, 1) }
            OP_VERIFY
        };

        let res = execute_script(script);
        assert!(!res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_fuzzy() {
        type F<const WINDOW: u32> = Fp<254, 30, WINDOW>;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        seq!(WINDOW in 1..=4 {
            print!("254-bit-windowed-op-tmul-{}-bit-window, script_size: {}", WINDOW, F::<WINDOW>::OP_TMUL().len());

            let mut max_stack_items: usize = 0;

            for _ in 0..100 {
                let p = F::<WINDOW>::modulus();
                let x = prng.gen_biguint_below(&p);
                let y = prng.gen_biguint_below(&p);
                let c = &x * &y;
                let q = &c / &p;
                let r = &c % &p;

                let script = script! {
                    { F::<WINDOW>::U::push_u32_le(&q.to_u32_digits()) }
                    { F::<WINDOW>::U::push_u32_le(&x.to_u32_digits()) }
                    { F::<WINDOW>::U::push_u32_le(&y.to_u32_digits()) }
                    { F::<WINDOW>::OP_TMUL() }
                    { F::<WINDOW>::U::push_u32_le(&r.to_u32_digits()) }
                    { F::<WINDOW>::U::equalverify(0, 1) }
                    OP_TRUE
                };

                let res = execute_script(script);
                assert!(res.success);
                max_stack_items = res.stats.max_nb_stack_items;
            }

            println!(", max_stack_usage: {}", max_stack_items);
        });
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_invalid_q_fuzzy() {
        type F<const WINDOW: u32> = Fp<254, 30, WINDOW>;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        seq!(WINDOW in 1..=4 {
            for _ in 0..100 {
                let p = F::<WINDOW>::modulus();
                let x = prng.gen_biguint_below(&p);
                let y = prng.gen_biguint_below(&p);
                let c = &x * &y;
                let q = &c / &p;
                let r = &c % &p;

                let q_invalid = loop {
                    let rnd = prng.gen_biguint_below(&p);
                    if rnd != q {
                        break rnd;
                    }
                };

                let script = script! {
                    { F::<WINDOW>::U::push_u32_le(&q_invalid.to_u32_digits()) }
                    { F::<WINDOW>::U::push_u32_le(&x.to_u32_digits()) }
                    { F::<WINDOW>::U::push_u32_le(&y.to_u32_digits()) }
                    { F::<WINDOW>::OP_TMUL() }
                    { F::<WINDOW>::U::push_u32_le(&r.to_u32_digits()) }
                    { F::<WINDOW>::U::equal(0, 1) }
                    OP_VERIFY
                };

                let res = execute_script(script);
                assert!(!res.success);
            }
        });
    }
}
