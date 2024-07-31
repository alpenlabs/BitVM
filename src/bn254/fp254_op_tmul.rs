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
pub struct Fp<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const LC: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const LC: u32>
    Fp<N_BITS, LIMB_SIZE, WINDOW, LC>
{
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
    pub const N_WINDOW: u32 = (N_BITS + WINDOW - 1) / WINDOW; // num coefficients in w-width form
    pub const WINDOW: u32 = WINDOW;

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type P = PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW, LC>; // pre-compute table

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

    fn bit_decomp_script_generator() -> impl FnMut() -> Script
    where
        [(); LC as usize]:,
        [(); { N_BITS + WINDOW + Self::P::BATCH_BITS } as usize]:,
    {
        let n_window = Self::N_WINDOW;
        let limb_size = Self::LIMB_SIZE;

        let mut iter = n_window + 1;

        move || {
            let n_limbs = Self::P::W::N_LIMBS;

            let stack_top = n_limbs;

            iter -= 1;

            let s_bit = iter * WINDOW - 1; // start bit
            let e_bit = (iter - 1) * WINDOW; // end bit

            let s_limb = s_bit / limb_size; // start bit limb
            let e_limb = e_bit / limb_size; // end bit limb

            script! {
                for j in 0..LC {
                    { 0 }
                    if iter == n_window { // initialize accumulator to track reduced limb

                        { stack_top + n_limbs * j + s_limb + 1 } OP_PICK

                    } else if (s_bit + 1) % limb_size == 0  { // drop current and initialize next accumulator
                        OP_FROMALTSTACK OP_DROP
                        { stack_top + n_limbs * j   + s_limb + 1 } OP_PICK

                    } else {
                        OP_FROMALTSTACK // load accumulator from altstack
                    }

                    for i in 0..WINDOW {
                        if s_limb > e_limb {
                            if i % limb_size == (s_bit % limb_size) + 1 {
                                // window is split between multiple limbs
                                OP_DROP
                                { stack_top + n_limbs * j   + e_limb + 1 } OP_PICK
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

                    if iter == n_window {
                        OP_TOALTSTACK
                        OP_TOALTSTACK
                    } else {

                        for _ in j+1..LC {
                            OP_FROMALTSTACK
                        }
                        { LC - j - 1 } OP_ROLL OP_TOALTSTACK // acc
                        { LC - j - 1 } OP_ROLL OP_TOALTSTACK // res
                        for _ in j+1..LC {
                            OP_TOALTSTACK
                        }
                    }

                }
                for _ in 0..LC {
                    OP_FROMALTSTACK
                    OP_FROMALTSTACK
                }
                for k in (0..LC).rev() {
                    { 2*k } OP_ROLL OP_TOALTSTACK
                }
            }
        }
    }

    // z = x0*y0 - x1*y1 + x2*y2
    // N = 5
    // ops = [true, false, true, true, false],
    //       true for addition, false for subtraction
    pub fn OP_TMUL(signs: [bool; LC as usize]) -> Script
    where
        [(); { N_BITS + 1 } as usize]:,
        [(); { N_BITS + WINDOW } as usize]:,
        [(); { N_BITS + WINDOW + Self::P::BATCH_BITS } as usize]:,
    {
        let mut bit_decomp_script_y = Self::bit_decomp_script_generator();

        script! {
                // stack: {q} {x0} {x1} {x2} {y0} {y1} {y2}

                // pre-compute tables
                for _ in 0..LC {
                    { Self::U::toaltstack() }
                }                             // {q} {x0} {x1} {x2}
                for _ in 0..LC {
                    { Self::U::toaltstack() }
                }                             // {q}

                // { Self::P::resize_into() }  // {q}: no need to resize as it's already sized in the input
                { Self::P::W::push_zero() } // {q} {0}
                { Self::P::W::sub(0, 1) }   // {-q}
                { Self::P::initialize() }   // {-q_table}

                for i in 0..LC {
                    { Self::U::fromaltstack() }
                    { Self::P::resize_into() }
                    if !signs[i as usize] {
                        { Self::P::W::push_zero() } // {-q_table} ... {x} {0}
                        { Self::P::W::sub(0, 1) }   // {-q_table} ... {-x}
                    }
                    { Self::P::initialize() }
                }                                   // {-q_table} {x0_table} {x1_table} {x2_table}

                for _ in 0..LC {
                    { Self::U::fromaltstack() }
                    { Self::P::resize_into() }
                }                           // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2}

                { Self::P::W::push_zero() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {0}

                // main loop
                for i in 0..Self::N_WINDOW {
                    if i != 0 {
                        // TODO: ensure res.num_bits() <= N_BITS
                        for _ in 0..WINDOW { // z <<= WINDOW
                            { Self::P::W::dbl() }
                        }
                    }

                    // z += q*p[i]
                    { Self::P::W::copy((1 + LC) * (1 << WINDOW) - Self::bit_decomp_modulus(i) + LC) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z=0} {-q[i]}
                    // {99} {i} {0} OP_LESSTHAN OP_VERIFY OP_DROP

                    { Self::P::W::add(0, 1) }  // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}

                    { bit_decomp_script_y() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {w0} {w1} {w2}

                    for _ in 0..LC {
                        OP_TOALTSTACK
                    }                         // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} -> {w0} {w1} {w2}

                    for j in 0..LC {
                        OP_FROMALTSTACK
                        { (1 << WINDOW) * (LC - j) + LC }
                        OP_SWAP
                        OP_SUB

                        // xj*yj[i]
                        { Self::P::W::stack_copy() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {xj*yj[i]}

                        // z += x*y[i]
                        {Self::P::W::add(0, 1) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}
                    }

                }

                // assert 0 <= res < modulus
                { Self::P::W::copy(0) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {z} {0}
                { Self::P::W::push_zero() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {z} {0}
                { Self::P::W::lessthanorequal(0, 1) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} 1
                OP_VERIFY // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}
                { Self::P::W::copy(0) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {z}
                { Self::P::W::push_u32_le(&Self::modulus().to_u32_digits()) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {z} {p}
                { Self::P::W::greaterthan(0, 1)} // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} 1
                OP_VERIFY // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}

                // resize res back to N_BITS
                { Self::P::W::resize::<N_BITS>() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}

                // cleanup
                { Self::U::toaltstack() }   // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} -> {r}
                for _ in 0..LC {
                    { Self::P::W::drop() }
                }                           // {-q_table} {x0_table} {x1_table} {x2_table} -> {r}
                for _ in 0..LC {
                    { Self::P::drop() }
                }                           // {-q_table} -> {r}
                { Self::P::drop() }         // -> {r}
                { Self::U::fromaltstack() } // {r}
        }
    }
}

struct PrecomputeTable<
    const N_BITS: u32,
    const LIMB_SIZE: u32,
    const WINDOW: u32,
    const BATCH_SIZE: u32,
> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const BATCH_SIZE: u32>
    PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW, BATCH_SIZE>
{
    const BATCH_BITS: u32 = 32 - BATCH_SIZE.leading_zeros() - 1;

    pub type U = BigIntImpl<N_BITS, LIMB_SIZE>;
    pub type W = BigIntImpl<{ N_BITS + WINDOW + Self::BATCH_BITS }, LIMB_SIZE> where [(); { N_BITS + WINDOW + Self::BATCH_BITS } as usize]:; // windowed multiple

    // drop table on top of the stack
    fn drop() -> Script
    where
        [(); { N_BITS + WINDOW + Self::BATCH_BITS } as usize]:,
    {
        script! {
            for _ in 0..1<<WINDOW {
                { Self::W::drop() }
            }
        }
    }

    fn resize_into() -> Script
    where
        [(); { N_BITS + WINDOW + Self::BATCH_BITS } as usize]:,
    {
        Self::U::resize::<{ N_BITS + WINDOW + Self::BATCH_BITS }>()
    }

    pub fn initialize() -> Script
    where
        [(); { N_BITS + WINDOW + Self::BATCH_BITS } as usize]:,
    {
        assert!(WINDOW < 7, "WINDOW > 6 (exceeds stack limit: 1000)");
        script! {
            for i in 1..=WINDOW {
                if i == 1 {
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
    use ark_ff::One;
    use num_bigint::{BigInt, RandBigInt, RandomBits, Sign, ToBigInt};
    use num_traits::{Signed, ToBytes};
    use rand::{Rng, SeedableRng};
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
    fn test_254_bit_windowed_batch() {
        const LC: usize = 6;
        const LC_SIGNS: [bool; LC as usize] = [true; LC];

        type F = Fp<254, 30, 3, { LC as u32 }>;

        let p = F::modulus();

        fn window(b: BigUint) -> [usize; F::N_WINDOW as usize] {
            let mut res = [0; F::N_WINDOW as usize];
            let mut b = b;

            for i in (0..res.len()).rev() {
                let next = b.clone() >> F::WINDOW;
                res[i] = (b.clone() - (next.clone() << F::WINDOW))
                    .to_usize()
                    .unwrap();
                b = next;
                if b <= BigUint::ZERO {
                    break;
                }
            }
            res
        }

        fn precompute_table(b: BigUint) -> [BigInt; 1 << F::WINDOW] {
            let mut res = [BigInt::ZERO; 1 << F::WINDOW];
            for i in 0..(1 << F::WINDOW) {
                res[i] = BigInt::from_biguint(Sign::Plus, b.clone() * BigUint::from(i));
            }
            res
        }

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let xs = (0..LC)
            .map(|_| prng.gen_biguint_below(&p))
            .collect::<Vec<_>>();
        let ys = (0..LC)
            .map(|_| prng.gen_biguint_below(&p))
            .collect::<Vec<_>>();

        let mut c = BigUint::ZERO;
        for i in 0..LC {
            let xy = &xs[i] * &ys[i];
            if LC_SIGNS[i] {
                c += xy;
            } else {
                c -= xy;
            };
        }

        let r = &c % &p;
        let q = &c / &p;

        let p_window = window(p.clone());
        let y_windows = ys.iter().map(|y| window(y.clone())).collect::<Vec<_>>();
        let x_tables = xs
            .iter()
            .map(|x| precompute_table(x.clone()))
            .collect::<Vec<_>>();
        let q_table = precompute_table(q.clone());

        // accumulator
        let mut z = BigInt::ZERO;
        for i in 0..F::N_WINDOW as usize {
            z *= 1 << F::WINDOW;
            z -= q_table[p_window[i]].clone();
            for j in 0..LC {
                let v = x_tables[j][y_windows[j][i]].clone();
                z += if LC_SIGNS[j] { v } else { -v };
            }
        }

        assert!(z == BigInt::from(r));
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_lc() {
        const LC: usize = 4;
        const LC_SIGNS: [bool; LC as usize] = [true; LC as usize];

        type F = Fp<254, 30, 3, { LC as u32 }>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL(LC_SIGNS));

        let p = F::modulus();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let xs = (0..LC)
            .map(|_| prng.gen_biguint_below(&p))
            .collect::<Vec<_>>();
        let ys = (0..LC)
            .map(|_| prng.gen_biguint_below(&p))
            .collect::<Vec<_>>();

        let mut c = BigUint::ZERO;
        for i in 0..LC {
            let xy = &xs[i] * &ys[i];
            if LC_SIGNS[i] {
                c += xy;
            } else {
                c -= xy;
            };
        }

        let r = &c % &p;
        let q = &c / &p;

        let script = script! {
            { F::P::W::push_u32_le(&q.to_u32_digits()) }
            for i in 0..LC {
                { F::U::push_u32_le(&xs[i].to_u32_digits()) }
            }
            for i in 0..LC {
                { F::U::push_u32_le(&ys[i].to_u32_digits()) }
            }
            { F::OP_TMUL(LC_SIGNS) }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equalverify(0, 1) }
            OP_TRUE
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:5}: {:?}", res.final_stack.get(i));
        }
        println!("{:?}", res.stats);
        assert!(res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul() {
        type F = Fp<254, 30, 3, 1>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL([true; 1]));

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
            { F::OP_TMUL([true; 1]) }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equalverify(0, 1) }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_invalid_q() {
        type F = Fp<254, 30, 3, 1>;

        print_script_size("254-bit-windowed-op-tmul-invalid-q", F::OP_TMUL([true; 1]));

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
            { F::OP_TMUL([true; 1]) }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equal(0, 1) }
            OP_VERIFY
        };

        let res = execute_script(script);
        assert!(!res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_fuzzy() {
        type F<const WINDOW: u32> = Fp<254, 30, WINDOW, 1>;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        seq!(WINDOW in 1..=4 {
            print!("254-bit-windowed-op-tmul-{}-bit-window, script_size: {}", WINDOW, F::<WINDOW>::OP_TMUL([true; 1]).len());

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
                    { F::<WINDOW>::OP_TMUL([true; 1]) }
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
        type F<const WINDOW: u32> = Fp<254, 30, WINDOW, 1>;

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
                    { F::<WINDOW>::OP_TMUL([true; 1]) }
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
