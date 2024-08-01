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

// Linear Combination
pub struct LinearCombination<const SIZE: usize>([bool; SIZE]);
impl<const SIZE: usize> LinearCombination<SIZE> {
    pub const fn new(inner: [bool; SIZE]) -> LinearCombination<SIZE> { LinearCombination(inner) }
    pub const fn from(n: usize) -> LinearCombination<SIZE> {
        let mut inner: [bool; SIZE] = [true; SIZE];
        let mut n = n;
        let mut i = 0;
        while i < SIZE {
            inner[i] = (n & 1) != 0;
            n >>= 1;
            i += 1;
        }
        LinearCombination(inner)
    }
    pub const fn get(&self, index: usize) -> bool { self.0[index] }
    pub const fn SIZE(&self) -> usize { self.0.len() }
    pub const fn SIZE_U32(&self) -> u32 { self.SIZE() as u32 }
}

// Finite field multiplication impl
pub struct Fp<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const LC_SIZE: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const LC_SIZE: u32>
    Fp<N_BITS, LIMB_SIZE, WINDOW, LC_SIZE>
{
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
    pub const N_WINDOW: u32 = (N_BITS + WINDOW - 1) / WINDOW; // num coefficients in w-width form
    pub const WINDOW: u32 = WINDOW;

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type P = PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW, LC_SIZE>; // pre-compute table

    pub fn modulus() -> BigUint {
        BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .expect("modulus: should not fail")
    }

    fn get_modulus_window(index: u32) -> u32 {
        let shift_by = WINDOW * (Self::N_WINDOW - index - 1);
        let mut bit_mask =
            BigUint::from_u32((1 << WINDOW) - 1).expect("bit_decomp:bit_mask: should not fail");
        bit_mask <<= shift_by;
        ((Self::modulus() & bit_mask) >> shift_by)
            .to_u32()
            .expect("bit_decomp_modulus: should not fail")
    }

    fn get_window_script_generator() -> impl FnMut() -> Script
    where
        [(); LC_SIZE as usize]:,
        [(); { N_BITS + WINDOW + Self::P::LC_BITS } as usize]:,
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
                for j in 0..LC_SIZE as u32 {
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

                    if j+1 < LC_SIZE as u32 {
                        if iter == n_window {
                            OP_TOALTSTACK
                            OP_TOALTSTACK
                        } else {
                            for _ in j+1..LC_SIZE as u32 {
                                OP_FROMALTSTACK
                            }
                            { LC_SIZE - j - 1 } OP_ROLL OP_TOALTSTACK // acc
                            { LC_SIZE - j - 1 } OP_ROLL OP_TOALTSTACK // res
                            for _ in j+1..LC_SIZE as u32 {
                                OP_TOALTSTACK
                            }
                        }
                    }
                }
                for _ in 0..LC_SIZE-1 {
                    OP_FROMALTSTACK
                    OP_FROMALTSTACK
                }
                for j in (0..LC_SIZE).rev() {
                    if j != 0 {
                        { 2*j } OP_ROLL
                    }
                    if iter == 1 { OP_DROP } else { OP_TOALTSTACK }
                }
            }
        }
    }

    // z = x0*y0 - x1*y1 + x2*y2
    // N = 5
    // ops = [true, false, true, true, false],
    //       true for addition, false for subtraction
    pub fn OP_TMUL(lcs: LinearCombination<{ LC_SIZE as usize }>) -> Script
    where
        [(); { N_BITS + 1 } as usize]:,
        [(); { N_BITS + WINDOW } as usize]:,
        [(); { N_BITS + WINDOW + Self::P::LC_BITS } as usize]:,
        [(); LC_SIZE as usize]:,
    {
        let mut get_window_script = Self::get_window_script_generator();

        script! {
                // stack: {q} {x0} {x1} {x2} {y0} {y1} {y2}
                // pre-compute tables
                for _ in 0..LC_SIZE {
                    { Self::U::toaltstack() }
                }                             // {q} {x0} {x1} {x2}
                for _ in 0..LC_SIZE {
                    { Self::U::toaltstack() }
                }                             // {q}

                { Self::P::W::push_zero() } // {q} {0}
                { Self::P::W::sub(0, 1) }   // {-q}
                { Self::P::initialize() }   // {-q_table}

                for i in 0..LC_SIZE {
                    { Self::U::fromaltstack() }
                    { Self::P::resize_into() }
                    if !lcs.0[i as usize] {
                        { Self::P::W::push_zero() } // {-q_table} ... {x} {0}
                        { Self::P::W::sub(0, 1) }   // {-q_table} ... {-x}
                    }
                    { Self::P::initialize() }
                }                                   // {-q_table} {x0_table} {x1_table} {x2_table}

                for _ in 0..LC_SIZE {
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
                    if Self::get_modulus_window(i) != 0 {
                        { Self::P::W::copy(1 + LC_SIZE + (1 + LC_SIZE) * ((1 << WINDOW) - 1) - Self::get_modulus_window(i)) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z=0} {-q[i]}
                        { Self::P::W::add(0, 1) }  // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}
                    }

                    { get_window_script() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {w0} {w1} {w2}

                    for _ in 0..LC_SIZE-1 {
                        OP_TOALTSTACK
                    }                         // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {w0} -> {w1} {w2}

                    for j in 0..LC_SIZE {
                        if j != 0 { OP_FROMALTSTACK }
                        OP_DUP OP_NOT
                        OP_IF
                            OP_DROP
                        OP_ELSE
                            { 1 + LC_SIZE + (LC_SIZE - j) * ((1 << WINDOW) - 1)  }
                            OP_SWAP
                            OP_SUB
                            // xj*yj[i]
                            { Self::P::W::stack_copy() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z} {xj*yj[i]}
                            // z += x*y[i]
                            { Self::P::W::add(0, 1) } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}
                        OP_ENDIF
                    }
                }

                { Self::P::W::is_positive(LC_SIZE + (1 + LC_SIZE) * ((1 << WINDOW) - 1))  } // -q >= 0 -> q is negative
                OP_TOALTSTACK               // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {r} -> {1/0}
                { Self::P::W::toaltstack() }   // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} -> {r} {1/0}

                // cleanup
                for _ in 0..LC_SIZE {
                    { Self::P::W::drop() }
                }                           // {-q_table} {x0_table} {x1_table} {x2_table} -> {r} {1/0}
                for _ in 0..LC_SIZE {
                    { Self::P::drop() }
                }                           // {-q_table} -> {r} {1/0}
                { Self::P::drop() }         // -> {r} {1/0}

                // validation: r = if r < 0 { r + p } else { r }; assert(r < p)
                { Self::P::W::fromaltstack() } OP_FROMALTSTACK // {r} {1/0}
                OP_IF                                                             // {r}
                    { Self::P::W::push_u32_le(&Self::modulus().to_u32_digits()) } // {r} {p}
                    { Self::P::W::add(0, 1) }                                     // {r_final}
                OP_ENDIF
                { Self::P::W::copy(0) }                                       // {r_final} {r_final}
                { Self::P::W::push_u32_le(&Self::modulus().to_u32_digits()) } // {r_final} {r_final} {p}
                { Self::P::W::greaterthan(0, 1) } OP_VERIFY                   // {r_final}

                // resize res back to N_BITS
                { Self::P::W::resize::<N_BITS>() } // {-q_table} {x0_table} {x1_table} {x2_table} {y0} {y1} {y2} {z}
        }
    }
}

struct PrecomputeTable<
    const N_BITS: u32,
    const LIMB_SIZE: u32,
    const WINDOW: u32,
    const LC_SIZE: u32,
> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WINDOW: u32, const LC_SIZE: u32>
    PrecomputeTable<N_BITS, LIMB_SIZE, WINDOW, LC_SIZE>
{
    pub const LC_BITS: u32 = u32::BITS - LC_SIZE.leading_zeros() - 1;

    const _WINDOW_LIMIT: u32 = (5 - WINDOW) * (WINDOW - 1); // compile time limit (1 <= WINDOW <= 5)

    pub type U = BigIntImpl<N_BITS, LIMB_SIZE>;
    pub type W = BigIntImpl<{ N_BITS + WINDOW + Self::LC_BITS }, LIMB_SIZE> where [(); { N_BITS + WINDOW + Self::LC_BITS } as usize]:; // windowed multiple

    // drop table on top of the stack
    fn drop() -> Script
    where
        [(); { N_BITS + WINDOW + Self::LC_BITS } as usize]:,
    {
        script! {
            for _ in 1..1<<WINDOW {
                { Self::W::drop() }
            }
        }
    }

    fn resize_into() -> Script
    where
        [(); { N_BITS + WINDOW + Self::LC_BITS } as usize]:,
    {
        Self::U::resize::<{ N_BITS + WINDOW + Self::LC_BITS }>()
    }

    pub fn initialize() -> Script
    where
        [(); { N_BITS + WINDOW + Self::LC_BITS } as usize]:,
    {
        _ = Self::_WINDOW_LIMIT;
        script! {
            for i in 2..=WINDOW {
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
    use num_traits::Signed;
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
    fn test_254_bit_windowed_batch() {
        type LC4 = LinearCombination<4>;
        const LC: LC4 = LC4::new([true, false, true, false]);

        type F = Fp<254, 30, 3, { LC.SIZE_U32() }>;

        let p = F::modulus();

        fn window(b: BigInt) -> [usize; F::N_WINDOW as usize] {
            let mut res = [0; F::N_WINDOW as usize];
            let mut b = b;
            for i in (0..res.len()).rev() {
                let next = b.clone() >> F::WINDOW;
                res[i] = (b.clone() - (next.clone() << F::WINDOW))
                    .to_usize()
                    .unwrap();
                b = next;
                if b <= BigInt::ZERO {
                    break;
                }
            }
            res
        }

        fn precompute_table(b: BigInt) -> [BigInt; 1 << F::WINDOW] {
            let mut res = [BigInt::ZERO; 1 << F::WINDOW];
            for i in 0..(1 << F::WINDOW) {
                res[i] = b.clone() * BigInt::from(i);
            }
            res
        }

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let xs = (0..LC.SIZE())
            .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
            .collect::<Vec<_>>();
        let ys = (0..LC.SIZE())
            .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
            .collect::<Vec<_>>();

        let p = p.to_bigint().unwrap();

        let mut c = BigInt::ZERO;
        for i in 0..LC.SIZE() {
            let xy = &xs[i] * &ys[i];
            c += if LC.get(i) { xy } else { -xy };
        }

        let q = &c / &p;
        let r = &c % &p;
        let r = if r.is_negative() { &p + r } else { r };

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
            for j in 0..LC.SIZE() {
                let v = x_tables[j][y_windows[j][i]].clone();
                z += if LC.get(j) { v } else { -v };
            }
        }
        z = if z.is_negative() { &p + z } else { z };
        assert!(z == BigInt::from(r));
    }

    #[test]
    fn test_254_bit_windowed_op_tmul() {
        const LC: LinearCombination<1> = LinearCombination::new([true]);

        type F = Fp<254, 30, 3, { LC.SIZE_U32() }>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL(LC));

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let p = F::modulus();
        let x = prng.gen_biguint_below(&p);
        let y = prng.gen_biguint_below(&p);
        let c = &x * &y;
        let q = &c / &p;
        let r = &c % &p;

        // correct quotient
        let script = script! {
            { F::P::W::push_u32_le(&q.to_u32_digits()) }
            { F::U::push_u32_le(&x.to_u32_digits()) }
            { F::U::push_u32_le(&y.to_u32_digits()) }
            { F::OP_TMUL(LC) }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equalverify(0, 1) }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);

        // incorrect quotient
        let q = loop {
            let rnd = prng.gen_biguint_below(&p);
            if rnd != q {
                break rnd;
            }
        };
        let script = script! {
            { F::P::W::push_u32_le(&q.to_u32_digits()) }
            { F::U::push_u32_le(&x.to_u32_digits()) }
            { F::U::push_u32_le(&y.to_u32_digits()) }
            { F::OP_TMUL(LC) }
            { F::U::push_u32_le(&r.to_u32_digits()) }
            { F::U::equal(0, 1) }
        };

        let res = execute_script(script);
        assert!(!res.success);
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_fuzzy() {
        const LC: LinearCombination<1> = LinearCombination::new([true]);

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        seq!(WINDOW in 1..=5 { {
            type F = Fp<254, 30, WINDOW, { LC.SIZE_U32() }>;

            print!("254-bit-windowed-op-tmul-{}-bit-window, script_size: {}", WINDOW, F::OP_TMUL(LC).len());

            let mut max_stack_items: usize = 0;

            for _ in 0..100 {
                let p = F::modulus();
                let x = prng.gen_biguint_below(&p);
                let y = prng.gen_biguint_below(&p);
                let c = &x * &y;
                let r = &c % &p;

                // correct quotient
                let q = &c / &p;
                let script = script! {
                    { F::P::W::push_u32_le(&q.to_u32_digits()) }
                    { F::U::push_u32_le(&x.to_u32_digits()) }
                    { F::U::push_u32_le(&y.to_u32_digits()) }
                    { F::OP_TMUL(LC) }
                    { F::U::push_u32_le(&r.to_u32_digits()) }
                    { F::U::equalverify(0, 1) }
                    OP_TRUE
                };
                let res = execute_script(script);
                assert!(res.success);

                max_stack_items = max_stack_items.max(res.stats.max_nb_stack_items);

                // incorrect quotient
                let q = loop {
                    let rnd = prng.gen_biguint_below(&p);
                    if rnd != q {
                        break rnd;
                    }
                };
                let script = script! {
                    { F::P::W::push_u32_le(&q.to_u32_digits()) }
                    { F::U::push_u32_le(&x.to_u32_digits()) }
                    { F::U::push_u32_le(&y.to_u32_digits()) }
                    { F::OP_TMUL(LC) }
                    { F::U::push_u32_le(&r.to_u32_digits()) }
                    { F::U::equal(0, 1) }
                };

                let res = execute_script(script);
                assert!(!res.success);

                max_stack_items = max_stack_items.max(res.stats.max_nb_stack_items);
            }

            println!(", max_stack_usage: {}", max_stack_items);
        } });
    }

    #[test]
    fn test_254_bit_windowed_op_tmul_lc() {
        const LC: LinearCombination<4> = LinearCombination::new([true, false, true, false]);

        type F = Fp<254, 30, 3, { LC.SIZE() as u32 }>;

        print_script_size("254-bit-windowed-op-tmul", F::OP_TMUL(LC));

        let p = F::modulus();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let xs = (0..LC.SIZE())
            .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
            .collect::<Vec<_>>();
        let ys = (0..LC.SIZE())
            .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
            .collect::<Vec<_>>();

        let p = p.to_bigint().unwrap();

        let mut c = BigInt::ZERO;
        for i in 0..LC.SIZE() as usize {
            let xy = &xs[i] * &ys[i];
            c += if LC.get(i) { xy } else { -xy };
        }

        let r = &c % &p;
        let r = if r.is_negative() { &p + r } else { r };

        // correct quotient
        let q = &c / &p;
        let script = script! {
            { F::P::W::push_u32_le(&bigint_to_u32_limbs(q.clone(), F::P::W::N_BITS)) }
            for i in 0..LC.SIZE() {
                { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
            }
            for i in 0..LC.SIZE() {
                { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
            }
            { F::OP_TMUL(LC) }
            { F::P::W::push_u32_le(&r.to_u32_digits().1) }
            { F::U::equalverify(0, 1) }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);

        // incorrect quotient
        let q = loop {
            let rnd = prng.gen_bigint_range(&(-p.clone()), &p);
            if rnd != q.clone() {
                break rnd;
            }
        };
        let script = script! {
            { F::P::W::push_u32_le(&bigint_to_u32_limbs(q, F::P::W::N_BITS)) }
            for i in 0..LC.SIZE() {
                { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
            }
            for i in 0..LC.SIZE() {
                { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
            }
            { F::OP_TMUL(LC) }
            { F::U::push_u32_le(&r.to_u32_digits().1) }
            { F::U::equal(0, 1) }
        };

        let res = execute_script(script);
        assert!(!res.success);
        println!("{:?}", res.stats);
    }

    macro_rules! const_if {
        ($cond:expr, $true_branch:block, $false_branch:block) => {{
            const CONDITION: bool = $cond;
            if CONDITION {
                $true_branch
            } else {
                $false_branch
            }
        }};
    }

    #[test]
    #[cfg(feature = "ignored_test")]
    fn test_254_bit_windowed_op_tmul_lc_fuzzy() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        seq!(WINDOW in 1..=4 {
            seq!(LC_SIZE in 1..=5 { {
                seq!(LC_BITS in 0..32 { {
                    const_if!(
                        LC_BITS < (1 << LC_SIZE),
                        {
                            const LC: LinearCombination<LC_SIZE> = LinearCombination::from(LC_BITS);
                            type F = Fp<254, 30, WINDOW, { LC.SIZE_U32() }>;

                            let p = F::modulus();

                            let xs = (0..LC.SIZE())
                                .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
                                .collect::<Vec<_>>();
                            let ys = (0..LC.SIZE())
                                .map(|_| prng.gen_biguint_below(&p).to_bigint().unwrap())
                                .collect::<Vec<_>>();

                            let p = p.to_bigint().unwrap();

                            let mut c = BigInt::ZERO;
                            for i in 0..LC.SIZE() as usize {
                                let xy = &xs[i] * &ys[i];
                                c += if LC.get(i) { xy } else { -xy };
                            }

                            let r = &c % &p;
                            let r = if r.is_negative() { &p + r } else { r };

                            // correct quotient
                            let q = &c / &p;
                            let script = script! {
                                { F::P::W::push_u32_le(&bigint_to_u32_limbs(q.clone(), F::P::W::N_BITS)) }
                                for i in 0..LC.SIZE() {
                                    { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
                                }
                                for i in 0..LC.SIZE() {
                                    { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
                                }
                                { F::OP_TMUL(LC) }
                                { F::U::push_u32_le(&r.to_u32_digits().1) }
                                { F::U::equalverify(0, 1) }
                                OP_TRUE
                            };
                            let res = execute_script(script);
                            assert!(res.success);

                            // incorrect quotient
                            let q = loop {
                                let rnd = prng.gen_bigint_range(&(-p.clone()), &p);
                                if rnd != q.clone() {
                                    break rnd;
                                }
                            };
                            let script = script! {
                                { F::P::W::push_u32_le(&bigint_to_u32_limbs(q, F::P::W::N_BITS)) }
                                for i in 0..LC.SIZE() {
                                    { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
                                }
                                for i in 0..LC.SIZE() {
                                    { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
                                }
                                { F::OP_TMUL(LC) }
                                { F::U::push_u32_le(&r.to_u32_digits().1) }
                                { F::U::equal(0, 1) }
                            };

                            let res = execute_script(script);
                            assert!(!res.success);
                        },
                        {}
                    );
                } });
            } });
        });
    }
}
