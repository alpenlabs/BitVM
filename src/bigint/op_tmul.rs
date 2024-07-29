use crate::treepp::*;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use std::str::FromStr;

use super::BigIntImpl;

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
}

pub struct WinBigIntImpl<const N_BITS: u32, const LIMB_SIZE: u32, const WIDTH: u32> {}

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WIDTH: u32>
    WinBigIntImpl<N_BITS, LIMB_SIZE, WIDTH>
{
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const DECOMPOSITION_SIZE: u32 = Self::decomposition_size(Self::N_BITS, WIDTH); // num coefficients in w-width form

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type S = BigIntImpl<{ N_BITS + 1 }, LIMB_SIZE> where [(); { N_BITS + 1 } as usize]:; // signed BigInt (1-bit for sign)
    type P = PrecomputeTable<{ N_BITS + WIDTH }, LIMB_SIZE, WIDTH> where [(); { N_BITS + WIDTH } as usize]:; // pre-compute table

    const fn decomposition_size(n_bits: u32, width: u32) -> u32 { (n_bits + width - 1) / width }

    pub fn modulus() -> BigUint {
        BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .expect("modulus: should not fail")
    }

    fn bit_decomp_modulus(index: u32) -> u32 {
        let shift_by = WIDTH * (Self::DECOMPOSITION_SIZE - index - 1);
        let mut bit_mask =
            BigUint::from_u32((1 << WIDTH) - 1).expect("bit_decomp:bit_mask: should not fail");
        bit_mask <<= shift_by;
        ((Self::modulus() & bit_mask) >> shift_by)
            .to_u32()
            .expect("bit_decomp_modulus: should not fail")
    }

    fn bit_decomp_script(index: u32, src_depth: u32) -> Script {
        let n_limbs = (Self::N_BITS + Self::LIMB_SIZE - 1) / Self::LIMB_SIZE;
        let n_window = (Self::N_BITS + WIDTH - 1) / WIDTH;
        let limb_size = Self::LIMB_SIZE;

        let index = n_window - index;
        let lookup_offset = n_limbs * src_depth;

        let s_bit = index * WIDTH - 1; // start bit
        let e_bit = (index - 1) * WIDTH; // end bit

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

            for i in 0..WIDTH {
                if s_limb > e_limb {
                    if i % limb_size == (s_bit % limb_size) + 1 {
                        // window is split between multiple limbs
                        OP_DROP
                        { lookup_offset + e_limb + 1 } OP_PICK
                    }
                }
                OP_TUCK
                { (1 << ((s_bit - i) % Self::LIMB_SIZE)) - 1 }
                OP_GREATERTHAN
                OP_TUCK
                OP_ADD
                if i < WIDTH - 1 {
                    { crate::pseudo::OP_2MUL() }
                }
                OP_ROT OP_ROT
                OP_IF
                    { 1 << ((s_bit - i) % Self::LIMB_SIZE) }
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

    pub fn OP_TMUL() -> Script
    where
        [(); { N_BITS + 1 } as usize]:,
        [(); { N_BITS + WIDTH } as usize]:,
    {
        const fn loop_offset(i: u32) -> u32 {
            if i == 0 {
                0
            } else {
                1
            }
        }

        script! {
            { Self::U::toaltstack() }   // move y to altstack
            { Self::U::toaltstack() }   // move x to altstack
            { Self::P::initialize() }   // q: {0*z, 1*z, ..., ((1<<WIDTH)-1)*z}
            { Self::U::fromaltstack() } // move x back to stack
            { Self::P::initialize() }   // x: {0*z, 1*z, ..., ((1<<WIDTH)-1)*z}
            { Self::U::fromaltstack() } // move y back to stack

            // main loop
            for i in 0..Self::DECOMPOSITION_SIZE {
                if i != 0 {
                    // TODO: ensure result.num_bits() <= N_BITS + WIDTH
                    for _ in 0..WIDTH { // z <<= WIDTH
                        { Self::P::U::dbl() }
                    }
                }

                // q*p[i]
                { Self::P::U::copy(2 * (1 << WIDTH) - Self::bit_decomp_modulus(i) + loop_offset(i)) }

                // x*y[i]
                { Self::bit_decomp_script(i, 1 + loop_offset(i)) }
                { (1 << WIDTH) + 1 + loop_offset(i) }
                OP_SWAP
                OP_SUB
                { Self::P::U::stack_copy() }

                // x*y[i] - q*p[i]
                { Self::P::U::sub(0, 1) }

                // z += x*y[i] - q*p[i]
                if i != 0 {
                    { Self::P::U::add(0, 1) }
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

impl<const N_BITS: u32, const LIMB_SIZE: u32, const WIDTH: u32>
    PrecomputeTable<N_BITS, LIMB_SIZE, WIDTH>
{
    pub type U = BigIntImpl<N_BITS, LIMB_SIZE>;

    fn drop() -> Script {
        script! {
            for _ in 0..1<<WIDTH {
                { Self::U::drop() }
            }
        }
    }

    /// {0, z} for WINDOW=2
    fn initialize_1mul() -> Script {
        script! {
            { Self::U::push_zero() } // {z, 0}
            { Self::U::roll(1) }     // {0, z}
        }
    }

    /// Precomputes values `{0*z, 1*z, 2*z, 3*z}` (corresponding to `WIDTH=2`) needed
    /// for multiplication, assuming that `z` is the top stack element.
    fn initialize_2mul() -> Script {
        script! {
            { Self::initialize_1mul() } // {0, z}
            { Self::U::copy(0) }         // {0, z, z}
            { Self::U::dbl() }           // {0, z, 2*z}
            { Self::U::copy(1) }         // {0, z, 2*z, z}
            { Self::U::copy(1) }         // {0, z, 2*z, z, 2*z}
            { Self::U::add(0, 1) }       // {0, z, 2*z, 3*z}
        }
    }

    /// Precomputes values `{0*z, 1*z, ..., 7*z}` (corresponding to `WIDTH=3`) needed
    /// for multiplication, assuming that `z` is the top stack element.
    fn initialize_3mul() -> Script {
        script! {
            { Self::initialize_2mul() } // {0, z, 2*z, 3*z}
            { Self::U::copy(1) }         // {0, z, 2*z, 3*z, 2*z}
            { Self::U::dbl() }           // {0, z, 2*z, 3*z, 4*z}
            { Self::U::copy(3) }         // {0, z, 2*z, 3*z, 4*z, z}
            { Self::U::copy(1) }         // {0, z, 2*z, 3*z, 4*z, z, 4*z}
            { Self::U::add(0, 1) }       // {0, z, 2*z, 3*z, 4*z, 5*z}
            { Self::U::copy(2) }         // {0, z, 2*z, 3*z, 4*z, 5*z, 3*z}
            { Self::U::dbl() }           // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z}
            { Self::U::copy(5) }         // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, z}
            { Self::U::copy(1) }         // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, z, 6*z}
            { Self::U::add(0, 1) }       // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z}
        }
    }

    /// Precomputes values `{0*z, 1*z, ..., 7*z, ..., 14*z, 15*z}` (corresponding to `WIDTH=4`) needed
    /// for multiplication, assuming that `z` is the top stack element.
    fn initialize_4mul() -> Script {
        script! {
            { Self::initialize_3mul() }  // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z}
            { Self::U::copy(3) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 4*z}
            { Self::U::dbl() }            // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z}
            { Self::U::copy(7) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, z}
            { Self::U::copy(1) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, z, 8*z}
            { Self::U::add(1, 0) }        // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z}
            { Self::U::copy(4) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 5*z}
            { Self::U::dbl() }            // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z}
            { Self::U::copy(9) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, z}
            { Self::U::copy(1) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, z, 10*z}
            { Self::U::add(1, 0) }        // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z}
            { Self::U::copy(5) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 6*z}
            { Self::U::dbl() }            // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z}
            { Self::U::copy(11) }         // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, z}
            { Self::U::copy(1) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, z, 12*z}
            { Self::U::add(1, 0) }        // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z}
            { Self::U::copy(6) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z, 7*z}
            { Self::U::dbl() }            // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z, 14*z}
            { Self::U::copy(13) }         // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z, 14*z, z}
            { Self::U::copy(1) }          // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z, 14*z, z, 14*z}
            { Self::U::add(1, 0) }        // {0, z, 2*z, 3*z, 4*z, 5*z, 6*z, 7*z, 8*z, 9*z, 10*z, 11*z, 12*z, 13*z, 14*z, 15*z}
        }
    }

    pub fn lazy_initialize() -> Script {
        assert!(WIDTH >= 2, "width should be at least 2");

        script! {
            { Self::initialize_1mul() } // {0, z}
            { Self::U::copy(0) }        // {0, z, z}
            { Self::U::dbl() }          // {0, z, 2*z}
            for i in 0..(1<<WIDTH)-3 {
                // Given {0, z, 2z, ..., (i+2)z} we add (i+3)z to the end
                { Self::U::copy(0) }    // {0, z, ..., (i+2)z, (i+2)z}
                { Self::U::copy(i+2) }  // {0, z, ..., (i+2)z, (i+2)z, z}
                { Self::U::add(0, 1) }  // {0, z, ..., (i+2)z, (i+3)z}
            }
        }
    }

    pub fn initialize() -> Script {
        match WIDTH {
            1 => Self::initialize_1mul(),
            2 => Self::initialize_2mul(),
            3 => Self::initialize_3mul(),
            4 => Self::initialize_4mul(),
            _ => Self::lazy_initialize(),
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    pub fn print_script_size(name: &str, script: Script) {
        println!("{} script is {} bytes in size", name, script.len());
    }

    #[test]
    fn test_254_bit_windowed_op_tmul() {
        type W = WinBigIntImpl<254, 30, 3>;

        print_script_size("254-bit-windowed-op-tmul", W::OP_TMUL());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p = W::modulus();
        let x = prng.gen_biguint_below(&p);
        let y = prng.gen_biguint_below(&p);
        let c = &x * &y;
        let q = &c / &p;
        let r = &c % &p;

        let script = script! {
            { W::U::push_u32_le(&q.to_u32_digits()) }
            { W::U::push_u32_le(&x.to_u32_digits()) }
            { W::U::push_u32_le(&y.to_u32_digits()) }
            { W::OP_TMUL() }
            { W::U::push_u32_le(&r.to_u32_digits()) }
            { W::U::equalverify(1, 0) }
            OP_TRUE
        };

        let res = execute_script(script);
        assert!(res.success);

        println!("stack:");
        for i in 0..res.final_stack.len() {
            println!("{i}: {:?}", res.final_stack.get(i));
        }

        println!("{:?}", res.stats);
    }
}
