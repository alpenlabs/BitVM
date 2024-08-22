use crate::{
    bigint::{
        add::{limb_add_carry, limb_add_nocarry},
        BigIntImpl,
    },
    treepp::*,
};
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use std::str::FromStr;

pub fn NMUL(n: u32) -> Script {
    let n_bits = u32::BITS - n.leading_zeros();
    let bits = (0..n_bits).map(|i| 1 & (n >> i)).collect::<Vec<_>>();
    script! {
        if n_bits == 0 { OP_DROP 0 }
        else {
            for i in 0..bits.len()-1 {
                if bits[i] == 1 { OP_DUP }
                { crate::pseudo::OP_2MUL() }
            }
            for _ in 1..bits.iter().sum() { OP_ADD }
        }
    }
}

fn limb_add_with_carry_prevent_overflow(head_offset: u32) -> Script {
    script! {
        // {a} {b} {c:carry}
        OP_3DUP                                           // {a} {b} {c} {a} {b} {c}
        OP_ADD OP_ADD OP_NIP                              // {a} {b} {a+b+c}
        OP_ROT                                            // {b} {a+b+c} {a}
        { head_offset >> 1 } OP_LESSTHAN                  // {b} {a+b+c} {sign_a}
        OP_ROT                                            // {a+b+c} {sign_a} {b}
        { head_offset >> 1 } OP_LESSTHAN                  // {a+b+c} {sign_a} {sign_b}
        OP_ADD                                            // {a+b+c} {sign_a+b} -> both neg: 0, both diff: 1, both pos: 2
        OP_SWAP                                           // {sign_a+b} {a+b+c}
        OP_DUP { head_offset } OP_GREATERTHANOREQUAL      // {sign_a+b} {a+b+c} {L:0/1} // limb overflow
        OP_TUCK                                           // {sign_a+b} {L:0/1} {a+b+c} {L:0/1}
        OP_IF { head_offset } OP_SUB OP_ENDIF             // {sign_a+b} {L:0/1} {a+b+c_nlo}
        OP_DUP { head_offset >> 1 } OP_GREATERTHANOREQUAL // {sign_a+b} {L:0/1} {a+b+c_nlo} {I:0/1} // integer overflow
        OP_2SWAP                                          // {a+b+c_nlo} {I:0/1} {sign_a+b} {L:0/1}
        OP_IF                                             // {a+b+c_nlo} {I:0/1} {sign_a+b}
            OP_NOTIF OP_VERIFY 0 OP_ENDIF                 // {a+b+c_nlo} 0
        OP_ELSE
            OP_1SUB OP_IF OP_NOT OP_VERIFY 0 OP_ENDIF    // {a+b+c_nlo} 0
        OP_ENDIF
        OP_DROP                                          // {a+b+c_nlo}
    }
}

fn limb_double_without_carry() -> Script {
    script! {
        // {limb} {base}
        OP_SWAP // {base} {limb}
        { NMUL(2) } // {base} {2*limb}
        OP_2DUP // {base} {2*limb} {base} {2*limb}
        OP_LESSTHANOREQUAL // {base} {2*limb} {base<=2*limb}
        OP_TUCK // {base} {base<=2*limb} {2*limb} {base<=2*limb}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_double_with_carry() -> Script {
    script! {
        // {limb} {base} {carry}
        OP_ROT // {base} {carry} {limb}
        { NMUL(2) } // {base} {carry} {2*limb}
        OP_ADD // {base} {2*limb + carry}
        OP_2DUP // {base} {2*limb + carry} {base} {2*limb + carry}
        OP_LESSTHANOREQUAL // {base} {2*limb + carry} {base<=2*limb + carry}
        OP_TUCK // {base} {base<=2*limb+carry} {2*limb+carry} {base<=2*limb+carry}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_double_with_carry_allow_overflow(head_offset: u32) -> Script {
    script! {
        OP_SWAP // {carry} {limb}
        { NMUL(2) } // {carry} {2*limb}
        OP_ADD // {carry + 2*limb}
        { head_offset } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    }
}

fn limb_double_with_carry_prevent_overflow(head_offset: u32) -> Script {
    script! {
        // {a} {c:carry}
        OP_OVER                                          // {a} {c} {a}
        OP_DUP OP_ADD OP_ADD                             // {a} {2a+c}
        OP_SWAP                                          // {2a+c} {a}
        { head_offset >> 1 } OP_LESSTHAN                 // {2a+c} {sign_a} // neg: 0, pos: 1
        OP_SWAP                                          // {sign_a} {2a+c}
        OP_DUP { head_offset } OP_GREATERTHANOREQUAL     // {sign_a} {2a+c} {L:0/1} // limb overflow

        OP_TUCK                                          // {sign_a} {L:0/1} {2a+c} {L:0/1}
        OP_IF { head_offset } OP_SUB OP_ENDIF            // {sign_a} {L:0/1} {2a+c_nlo}
        OP_DUP {head_offset >> 1 } OP_GREATERTHANOREQUAL // {sign_a} {L:0/1} {2a+c_nlo} {I:0/1}
        OP_2SWAP                                         // {2a+c_nlo} {I:0/1} {sign_a} {L:0/1}

        OP_IF                                            // {2a+c_nlo} {I:0/1} {sign_a}
            OP_NOTIF OP_VERIFY 0 OP_ENDIF                // {2a+c_nlo} 0
        OP_ELSE                                          // {2a+c_nlo} {I:0/1} {sign_a}
            OP_IF OP_NOT OP_VERIFY 0 OP_ENDIF            // {2a+c_nlo} 0
        OP_ENDIF
        OP_DROP                                          // {2a+c_nlo}
    }
}

fn limb_lshift_without_carry(bits: u32) -> Script {
    script! {
        OP_SWAP                  // {base} {limb}
        for i in 1..=bits {
            { NMUL(2) }          // {base} {2*limb}
            OP_2DUP              // {base} {2*limb} {base} {2*limb}
            OP_LESSTHANOREQUAL   // {base} {2*limb} {carry:base<=2*limb}
            OP_TUCK              // {base} {carry} {2*limb} {carry}
            OP_IF                // {base} {carry} {2*limb}
                2 OP_PICK OP_SUB // {base} {carry} {2*limb-base}
            OP_ENDIF
            if i < bits { OP_ROT OP_SWAP } // {carry...} {base} {2*limb-base}
            else { OP_TOALTSTACK OP_SWAP } // {carry...} {base} -> {2*limb-base}
        }
    }
}

fn limb_lshift_with_carry(bits: u32) -> Script {
    script! {
        // {limb} {p_carry..} {base}
        { 1 + bits } OP_ROLL     // {p_carry..} {base} {limb}
        for i in 1..=bits {
            { NMUL(2) }                     // {p_carry..} {base} {2*limb}
            { 1 + bits } OP_ROLL OP_ADD     // {p_carry..} {base} {2*limb+c0}
            OP_2DUP                         // {p_carry..} {base} {2*limb+c0} {base} {2*limb+c0}
            OP_LESSTHANOREQUAL              // {p_carry..} {base} {2*limb+c0} {carry:base<=2*limb+c0}
            OP_TUCK                         // {p_carry..} {base} {carry} {2*limb+c0} {carry}
            OP_IF                           // {p_carry..} {base} {carry} {2*limb+c0}
                2 OP_PICK OP_SUB            // {p_carry..} {base} {carry} {2*limb+c0-base}
            OP_ENDIF
            if i < bits { OP_ROT OP_SWAP } // {p_carry..} {carry..} {base} {2*limb-base}
            else { OP_TOALTSTACK OP_SWAP } // {carry..} {base} -> {2*limb-base}
        }
    }
}

fn limb_lshift_with_carry_prevent_overflow(bits: u32, head: u32) -> Script {
    script! {
        // {a} {c..}
        { bits } OP_PICK     // {a} {c..} {a}
        for i in 0..bits {
            { NMUL(2) }                     // {a} {c..} {2*a}
            if i < bits - 1 {
                { bits - i } OP_ROLL
            }
            OP_ADD                          // {a} {c..} {2*a+c0}
        }                                   // {a} {2*a+c..}

        OP_SWAP                                          // {2a+c} {a}
        { 1 << (head - 1) } OP_LESSTHAN                  // {2a+c} {sign_a} // neg: 0, pos: 1
        OP_SWAP                                          // {sign_a} {2a+c}

        OP_DUP { 1 << head } OP_GREATERTHANOREQUAL          // {sign_a} {2a+c} {L:0/1} // limb overflow
        OP_TUCK                                             // {sign_a} {L:0/1} {2a+c} {L:0/1}
        OP_IF { ((1 << bits) - 1) << head } OP_SUB OP_ENDIF // {sign_a} {L:0/1} {2a+c_nlo}
        OP_DUP { 1 << head } OP_LESSTHAN OP_VERIFY
        OP_DUP { 1 << (head - 1) } OP_GREATERTHANOREQUAL // {sign_a} {L:0/1} {2a+c_nlo} {I:0/1}
        OP_2SWAP                                         // {2a+c_nlo} {I:0/1} {sign_a} {L:0/1}

        OP_IF                                            // {2a+c_nlo} {I:0/1} {sign_a}
            OP_NOTIF OP_VERIFY 0 OP_ENDIF                // {2a+c_nlo} 0
        OP_ELSE                                          // {2a+c_nlo} {I:0/1} {sign_a}
            OP_IF OP_NOT OP_VERIFY 0 OP_ENDIF            // {2a+c_nlo} 0
        OP_ENDIF
        OP_DROP                                          // {2a+c_nlo}
    }
}

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    // double the item on top of the stack ignoring overflow bits
    pub fn double_allow_overflow() -> Script {
        script! {
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            limb_double_without_carry OP_TOALTSTACK


            for _ in 0..Self::N_LIMBS - 2 {
                limb_double_with_carry OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            { limb_double_with_carry_allow_overflow(Self::HEAD_OFFSET) }

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    // double the item on top of the stack preventing overflow
    pub fn double_prevent_overflow() -> Script {
        script! {
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            limb_double_without_carry OP_TOALTSTACK


            for _ in 0..Self::N_LIMBS - 2 {
                limb_double_with_carry OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            { limb_double_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    // left shift by bits preventing overflow
    pub fn lshift_prevent_overflow(bits: u32) -> Script {
        script! {
            // {limb}
            { 1 << LIMB_SIZE } // {limb} {base}

            { limb_lshift_without_carry(bits) } // {limb} {carry..} {base}

            for _ in 0..Self::N_LIMBS - 2 {
                { limb_lshift_with_carry(bits) } // {limb} {carry..} {base}
            }
            // // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_DROP // {limb} {carry..}
            { limb_lshift_with_carry_prevent_overflow(bits, Self::HEAD) }

            // Take all limbs from the alt stack to the main stack
            for _ in 1..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
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

    pub fn add_ref(b: u32) -> Script {
        let b_depth = b * Self::N_LIMBS;
        if b > 1 {
            script! {
                { b_depth }
                { Self::_add_ref_inner() }
            }
        } else {
            script! {
                {b_depth} OP_PICK
                { 1 << LIMB_SIZE }
                limb_add_carry OP_TOALTSTACK
                for i in 1..Self::N_LIMBS {
                    { b_depth + 2 } OP_PICK
                    if i < Self::N_LIMBS - 1 {
                        OP_ADD
                        OP_SWAP
                        limb_add_carry OP_TOALTSTACK
                    } else {
                        OP_ROT OP_DROP
                        OP_SWAP { limb_add_with_carry_prevent_overflow(Self::HEAD_OFFSET) }
                        // OP_SWAP { limb_add_nocarry(Self::HEAD_OFFSET) }
                    }
                }
                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        }
    }

    // does not support addition to self, stack_top=0
    pub fn add_ref_stack() -> Script {
        script! {
            { NMUL(Self::N_LIMBS) }
            { Self::_add_ref_inner() }
        }
    }

    fn _add_ref_inner() -> Script {
        script! {
            // OP_DUP OP_NOT OP_NOT OP_VERIFY // fail on {0} stack
            // OP_DUP OP_NOT
            // OP_IF
            //     OP_DROP
            //     { Self::topadd_new(0) }
            // OP_ELSE
                3 OP_ADD
                { 1 << LIMB_SIZE }
                0
                for _ in 0..Self::N_LIMBS-1 {
                    2 OP_PICK
                    OP_PICK
                    OP_ADD
                    3 OP_ROLL
                    OP_ADD
                    OP_2DUP
                    OP_LESSTHANOREQUAL
                    OP_TUCK
                    OP_IF 2 OP_PICK OP_SUB OP_ENDIF
                    OP_TOALTSTACK
                }
                OP_NIP OP_SWAP
                2 OP_SUB OP_PICK

                OP_SWAP { limb_add_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK
                }
            // OP_ENDIF
        }
    }
}

pub trait LookupTable<const N_BITS: u32, const LIMB_SIZE: u32> {
    fn size_table(window: u32) -> u32 { (1 << window) - 1 }
    fn drop_table(window: u32) -> Script;
    fn init_table(window: u32) -> Script;
}

impl<const N_BITS: u32, const LIMB_SIZE: u32> LookupTable<N_BITS, LIMB_SIZE>
    for BigIntImpl<N_BITS, LIMB_SIZE>
{
    // drop table on top of the stack
    fn drop_table(window: u32) -> Script {
        script! {
            for _ in 1..1<<window {
                { Self::drop() }
            }
        }
    }

    // create table for top item on the stack
    fn init_table(window: u32) -> Script {
        assert!(
            1 <= window && window <= 6,
            "expected 1<=window<=6; got window={}",
            window
        );
        script! {
            for i in 2..=window {
                for j in 1 << (i - 1)..1 << i {
                    if j % 2 == 0 {
                        { Self::copy(j/2 - 1) }
                        { Self::double_allow_overflow() }
                    } else {
                        { Self::copy(0) }
                        { Self::add_ref(j - 1) }
                    }
                }
            }
        }
    }
}

const fn log(n: u32, base: u32) -> u32 {
    _ = n - 1; // compile time assertion: self >= 1
    _ = base - 2; // compile time assertion: base >= 2
    let mut res = 0;
    let mut power = 1;
    while power < n {
        res += 1;
        power *= base;
    }
    res
}

// Finite field multiplication impl LC
pub struct Fq<
    const N_BITS: u32,
    const LIMB_SIZE: u32,
    const MOD_WIDTH: u32,
    const VAR_WIDTH: u32,
    const N_LC: usize,
    const OTS_WIDTH: u32,
> {
    pub secret: String,
    pub wots_encode_counter: u32,
    pub wots_decode_counter: u32,
    pub lc_signs: [bool; N_LC],
}

impl<
        const N_BITS: u32,
        const LIMB_SIZE: u32,
        const MOD_WIDTH: u32,
        const VAR_WIDTH: u32,
        const N_LC: usize,
        const OTS_WIDTH: u32,
    > Fq<N_BITS, LIMB_SIZE, MOD_WIDTH, VAR_WIDTH, N_LC, OTS_WIDTH>
{
    pub const N_BITS: u32 = N_BITS;
    pub const LIMB_SIZE: u32 = LIMB_SIZE;
    pub const N_LIMBS: u32 = (N_BITS + LIMB_SIZE - 1) / LIMB_SIZE;
    pub const MOD_WIDTH: u32 = MOD_WIDTH;
    pub const VAR_WIDTH: u32 = VAR_WIDTH;
    pub const N_LC: u32 = N_LC as u32;
    pub const LC_BITS: u32 = usize::BITS - N_LC.leading_zeros() - 1;
    pub const N_VAR_BITS: u32 = 1 /* sign bit */ + N_BITS + VAR_WIDTH + Self::LC_BITS;

    // N_BITS for the extended number used during intermediate computation
    pub const MAIN_LOOP_END: u32 = {
        let n_bits_mod_width = ((N_BITS + MOD_WIDTH - 1) / MOD_WIDTH) * MOD_WIDTH;
        let n_bits_var_width = ((N_BITS + VAR_WIDTH - 1) / VAR_WIDTH) * VAR_WIDTH;
        // let n_bits_var_width =
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
    pub const MAIN_LOOP_START: u32 = {
        if MOD_WIDTH < VAR_WIDTH {
            MOD_WIDTH
        } else {
            VAR_WIDTH
        }
    };

    type U = BigIntImpl<N_BITS, LIMB_SIZE>; // unsigned BigInt
    type T = BigIntImpl<{ Self::N_VAR_BITS }, LIMB_SIZE> where [(); { Self::N_VAR_BITS } as usize]:;

    pub fn new(secret: String, lc_signs: [bool; N_LC]) -> Self {
        Self {
            secret,
            lc_signs,
            wots_encode_counter: 0,
            wots_decode_counter: 0,
        }
    }

    pub fn modulus() -> BigUint {
        BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .expect("modulus: should not fail")
    }

    pub fn get_modulus(&self) -> BigUint { Self::modulus() }

    fn get_mod_window(&self, index: u32) -> u32 {
        let n_window = Self::MAIN_LOOP_END / MOD_WIDTH;
        let shift_by = MOD_WIDTH * (n_window - index - 1);
        let bit_mask = BigUint::from_i32((1 << MOD_WIDTH) - 1).unwrap() << shift_by;
        ((Self::modulus() & bit_mask) >> shift_by).to_u32().unwrap()
    }

    fn get_var_window_script_generator(&self) -> impl FnMut() -> Script
    where
        [(); { Self::N_VAR_BITS } as usize]:,
    {
        let n_window = Self::MAIN_LOOP_END / VAR_WIDTH;
        let limb_size = Self::LIMB_SIZE;

        let mut iter = n_window + 1;

        move || {
            let n_limbs = Self::T::N_LIMBS;

            let stack_top = n_limbs;

            iter -= 1;

            let s_bit = iter * VAR_WIDTH - 1; // start bit
            let e_bit = (iter - 1) * VAR_WIDTH; // end bit

            let s_limb = s_bit / limb_size; // start bit limb
            let e_limb = e_bit / limb_size; // end bit limb

            script! {
                for j in 0..Self::N_LC {
                    { 0 }
                    if iter == n_window { // initialize accumulator to track reduced limb

                        { stack_top + n_limbs * j + s_limb + 1 } OP_PICK

                    } else if (s_bit + 1) % limb_size == 0  { // drop current and initialize next accumulator
                        OP_FROMALTSTACK OP_DROP
                        { stack_top + n_limbs * j   + s_limb + 1 } OP_PICK

                    } else {
                        OP_FROMALTSTACK // load accumulator from altstack
                    }

                    for i in 0..VAR_WIDTH {
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
                        if i < VAR_WIDTH - 1 {
                            { NMUL(2) }
                        }
                        OP_ROT OP_ROT
                        OP_IF
                            { 1 << ((s_bit - i) % limb_size) }
                            OP_SUB
                        OP_ENDIF
                    }

                    if j+1 < Self::N_LC {
                        if iter == n_window {
                            OP_TOALTSTACK
                            OP_TOALTSTACK
                        } else {
                            for _ in j+1..Self::N_LC {
                                OP_FROMALTSTACK
                            }
                            { Self::N_LC - j - 1 } OP_ROLL OP_TOALTSTACK // acc
                            { Self::N_LC - j - 1 } OP_ROLL OP_TOALTSTACK // res
                            for _ in j+1..Self::N_LC {
                                OP_TOALTSTACK
                            }
                        }
                    }
                }
                for _ in 0..N_LC-1 {
                    OP_FROMALTSTACK
                    OP_FROMALTSTACK
                }
                for j in (0..N_LC).rev() {
                    if j != 0 {
                        { 2*j } OP_ROLL
                    }
                    if iter == 1 { OP_DROP } else { OP_TOALTSTACK }
                }
            }
        }
    }

    pub fn OP_TMUL(&self) -> (Script, (i32, i32, i32))
    where
        [(); { Self::N_VAR_BITS } as usize]:,
    {
        let mut get_var_windows = self.get_var_window_script_generator();

        let mut ops = (0, 0, 0);
        let mut add_op = |dbl: i32, add: i32, stack_add: i32| -> Script {
            ops = (ops.0 + dbl, ops.1 + add, ops.2 + stack_add);
            script! {}
        };

        let scr = script! {
                // stack: {q} {x0} {x1} {y0} {y1}
                for _ in 0..2*N_LC {
                    // range check: U < MODULUS
                    { Self::U::copy(0) }                                       // {q} {x0} {x1} {y0} {y1} {y1}
                    { Self::U::push_u32_le(&Self::modulus().to_u32_digits()) } // {q} {x0} {x1} {y0} {y1} {y1} {MODULUS}
                    { Self::U::lessthan(1, 0) } OP_VERIFY                      // {q} {x0} {x1} {y0} {y1}
                    { Self::U::toaltstack() }                                  // {q} {x0} {x1} {y0} -> {y1}
                }                                                              // {q} -> {x0} {x1} {y0} {y1}
                // pre-compute tables
                // TODO: range check for quotient
                { Self::T::push_zero() }             // {q} {0} -> {x0} {x1} {y0} {y1}
                { Self::T::sub(0, 1) }               // {-q} -> {x0} {x1} {y0} {y1}
                { Self::T::init_table(MOD_WIDTH) }   // {-q_table} -> {x0} {x1} {y0} {y1}
                for i in 0..N_LC {
                    { Self::U::fromaltstack() }                   // {-q_table} {x0} -> {x1} {y0} {y1}
                    { Self::U::resize::<{ Self::N_VAR_BITS }>() } // {-q_table} {x0} -> {x1} {y0} {y1}
                    if !self.lc_signs[i] {
                        { Self::T::push_zero() }             // {q} {x0} {0} -> {x1} {y0} {y1}
                        { Self::T::sub(0, 1) }               // {-q} {-x0} -> {x1} {y0} {y1}
                    }
                    { Self::T::init_table(VAR_WIDTH) }            // {-q_table} {x0_table} -> {x1} {y0} {y1}
                }                                                 // {-q_table} {x0_table} {x1_table} -> {y0} {y1}
                for _ in 0..N_LC {
                    { Self::U::fromaltstack() }                   // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
                    { Self::U::resize::<{ Self::N_VAR_BITS }>() } // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
                }                                                 // {-q_table} {x0_table} {x1_table} {y0} {y1}                                                             // {q0} {q1} {x0} {x1} {y0} {y1}
                { Self::T::push_zero() }                          // {-q_table} {x0_table} {x1_table} {y0} {y1} {0}

                // main loop
                for i in Self::MAIN_LOOP_START..=Self::MAIN_LOOP_END {
                    // z -= q*p[i]
                    if i % MOD_WIDTH == 0 && self.get_mod_window(i/MOD_WIDTH - 1) != 0  {
                        { Self::T::add_ref(1 + Self::N_LC + Self::T::size_table(MOD_WIDTH) +
                            Self::N_LC * Self::T::size_table(VAR_WIDTH) - self.get_mod_window(i/MOD_WIDTH - 1)) }
                        { add_op(0, 1, 0) }
                    }
                    // z += x*y[i]
                    if i % VAR_WIDTH == 0 {
                        { get_var_windows() }
                        for _ in 1..Self::N_LC { OP_TOALTSTACK }
                        for j in 0..Self::N_LC {
                            if j != 0 { OP_FROMALTSTACK }
                            OP_DUP OP_NOT
                            OP_IF
                                OP_DROP
                            OP_ELSE
                                { 1 + Self::N_LC + (Self::N_LC - j) * Self::T::size_table(VAR_WIDTH)  }
                                OP_SWAP
                                OP_SUB
                                { Self::T::add_ref_stack() }
                                { add_op(0, 0, 1) }
                            OP_ENDIF
                        }
                    }
                    if i < Self::MAIN_LOOP_END {
                        if MOD_WIDTH == VAR_WIDTH {
                            if i % VAR_WIDTH == 0 {
                                { Self::T::lshift_prevent_overflow(VAR_WIDTH) }
                                { add_op(VAR_WIDTH as i32, 0, 0) }
                            }
                        } else {
                            { Self::T::double_prevent_overflow() }
                            { add_op(1, 0, 0) }
                        }
                    }
                }

                { Self::T::is_positive(Self::T::size_table(MOD_WIDTH) +                       // q was negative
                    Self::N_LC * Self::T::size_table(VAR_WIDTH) + Self::N_LC) } OP_TOALTSTACK // {-q_table} {x0_table} {x1_table} {y0} {y1} {r} -> {0/1}
                { Self::T::toaltstack() }                                               // {-q_table} {x0_table} {x1_table} {y0} {y1} -> {r} {0/1}

                // cleanup
                for _ in 0..N_LC { { Self::T::drop() } }                // {-q_table} {x0_table} {x1_table} -> {r} {0/1}
                for _ in 0..N_LC { { Self::T::drop_table(VAR_WIDTH) } } // {-q_table} -> {r} {0/1}
                { Self::T::drop_table(MOD_WIDTH) }                      // -> {r} {0/1}

                // correction/validation: r = if q < 0 { r + p } else { r }; assert(r < p)
                { Self::T::push_u32_le(&Self::modulus().to_u32_digits()) } // {MODULUS} -> {r} {0/1}
                { Self::T::fromaltstack() } OP_FROMALTSTACK // {MODULUS} {r} {0/1}
                OP_IF { Self::T::add_ref(1) } OP_ENDIF      // {MODULUS} {-r/r}
                { Self::T::copy(0) }                        // {MODULUS} {-r/r} {-r/r}
                { Self::T::lessthan(0, 2) } OP_VERIFY       // {-r/r}

                // resize res back to N_BITS
                { Self::T::resize::<N_BITS>() } // {r}
        };

        (scr, ops)
    }

    pub fn OP_TMUL_WOTS(&mut self) -> Script
    where
        [(); { Self::N_VAR_BITS } as usize]:,
    {
        self.wots_decode_counter = self.wots_encode_counter;
        let mut get_var_windows = self.get_var_window_script_generator();

        script! {
            // stack: {wr} {q} {wx0} {wx1} {wy0} {wy1}
            for _ in 0..2*N_LC as u32 {
                { self.wots_decode() }
                // range check: U < MODULUS
                { Self::U::copy(0) }                                       // {wr} {q} {x0} {x1} {y0} {y1} {y1}
                { Self::U::push_u32_le(&Self::modulus().to_u32_digits()) } // {wr} {q} {x0} {x1} {y0} {y1} {y1} {MODULUS}
                { Self::U::lessthan(1, 0) } OP_VERIFY                      // {wr} {q} {x0} {x1} {y0} {y1}
                { Self::U::toaltstack() }                                  // {wr} {q} {x0} {x1} {y0} -> {y1}
            }                                                              // {wr} {q} -> {x0} {x1} {y0} {y1}

            { Self::T::toaltstack() }                                      // {rw} -> {q} {x0} {x1} {y0} {y1}
            { self.wots_decode() }                                         // {r} -> {q} {x0} {x1} {y0} {y1}
            { Self::T::fromaltstack() }                                    // {r} {q} -> {x0} {x1} {y0} {y1}

            // pre-compute tables
            // TODO: range check for quotient
            { Self::T::push_zero() }             // {q} {0} -> {x0} {x1} {y0} {y1}
            { Self::T::sub(0, 1) }               // {-q} -> {x0} {x1} {y0} {y1}
            { Self::T::init_table(MOD_WIDTH) }   // {-q_table} -> {x0} {x1} {y0} {y1}
            for i in 0..N_LC {
                { Self::U::fromaltstack() }                   // {-q_table} {x0} -> {x1} {y0} {y1}
                { Self::U::resize::<{ Self::N_VAR_BITS }>() } // {-q_table} {x0} -> {x1} {y0} {y1}
                if !self.lc_signs[i] {
                    { Self::T::push_zero() }             // {q} {x0} {0} -> {x1} {y0} {y1}
                    { Self::T::sub(0, 1) }               // {-q} {-x0} -> {x1} {y0} {y1}
                }
                { Self::T::init_table(VAR_WIDTH) }            // {-q_table} {x0_table} -> {x1} {y0} {y1}
            }                                                 // {-q_table} {x0_table} {x1_table} -> {y0} {y1}
            for _ in 0..N_LC {
                { Self::U::fromaltstack() }                   // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
                { Self::U::resize::<{ Self::N_VAR_BITS }>() } // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
            }                                                 // {-q_table} {x0_table} {x1_table} {y0} {y1}                                                             // {q0} {q1} {x0} {x1} {y0} {y1}
            { Self::T::push_zero() }                          // {-q_table} {x0_table} {x1_table} {y0} {y1} {0}

            // main loop
            for i in Self::MAIN_LOOP_START..=Self::MAIN_LOOP_END {
                // z -= q*p[i]
                if i % MOD_WIDTH == 0 && self.get_mod_window(i/MOD_WIDTH - 1) != 0  {
                    { Self::T::add_ref(1 + Self::N_LC + Self::T::size_table(MOD_WIDTH) +
                        Self::N_LC * Self::T::size_table(VAR_WIDTH) - self.get_mod_window(i/MOD_WIDTH - 1)) }
                }
                // z += x*y[i]
                if i % VAR_WIDTH == 0 {
                    { get_var_windows() }
                    for _ in 1..Self::N_LC { OP_TOALTSTACK }
                    for j in 0..Self::N_LC {
                        if j != 0 { OP_FROMALTSTACK }
                        OP_DUP OP_NOT
                        OP_IF
                            OP_DROP
                        OP_ELSE
                            { 1 + Self::N_LC + (Self::N_LC - j) * Self::T::size_table(VAR_WIDTH)  }
                            OP_SWAP
                            OP_SUB
                            { Self::T::add_ref_stack() }
                        OP_ENDIF
                    }
                }
                if i < Self::MAIN_LOOP_END {
                    if MOD_WIDTH == VAR_WIDTH {
                        if i % VAR_WIDTH == 0 {
                            { Self::T::lshift_prevent_overflow(VAR_WIDTH) }
                        }
                    } else {
                        { Self::T::double_prevent_overflow() }
                    }
                }
            }

            { Self::T::is_positive(Self::T::size_table(MOD_WIDTH) +                       // q was negative
                Self::N_LC * Self::T::size_table(VAR_WIDTH) + Self::N_LC) } OP_TOALTSTACK // {-q_table} {x0_table} {x1_table} {y0} {y1} {r} -> {0/1}
            { Self::T::toaltstack() }                                               // {-q_table} {x0_table} {x1_table} {y0} {y1} -> {r} {0/1}

            // cleanup
            for _ in 0..N_LC { { Self::T::drop() } }                // {-q_table} {x0_table} {x1_table} -> {r} {0/1}
            for _ in 0..N_LC { { Self::T::drop_table(VAR_WIDTH) } } // {-q_table} -> {r} {0/1}
            { Self::T::drop_table(MOD_WIDTH) }                      // -> {r} {0/1}

            // correction/validation: r = if q < 0 { r + p } else { r }; assert(r < p)
            { Self::T::push_u32_le(&Self::modulus().to_u32_digits()) } // {MODULUS} -> {r} {0/1}
            { Self::T::fromaltstack() } OP_FROMALTSTACK // {MODULUS} {r} {0/1}
            OP_IF { Self::T::add_ref(1) } OP_ENDIF      // {MODULUS} {-r/r}
            { Self::T::copy(0) }                        // {MODULUS} {-r/r} {-r/r}
            { Self::T::lessthan(0, 2) } OP_VERIFY       // {-r/r}

            // resize res back to N_BITS
            { Self::T::resize::<N_BITS>() } // {r}
            { Self::U::equal(0, 1) }
        }
    }

    /// Winternitz OTS
    /// WINDOW
    const OTS_WIDTH: u32 = OTS_WIDTH;
    /// Digits are base d+1
    const MAX_DIGIT: u32 = (1 << Self::OTS_WIDTH) - 1;
    /// Number of digits of the message
    const N_DIGITS: u32 = (N_BITS + Self::OTS_WIDTH - 1) / Self::OTS_WIDTH;
    /// Number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
    const C_DIGITS: usize = log(Self::MAX_DIGIT * Self::N_DIGITS, Self::MAX_DIGIT + 1) as usize;
    /// Total number of chains
    const N_CHAINS: u32 = Self::N_DIGITS + Self::C_DIGITS as u32;

    fn wots_biguint_digits(n: &BigUint) -> [u8; Self::N_DIGITS as usize] {
        assert!(n < &Self::modulus(), "n should be smaller than modulus");
        let mut digits = [0; Self::N_DIGITS as usize];
        for i in 0..Self::N_DIGITS {
            let shift_by = Self::OTS_WIDTH * (Self::N_DIGITS - i - 1);
            let bit_mask = BigUint::from_u32((1 << Self::OTS_WIDTH) - 1).unwrap() << shift_by;
            digits[i as usize] = ((n & bit_mask) >> shift_by).to_u8().unwrap();
        }
        digits
    }

    /// Compute the checksum of the message's digits.
    /// Further infos in chapter "A domination free function for Winternitz signatures"
    fn wots_checksum(digits: [u8; Self::N_DIGITS as usize]) -> u32 {
        let mut sum = 0;
        for digit in digits {
            sum += digit as u32;
        }
        Self::MAX_DIGIT * Self::N_DIGITS - sum
    }

    /// Convert a number to digits
    fn wots_digits(mut number: u32) -> [u8; Self::C_DIGITS] {
        let mut digits: [u8; Self::C_DIGITS] = [0; Self::C_DIGITS];
        for i in 0..Self::C_DIGITS {
            let digit = number % (Self::MAX_DIGIT + 1);
            number = (number - digit) / (Self::MAX_DIGIT + 1);
            digits[i] = digit as u8;
        }
        digits
    }

    /// Generate the public key for the i-th digit of the message
    fn wots_public_key(&self, var_index: u32, digit_index: u32) -> Script {
        let mut secret = hex_decode(&self.secret).expect("invalid secret key");
        secret.extend_from_slice(&var_index.to_le_bytes()[..]);
        secret.push(digit_index as u8);
        let mut hash = hash160::Hash::hash(&secret); // first secret, for 0
        for _ in 0..=Self::MAX_DIGIT {
            hash = hash160::Hash::hash(&hash[..]);
        }
        script! {
            { hash.as_byte_array().to_vec() }
        }
    }

    /// Compute the signature for the i-th digit of the message
    fn wots_sign_digit(&self, var_index: u32, digit_index: u32, message_digit: u8) -> Script {
        let mut secret = hex_decode(&self.secret).expect("invalid secret key");
        secret.extend_from_slice(&var_index.to_le_bytes()[..]);
        secret.push(digit_index as u8);
        let mut hash = hash160::Hash::hash(&secret); // first secret, for 0
        for _ in 0..message_digit {
            hash = hash160::Hash::hash(&hash[..]);
        }
        script! {
            {  hash.as_byte_array().to_vec() }
        }
    }

    pub fn wots_encode(&mut self, n: &BigUint) -> Script
    where
        [(); Self::N_DIGITS as usize]:,
        [(); Self::C_DIGITS]:,
    {
        let n_digits = Self::wots_biguint_digits(n);
        let mut digits = Self::wots_digits(Self::wots_checksum(n_digits)).to_vec();
        digits.append(&mut n_digits.to_vec());
        let var_index = self.wots_encode_counter;
        self.wots_encode_counter += 1;
        script! {
            for i in 0..Self::N_CHAINS {
                { self.wots_sign_digit(var_index, i, digits[(Self::N_CHAINS-1-i) as usize]) }
            }
        }
    }

    pub fn wots_decode(&mut self) -> Script {
        self.wots_decode_counter -= 1;
        let var_index = self.wots_decode_counter;

        fn split_digit(window: u32, index: u32) -> Script {
            script! {
                // {v}
                0                           // {v} {A}
                OP_SWAP
                for i in 0..index {
                    OP_TUCK                 // {v} {A} {v}
                    { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
                    OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
                    OP_TUCK                 // {v} {1/0} {A} {1/0}
                    OP_ADD                  // {v} {1/0} {A+1/0}
                    if i < index - 1 { { NMUL(2) } }
                    OP_ROT OP_ROT
                    OP_IF
                        { 1 << (window - i - 1) }
                        OP_SUB
                    OP_ENDIF
                }
                OP_SWAP
            }
        }

        script! {
            for i in 0..Self::N_CHAINS {
                { self.wots_public_key( var_index, Self::N_CHAINS - i - 1) } OP_SWAP
                for j in 0..=Self::MAX_DIGIT {
                    OP_HASH160
                    OP_2DUP OP_EQUAL
                    OP_IF {Self::MAX_DIGIT - j} OP_TOALTSTACK OP_ENDIF
                }
                OP_2DROP
            }
            // compute checksum
            OP_FROMALTSTACK OP_DUP OP_NEGATE
            for _ in 1..Self::N_DIGITS {
                    OP_FROMALTSTACK OP_TUCK OP_SUB
            }
            { Self::MAX_DIGIT * Self::N_DIGITS }
            OP_ADD
            // pre-computed checksum
            OP_FROMALTSTACK
            for _ in 1..Self::C_DIGITS {
                for _ in 0..Self::OTS_WIDTH {
                    OP_DUP OP_ADD
                }
                OP_FROMALTSTACK OP_ADD
            }
            OP_EQUALVERIFY

            // field element reconstruction
            for i in (1..=Self::N_DIGITS).rev() {
                if (i * Self::OTS_WIDTH) % LIMB_SIZE == 0 {
                    OP_TOALTSTACK
                } else if (i * Self::OTS_WIDTH) % LIMB_SIZE > 0 &&
                            (i * Self::OTS_WIDTH) % LIMB_SIZE < Self::OTS_WIDTH {
                    OP_SWAP
                    { split_digit(Self::OTS_WIDTH, (i * Self::OTS_WIDTH) % LIMB_SIZE) }
                    OP_ROT
                    { NMUL(1 << ((i * Self::OTS_WIDTH) % LIMB_SIZE)) }
                    OP_ADD
                    OP_TOALTSTACK
                } else if i != Self::N_DIGITS {
                    { NMUL(1 << Self::OTS_WIDTH) }
                    OP_ADD
                }
            }
            for _ in 1..Self::U::N_LIMBS { OP_FROMALTSTACK }
            for i in 1..Self::U::N_LIMBS { { i } OP_ROLL }
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, RandBigInt, ToBigInt};
    use num_traits::Signed;
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

    fn print_bigint_in_stack_with_limb(n: BigInt, n_bits: u32, limb_size: u32) {
        let mut limbs = bigint_to_uXu8_limbs(n.clone(), n_bits, limb_size);
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
        for i in 1..1 << window {
            res.push(b.clone() * BigInt::from(i));
        }
        res
    }

    #[test]
    fn test_multi_window_mul() {
        const N_LC: usize = 3;
        const VAR_WIDTH: u32 = 3;
        const MOD_WIDTH: u32 = 3;
        type F = Fq<254, 30, MOD_WIDTH, VAR_WIDTH, N_LC, 0>;

        let fq = F::new("".to_string(), [true; N_LC]);

        let zero = &BigInt::ZERO;
        let modulus = &fq.get_modulus().to_bigint().unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let xs = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let ys = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let mut qs = vec![];
        let mut rs = vec![];

        let mut c = zero.clone();
        for i in 0..N_LC {
            let xy = &xs[i] * &ys[i];
            qs.push(&xy / modulus);
            rs.push(&xy % modulus);
            c += if fq.lc_signs[i] { xy } else { -xy };
        }
        let r = &c % modulus;

        // correct quotient
        let q = &(&c / modulus);
        let var_windows = ys
            .iter()
            .map(|var| get_window_decomps(var, VAR_WIDTH, F::MAIN_LOOP_END))
            .collect::<Vec<_>>();
        let qp_table = precompute_lookup_table(&(-q), MOD_WIDTH);
        let xy_tables = xs
            .iter()
            .map(|x| precompute_lookup_table(x, VAR_WIDTH))
            .collect::<Vec<_>>();

        let mut z = BigInt::ZERO;
        for i in F::MAIN_LOOP_START..=F::MAIN_LOOP_END {
            if i % MOD_WIDTH == 0 && fq.get_mod_window(i / MOD_WIDTH - 1) != 0 {
                z += &qp_table[fq.get_mod_window(i / MOD_WIDTH - 1) as usize - 1];
            }
            if i % VAR_WIDTH == 0 {
                for j in 0..N_LC {
                    if var_windows[j][(i / VAR_WIDTH - 1) as usize] != 0 {
                        z += &xy_tables[j][var_windows[j][(i / VAR_WIDTH - 1) as usize] - 1];
                    }
                }
            }
            if i < F::MAIN_LOOP_END {
                z *= 2;
            }
        }
        assert!(z == r);
    }

    fn rand_bools<const SIZE: usize>(seed: u64) -> [bool; SIZE] {
        let mut bools = [true; SIZE];
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(seed);
        for i in 0..SIZE {
            bools[i] = prng.gen_bool(0.5);
        }
        bools
    }

    #[test]
    fn test_multi_window_op_tmul() {
        const N_LC: usize = 13;
        const VAR_WIDTH: u32 = 3;
        const MOD_WIDTH: u32 = 1;
        type F = Fq<254, 30, MOD_WIDTH, VAR_WIDTH, N_LC, 0>;

        let fq = F::new("".to_string(), rand_bools(0));

        println!("script size: {}", fq.OP_TMUL().0.len());

        let zero = &BigInt::ZERO;
        let modulus = &fq.get_modulus().to_bigint().unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let xs = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let ys = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let mut qs = vec![];
        let mut rs = vec![];

        let mut c = zero.clone();
        for i in 0..F::N_LC as usize {
            let xy = &xs[i] * &ys[i];
            qs.push(&xy / modulus);
            rs.push(&xy % modulus);
            c += if fq.lc_signs[i] { xy } else { -xy };
        }
        let r = &c % modulus;
        let r = &(if r.is_negative() { modulus + r } else { r });

        // correct quotient
        let q = &(&c / modulus);
        let script = script! {
            { F::T::push_u32_le(&bigint_to_u32_limbs(q.clone(), F::T::N_BITS)) }
            for i in 0..N_LC {
                { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
            }
            for i in 0..N_LC {
                { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
            }
            { fq.OP_TMUL().0 }
            { F::U::push_u32_le(&r.to_u32_digits().1) }
            { F::U::equal(0, 1) }
        };
        let res = execute_script(script);
        assert!(res.success);

        // incorrect q
        let q = &loop {
            let rnd = prng.gen_bigint_range(zero, modulus);
            if rnd != *q {
                break rnd;
            }
        };
        let script = script! {
            { F::T::push_u32_le(&bigint_to_u32_limbs(q.clone(), F::T::N_BITS)) }
            for i in 0..N_LC {
                { F::U::push_u32_le(&xs[i].to_u32_digits().1) }
            }
            for i in 0..N_LC {
                { F::U::push_u32_le(&ys[i].to_u32_digits().1) }
            }
            { fq.OP_TMUL().0 }
            { F::U::push_u32_le(&r.to_u32_digits().1) }
            { F::U::equal(0, 1) }
        };
        let res = execute_script(script);
        assert!(!res.success);
    }

    #[test]
    fn test_multi_window_op_tmul_wots() {
        let secret = hex::encode("my_secret_key");

        const N_LC: usize = 6;
        const VAR_WIDTH: u32 = 3;
        const MOD_WIDTH: u32 = 3;
        const OTS_WIDTH: u32 = 4;
        type F = Fq<254, 30, MOD_WIDTH, VAR_WIDTH, N_LC, OTS_WIDTH>;

        let mut fq = F::new(secret, rand_bools(0));

        let zero = &BigInt::ZERO;
        let modulus = &fq.get_modulus().to_bigint().unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let xs = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let ys = (0..F::N_LC)
            .map(|_| prng.gen_bigint_range(zero, modulus))
            .collect::<Vec<_>>();
        let mut qs = vec![];
        let mut rs = vec![];

        let mut c = zero.clone();
        for i in 0..F::N_LC as usize {
            let xy = &xs[i] * &ys[i];
            qs.push(&xy / modulus);
            rs.push(&xy % modulus);
            c += if fq.lc_signs[i] { xy } else { -xy };
        }
        let r = &c % modulus;
        let r = &(if r.is_negative() { modulus + r } else { r });

        // correct quotient
        let q = &(&c / modulus);
        let script = script! {
            { fq.wots_encode(&r.to_biguint().unwrap())}
            { F::T::push_u32_le(&bigint_to_u32_limbs(q.clone(), F::T::N_BITS)) }
            for i in 0..N_LC {
                { fq.wots_encode(&xs[i].to_biguint().unwrap())}
            }
            for i in 0..N_LC {
                { fq.wots_encode(&ys[i].to_biguint().unwrap())}
            }
            { fq.OP_TMUL_WOTS() }
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
        println!("script: {}", fq.OP_TMUL_WOTS().len());
        println!("max stack: {}", res.stats.max_nb_stack_items);
    }

    #[test]
    #[cfg(feature = "ignore:bench")]
    fn test_multi_window_op_tmul_bench() {
        const N_LC: usize = 1;
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let modulus = Fq::<254, 30, 1, 1, N_LC, 0>::modulus();
        let x = prng.gen_biguint_below(&modulus);
        let y = prng.gen_biguint_below(&modulus);
        let c = &x * &y;
        let q = &c / &modulus;
        let r = &c % &modulus;

        let mut stats = vec![];

        seq!(VAR_WIDTH in 1..=6 {
            seq!(MOD_WIDTH in 1..=6 { {
                type F = Fq<254, 30, VAR_WIDTH, MOD_WIDTH, N_LC, 0>;
                let fq = F::new("".to_string(), [true; N_LC]);
                let script = script! {
                    { F::U::push_u32_le(&q.to_u32_digits()) }
                    { F::U::push_u32_le(&x.to_u32_digits()) }
                    { F::U::push_u32_le(&y.to_u32_digits()) }
                    { fq.OP_TMUL().0 }
                    { F::U::push_u32_le(&r.to_u32_digits()) }
                    { F::U::equalverify(0, 1) }
                    OP_TRUE
                };
                // fs::write("~/fq_op_tmul_script.txt", script.clone().compile().to_string()).unwrap();
                let res = execute_script(script);
                if VAR_WIDTH == 6 && VAR_WIDTH == MOD_WIDTH { // skip stack limit exceeding muls
                    let (scr, ops) = fq.OP_TMUL();
                    stats.push((format!("{}Y-{}P", VAR_WIDTH, MOD_WIDTH),scr.len(), 1000, ops));
                } else {
                    // assert!(res.success);
                    let (scr, ops) = fq.OP_TMUL();
                    stats.push((format!("{}Y-{}P", VAR_WIDTH, MOD_WIDTH), scr.len(), res.stats.max_nb_stack_items, ops));
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
                "254-bit-{}: script: {:6}, stack: {:4}, [D={:3}, A=({:3}, {:3})]",
                stat.0, stat.1, stat.2, stat.3 .0, stat.3 .1, stat.3 .2
            );
        }
    }
}
