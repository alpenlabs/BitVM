use num_bigint::BigUint;
use num_traits::Num;
use std::cmp::Ordering;
use std::str::FromStr;

use crate::bigint::BigIntImpl;
use crate::pseudo::{push_to_stack, NMUL};
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }
        bits.resize(N_BITS as usize, false);

        let mut limbs = vec![];
        for chunk in bits.chunks(LIMB_SIZE as usize) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(LIMB_SIZE as usize, false);

            let mut elem = 0u32;
            for (i, chunk_i) in chunk_vec.iter().enumerate() {
                if *chunk_i {
                    elem += 1 << i;
                }
            }

            limbs.push(elem);
        }

        limbs.reverse();

        script! {
            for limb in &limbs {
                { *limb }
            }
            { push_to_stack(0,Self::N_LIMBS as usize - limbs.len()) }
        }
    }

    pub fn push_u64_le(v: &[u64]) -> Script {
        let v = v
            .iter()
            .flat_map(|v| {
                [
                    (v & 0xffffffffu64) as u32,
                    ((v >> 32) & 0xffffffffu64) as u32,
                ]
            })
            .collect::<Vec<u32>>();

        Self::push_u32_le(&v)
    }

    /// Zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a }
                    OP_ROLL
                    { b + i + 1 }
                    OP_ROLL
                }
            }
        }
    }

    pub fn copy_zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_PICK { b + 1 + i } OP_PICK
            }
        }
    }

    pub fn dup_zip(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_ROLL OP_DUP
            }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            if a < 134 {
                for _ in 0..Self::N_LIMBS {
                    { a } OP_PICK
                }
            } else {
                { a + 1 }
                for _ in 0..Self::N_LIMBS - 1 {
                    OP_DUP OP_PICK OP_SWAP
                }
                OP_1SUB OP_PICK
            }
        }
        .add_stack_hint(-(Self::N_LIMBS as i32), Self::N_LIMBS as i32)
    }

    pub fn roll(mut a: u32) -> Script {
        if a == 0 {
            return script! {};
        }
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for _ in 0..Self::N_LIMBS {
                { a } OP_ROLL
            }
        }
    }

    pub fn drop() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS / 2 {
                OP_2DROP
            }
            if Self::N_LIMBS & 1 == 1 {
                OP_DROP
            }
        }
    }

    pub fn push_dec(dec_string: &str) -> Script {
        Self::push_u32_le(&BigUint::from_str(dec_string).unwrap().to_u32_digits())
    }

    pub fn push_hex(hex_string: &str) -> Script {
        Self::push_u32_le(
            &BigUint::from_str_radix(hex_string, 16)
                .unwrap()
                .to_u32_digits(),
        )
    }

    #[inline]
    pub fn push_zero() -> Script {
        push_to_stack(0, Self::N_LIMBS as usize)
    }

    #[inline]
    pub fn push_one() -> Script {
        script! {
            { push_to_stack(0,(Self::N_LIMBS - 1) as usize) }
            1
        }
    }

    pub fn is_zero_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for i in 0..Self::N_LIMBS {
                { a + i+1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_zero(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for _ in 0..Self::N_LIMBS {
                { a +1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_PICK
            1 OP_EQUAL OP_BOOLAND
            for i in 1..Self::N_LIMBS {
                { a + i + 1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_ROLL
            1 OP_EQUAL OP_BOOLAND
            for _ in 1..Self::N_LIMBS {
                { a + 1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_TOALTSTACK
            }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
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
            { Self::is_zero_keep_element(depth) } OP_NOT
            { (1 + depth) * Self::N_LIMBS } OP_PICK
            { Self::HEAD_OFFSET >> 1 }
            OP_LESSTHAN OP_BOOLAND
        }
    }

    /// Resize positive numbers
    ///
    /// # Note
    ///
    /// Does not work for negative numbers
    pub fn resize<const T_BITS: u32>() -> Script {
        let n_limbs_self = N_BITS.div_ceil(LIMB_SIZE);
        let n_limbs_target = T_BITS.div_ceil(LIMB_SIZE);

        match n_limbs_target.cmp(&n_limbs_self) {
            Ordering::Equal => script! {},
            Ordering::Greater => {
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
            Ordering::Less => {
                let n_limbs_to_remove = n_limbs_self - n_limbs_target;
                script! {
                    for _ in 0..n_limbs_to_remove {
                        { n_limbs_target } OP_ROLL OP_DROP
                    }
                }
            }
        }
    }

    /// Unpacks the limbs of the big integer into smaller parts (nibbles) based on a given window size.
    ///
    /// This function decomposes the limbs of a `BigIntImpl` into smaller components  
    /// determined by the specified `WINDOW` size.

    pub fn unpack_limbs<const WINDOW: u32>() -> Script {
        let n_digits: u32 = (N_BITS + WINDOW - 1) / WINDOW;
        println!("n_digits: {}", n_digits);

        script! {
            { Self::toaltstack() }
            for iter in (1..=n_digits).rev() {
                {{
                    let s_bit = iter * WINDOW - 1; // start bit
                    let e_bit = (iter - 1) * WINDOW; // end bit

                    let s_limb = s_bit / LIMB_SIZE; // start bit limb
                    let e_limb = e_bit / LIMB_SIZE; // end bit limb

                    let mut st = 0;
                    if (e_bit % LIMB_SIZE == 0) || (s_limb > e_limb) {
                        st = (s_bit % LIMB_SIZE) + 1;
                    }
                    script! {
                        if iter == n_digits { // initialize accumulator to track reduced limb
                            OP_FROMALTSTACK
                        } else if (s_bit + 1) % LIMB_SIZE == 0  { // drop current and initialize next accumulator
                            OP_DROP OP_FROMALTSTACK
                        }

                        if (e_bit % LIMB_SIZE == 0) || (s_limb > e_limb) {
                            if s_limb > e_limb {
                                { NMUL(2) }
                            } else {
                                0
                            }
                        }
                        for i in st..WINDOW {
                            if s_limb > e_limb {
                                if i % LIMB_SIZE == (s_bit % LIMB_SIZE) + 1 {
                                    // window is split between multiple limbs
                                    OP_FROMALTSTACK
                                }
                            }
                            if i == 0 {
                                { 1 << ((s_bit - i) % LIMB_SIZE) }
                                OP_2DUP
                                OP_GREATERTHANOREQUAL
                                OP_IF
                                    OP_SUB
                                    2
                                OP_ELSE
                                    OP_DROP
                                    0
                                OP_ENDIF
                                OP_SWAP
                            } else{
                                if (s_bit - i) % LIMB_SIZE > 7 {
                                    { 1 << ((s_bit - i) % LIMB_SIZE) }
                                    OP_2DUP
                                    OP_GREATERTHANOREQUAL
                                    OP_IF
                                        OP_SUB
                                        OP_SWAP OP_1ADD
                                    OP_ELSE
                                        OP_DROP
                                        OP_SWAP
                                    OP_ENDIF
                                    if i < WINDOW - 1 { { NMUL(2) } }
                                    OP_SWAP
                                } else {
                                    OP_TUCK
                                    { (1 << ((s_bit - i) % LIMB_SIZE)) - 1 }
                                    OP_GREATERTHAN
                                    OP_TUCK
                                    OP_ADD
                                    if i < WINDOW - 1 { { NMUL(2) } }
                                    OP_ROT OP_ROT
                                    OP_IF
                                        { 1 << ((s_bit - i) % LIMB_SIZE) }
                                        OP_SUB
                                    OP_ENDIF
                                }
                            }
                        }
                    }

                }}
            }
            OP_DROP // drop accumulator
        }
    }

    pub fn split_digit(window: u32, index: u32) -> Script {
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

    pub fn pack_limbs<const WINDOW: u32>() -> Script {
        let n_digits: u32 = (N_BITS + WINDOW - 1) / WINDOW;
        print!("n_digits :: {}\n",n_digits);

        let n_limbs: u32 = N_BITS.div_ceil(LIMB_SIZE);
        print!("n_limbs :: {}\n",n_limbs);

        for i in (1..=n_digits).rev(){
            println!("for i = {}, modulo = {}", i , (i * WINDOW) % LIMB_SIZE < WINDOW);
        }

        script! {
            for i in 1..n_digits { { i } OP_ROLL }
            for i in (1..=n_digits).rev() {
                if (i * WINDOW) % LIMB_SIZE == 0 {
                    OP_TOALTSTACK
                }
                 else if (i * WINDOW) % LIMB_SIZE > 0 &&
                            (i * WINDOW) % LIMB_SIZE < WINDOW {
                    OP_SWAP
                    { Self::split_digit(WINDOW, (i * WINDOW) % LIMB_SIZE) }
                    OP_ROT
                    { NMUL(1 << ((i * WINDOW) % LIMB_SIZE)) }
                    OP_ADD
                    OP_TOALTSTACK
                }
                 else if i != n_digits {
                    { NMUL(1 << WINDOW) }
                    OP_ADD
                }
            }
            for _ in 1..n_limbs { OP_FROMALTSTACK }
            for i in 1..n_limbs { { i } OP_ROLL }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::pseudo::{push_to_stack, NMUL};
    use crate::bigint::{BigIntImpl, U254, U64};
    use crate::{execute_script, run};
    use crate::treepp::script;
    use bitcoin::opcodes::all::{OP_FROMALTSTACK, OP_TOALTSTACK};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: u32 = 1450;
        const N_U30_LIMBS: u32 = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_copy() {
        println!("U254.copy(0): {} bytes", U254::copy(0).len());
        println!("U254.copy(13): {} bytes", U254::copy(13).len());
        println!("U254.copy(14): {} bytes", U254::copy(14).len());
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_roll() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::roll(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_copy_zip() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::dup_zip(1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn push_hex() {
        run(script! {
            { U254::push_hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47") }
            { 0x187cfd47 } OP_EQUALVERIFY // 410844487
            { 0x10460b6 } OP_EQUALVERIFY // 813838427
            { 0x1c72a34f } OP_EQUALVERIFY // 119318739
            { 0x2d522d0 } OP_EQUALVERIFY // 542811226
            { 0x1585d978 } OP_EQUALVERIFY // 22568343
            { 0x2db40c0 } OP_EQUALVERIFY // 18274822
            { 0xa6e141 } OP_EQUALVERIFY // 436378501
            { 0xe5c2634 } OP_EQUALVERIFY // 329037900
            { 0x30644e } OP_EQUAL // 12388
        });
    }

    #[test]
    fn test_unpack_limbs_to_nibbles() {
        const WINDOW: u32 = 4;

        println!(
            "U254::unpack_limbs().len: {}",
            U254::unpack_limbs::<WINDOW>().len()
        );

        let hex_str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

        let script = script! {
            { U254::push_hex(hex_str) }
            { U254::unpack_limbs::<WINDOW>() }
            for i in hex_str.chars().rev().map(|c| c.to_digit(16).unwrap() as u8) {
                { i } OP_EQUALVERIFY
            }
            OP_TRUE
        };

        run(script);
    }

    #[test]
    fn test_pack_nibbles_to_limbs() {
        const WINDOW: u32 = 4;

        println!(
            "U254::pack_limbs().len: {}",
            U254::pack_limbs::<WINDOW>().len()
        );

        let hex_str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

        let script = script! {
            for i in hex_str.chars().map(|c| c.to_digit(16).unwrap() as u8) {
                { i }
            }
            { U254::pack_limbs::<WINDOW>() }
            { U254::unpack_limbs::<WINDOW>()}
            // { U254::push_hex(hex_str) }

            // for i in (1..10).rev(){
            // {i}
            // OP_ROLL
            // OP_EQUALVERIFY
            // }
            // OP_TRUE
        };

        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    #[test]
    fn test_pack_unpack_u210() {
        const WINDOW: u32 = 3;
        const N_BITS: u32 = 210;
        const LIMB_SIZE: u32 = 30;

        type U210 = BigIntImpl<N_BITS, LIMB_SIZE>;

        let script = script! {
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }
            // { 0b111111111111111111111111111111 }

            // { U210::unpack_limbs::<WINDOW>() }

            for _ in 0..70{
                {0b111}
            }

            { U210::pack_limbs::<WINDOW>() }

        };
        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    #[test]
    fn test_pack_unpack_u64() {
        const WINDOW: u32 = 4;

        let script = script! {

            { 0b1111111111111111 }
            { 0b1111111111111111 }
            { 0b1111111111111111 }
            { 0b1111111111111111 }

            { U64::unpack_limbs::<WINDOW>() }
            // { U64::pack_limbs::<WINDOW>()}
        };
        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    #[test]
    fn test_pack_unpack_u254() {
        const WINDOW: u32 = 4;

        let script = script! {
            { 0b10101010101000010101110100101 }
            { 0b01010100101010000000101010101 }
            { 0b11010010100101001010101001010 }
            { 0b00101010001110110001010110101 }
            { 0b00010101001010101111111101001 }
            { 0b10111110101010100101001011001 }
            { 0b00001010100101010001010100101 }
            { 0b01111010101010110100100010000 }
            { 0b00010100101001010101001010101 }

            { U254::unpack_limbs::<WINDOW>() }
            { U254::pack_limbs::<WINDOW>() }
            { U254::unpack_limbs::<WINDOW>() }
            { U254::pack_limbs::<WINDOW>() }


            { 0b10101010101000010101110100101 }
            { 0b01010100101010000000101010101 }
            { 0b11010010100101001010101001010 }
            { 0b00101010001110110001010110101 }
            { 0b00010101001010101111111101001 }
            { 0b10111110101010100101001011001 }
            { 0b00001010100101010001010100101 }
            { 0b01111010101010110100100010000 }
            { 0b00010100101001010101001010101 }

            for i in (2..10).rev(){
                {i}
                OP_ROLL
                OP_EQUALVERIFY
            }
            OP_EQUALVERIFY
            OP_TRUE

        };
        println!("Script : {:?}", script.clone().compile());
        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        // let exec_result = execute_script(script);
        // assert!(exec_result.success);
    }

    #[test]
    fn test_split_digits() {
        const WINDOW: u32 = 4;

        let script = script! {
            { 0b10101010101000010101110100101 }
            { 0b01010100101010000000101010101 }
            { 0b11010010100101001010101001010 }
            { 0b00101010001110110001010110101 }
            { 0b00010101001010101111111101001 }
            { 0b10111110101010100101001011001 }
            { 0b00001010100101010001010100101 }
            { 0b01111010101010110100100010000 }
            { 0b00010100101001010101001010101 }

            {U254::split_digit(7,4)}


        };

        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    // 12 bits into window of 5 should take 3 limbs bit only 2 stack elements are shown.
    #[test]
    fn test_pack_unpack_u12() {
        const WINDOW: u32 = 5;
        const N_BITS: u32 = 12;
        const LIMB_SIZE: u32 = 6;

        type U12 = BigIntImpl<N_BITS, LIMB_SIZE>;

        let script = script! {
            // { 0b1}
            { 0b111111}
            { 0b111111}

            { U12::unpack_limbs::<WINDOW>() }
            OP_FROMALTSTACK
            // { U12::pack_limbs::<WINDOW>() }
            // { U12::unpack_limbs::<WINDOW>() }
            // { U12::pack_limbs::<WINDOW>() }

        };

        println!("Script : {:?}", script.clone().compile());
        let res = crate::execute_script(script);
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }


    #[test]
    fn test_popfromemptystack(){
        let script = script!(
            // OP_FALSE
            OP_TOALTSTACK
            OP_TRUE
        );


        println!("Script : {:?}", script.clone().compile());
        let res = crate::execute_script(script.clone());
        for i in 0..res.final_stack.len() {
            if res.final_stack.get(i).is_empty() {
                println!("Pos : {} -- Value : {:?}", i, res.final_stack.get(i));
            } else {
                println!(
                    "Pos : {} -- Value : {}",
                    i,
                    res.final_stack
                        .get(i)
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }

        let exec_result = execute_script(script);
        assert!(exec_result.success); 

    }
}
