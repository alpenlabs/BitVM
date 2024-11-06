use crate::bigint::U254;
use crate::bn254::utils::fq_push_not_montgomery;
use crate::chunk::blake3compiled;
use crate::pseudo::NMUL;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use std::cmp::min;

use crate::bn254::utils::fr_push_not_montgomery;

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
        // OP_SWAP
    }
}

pub fn unpack_limbs_to_nibbles() -> Script {
    script! {
        {8}
        OP_ROLL
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-1 + 6}
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}

        {NMUL(8)}
        {8-2 + 6+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-3 + 6+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-4 + 6+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-5 + 6+8+7+7+7} //
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}

        {NMUL(8)}
        {8-6 + 6+8+7+7+7+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-7 + 6+8+7+7+7+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-8 + 6+8+7+7+7+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

    }
}

pub fn pack_nibbles_to_limbs() -> Script {
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

    const WINDOW: u32 = 4;
    const LIMB_SIZE: u32 = 29;
    const N_BITS: u32 = U254::N_BITS;
    const N_DIGITS: u32 = (N_BITS + WINDOW - 1) / WINDOW;

    script! {
        for i in 1..64 { { i } OP_ROLL }
        for i in (1..=N_DIGITS).rev() {
            if (i * WINDOW) % LIMB_SIZE == 0 {
                OP_TOALTSTACK
            } else if (i * WINDOW) % LIMB_SIZE > 0 &&
                        (i * WINDOW) % LIMB_SIZE < WINDOW {
                OP_SWAP
                { split_digit(WINDOW, (i * WINDOW) % LIMB_SIZE) }
                OP_ROT
                { NMUL(1 << ((i * WINDOW) % LIMB_SIZE)) }
                OP_ADD
                OP_TOALTSTACK
            } else if i != N_DIGITS {
                { NMUL(1 << WINDOW) }
                OP_ADD
            }
        }
        for _ in 1..U254::N_LIMBS { OP_FROMALTSTACK }
        for i in 1..U254::N_LIMBS { { i } OP_ROLL }
    }
}

// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb

pub(crate) fn hash_fp2() -> Script {
    script! {
        { Fq::toaltstack() }
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { blake3compiled::hash_64b_75k() }
        { pack_nibbles_to_limbs() }
    }
}

pub(crate) fn hash_fp4() -> Script {
    script! {
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }

        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack()}
        { unpack_limbs_to_nibbles() }
        { blake3compiled::hash_128b_168k() }
        { pack_nibbles_to_limbs() }
    }
}

// msg to nibbles
pub(crate) fn emulate_extern_hash_fps(msgs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 6);
    let scr = script! {
        for i in 0..msgs.len() {
            {fq_push_not_montgomery(msgs[i])}
        }
        if msgs.len() == 4 {
            {hash_fp4()}
        } else if msgs.len() == 12 {
            if mode {
                {hash_fp12()}
            } else {
                {hash_fp12_192()}
            }
        } else if msgs.len() == 2 {
            {hash_fp2()}
        } else if msgs.len() == 6 {
            {hash_fp6()}
        }
        {unpack_limbs_to_nibbles()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u8; 64];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        if v.is_empty() {
            arr[i] = 0;
        } else {
            arr[i] = v[0];
        }
    }
    arr
}

pub(crate) fn emulate_extern_hash_nibbles(msgs: Vec<[u8; 64]>) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12);
    let scr = script! {
        for i in 0..msgs.len() {
            for j in 0..msgs[i].len() {
                {msgs[i][j]}
            }
            {pack_nibbles_to_limbs()} // pack only to unpack later, inefficient but ok for being emulated
        }
        if msgs.len() == 4 {
            {hash_fp4()}
        } else if msgs.len() == 12 {
            {hash_fp12()}
        } else if msgs.len() == 2 {
            {hash_fp2()}
        }
        {unpack_limbs_to_nibbles()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u8; 64];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        if v.is_empty() {
            arr[i] = 0;
        } else {
            arr[i] = v[0];
        }
    }
    arr
}

pub(crate) fn emulate_fq_to_nibbles(msg: ark_bn254::Fq) -> [u8; 64] {
    let scr = script! {
        {fq_push_not_montgomery(msg)}
        {unpack_limbs_to_nibbles()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u8; 64];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        if v.is_empty() {
            arr[i] = 0;
        } else {
            arr[i] = v[0];
        }
    }
    arr
}

pub(crate) fn emulate_fr_to_nibbles(msg: ark_bn254::Fr) -> [u8; 64] {
    let scr = script! {
        {fr_push_not_montgomery(msg)}
        {unpack_limbs_to_nibbles()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u8; 64];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        if v.is_empty() {
            arr[i] = 0;
        } else {
            arr[i] = v[0];
        }
    }
    arr
}

pub(crate) fn emulate_nibbles_to_limbs(msg: [u8; 64]) -> [u32; 9] {
    let scr = script! {
        for i in 0..msg.len() {
            {msg[i]}
        }
        {pack_nibbles_to_limbs()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u32; 9];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        let mut w: [u8; 4] = [0u8; 4];
        for j in 0..min(v.len(), 4) {
            w[j] = v[j];
        }
        arr[i] = u32::from_le_bytes(w);
    }
    arr
}

pub(crate) fn hash_fp12() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

        // second part

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }


        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }

        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

    }
}

pub(crate) fn hash_fp6() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        for _ in 0..5 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

    }
}

pub(crate) fn hash_fp12_192() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_192b_252k = blake3compiled::hash_192b_252k();

    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }
        {unpack_limbs_to_nibbles() }
        for _ in 0..5 {
            { Fq::fromaltstack()}
            {unpack_limbs_to_nibbles()}
        }
        {hash_192b_252k.clone()}
        {pack_nibbles_to_limbs()}

        for _ in 0..6 {
            { Fq::fromaltstack()}
            {unpack_limbs_to_nibbles()}
        }
        {hash_192b_252k}
        for _ in 0..9 {
            {64+8} OP_ROLL
        }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k}
        {pack_nibbles_to_limbs()}
    }
}

// 6Fp_hash
// fp6
pub fn hash_fp12_with_hints() -> Script {
    let hash_64b_75k = blake3compiled::hash_64b_75k();
    let hash_128b_168k = blake3compiled::hash_128b_168k();

    script! {
        {Fq::toaltstack()} //Hc0
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }

        { unpack_limbs_to_nibbles() }
        { Fq::fromaltstack() }
        { unpack_limbs_to_nibbles() }
        {hash_64b_75k.clone()}
        { pack_nibbles_to_limbs() }

        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { Fq::fromaltstack() }
        {unpack_limbs_to_nibbles()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}

        // wrap up
        {Fq::fromaltstack()}
        {unpack_limbs_to_nibbles()}
        {hash_64b_75k.clone()}
        {pack_nibbles_to_limbs()}

    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;
    use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{
        bigint::U254,
        bn254::{fp254impl::Fp254Impl, fq::Fq, utils::fq_push_not_montgomery},
        chunk::{
            evaluate::nib_to_byte_array,
            primitves::unpack_limbs_to_nibbles,
            wots::{wots_p160_sign_digits, wots_p256_sign_digits},
        },
        execute_script,
        signatures::wots::{
            wots128::compact::{get_signature, get_signature2},
            wots160, wots256,
        },
    };

    #[test]
    fn test_fq_from_nibbles() {
        // pack_nibbles_to_fq
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::Fq::rand(&mut prng);

        let mut nib32 = [15u8; 64];
        let script = script! {
             {fq_push_not_montgomery(ark_bn254::Fq::ONE)}
             {unpack_limbs_to_nibbles()}
             //{Fq::add(1, 0)}
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
    }

    #[test]
    fn test_emq() {
        let mut prng = ChaCha20Rng::seed_from_u64(100);
        let p = ark_bn254::Fq::rand(&mut prng);
        let pb1 = emulate_fq_to_nibbles(p);


        println!("pb1 {:?}", pb1);
        // let pbarr = nib_to_byte_array(&pb)[12..32].to_vec();
        // //let pbcomparr = p.into_bigint().to_bytes_le();
        // //println!("nbs {:?}", pb);
        // //println!("pbarr {:?}", pbarr);
        // //println!("pbcomparr {:?}", pbcomparr);
        // println!("orig {:?}", pb);

        // let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        // let res = wots160::get_signature(secret, &pbarr);
        // let mut nbcoll = vec![];
        // for (k, v) in res {
        //     nbcoll.push(v);
        // }

        // let mut nbcoll = nbcoll[0..40].to_vec();
        // nbcoll.reverse();
        // for chunk in nbcoll.chunks_exact_mut(2) {
        //     chunk.swap(0, 1);
        // }

        // // let pbarr = nib_to_byte_array(&nbcoll);
        // println!("nbcoll {:?}", nbcoll);
    }
}
