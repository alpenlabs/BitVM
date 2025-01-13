use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, fq6::Fq6}, hash::blake3_u4, treepp::*};
use bitcoin_script_stack::stack::StackTracker;

use super::primitves::{hash_fp12, hash_fp6};


fn wrap_scr(scr: Script) -> Script {
    script! {
        { scr }
        for _ in 0..(64-40)/2 { OP_2DROP }
        for _ in 0..40 { OP_TOALTSTACK }
        for _ in 0..(64-40) { 0 }
        for _ in 0..40 { OP_FROMALTSTACK  }
    }
}

pub fn hash_64b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4::blake3(&mut stack, 64, 8, Some(true));
    wrap_scr(stack.get_script())
}

pub fn hash_128b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4::blake3(&mut stack, 128, 8, Some(false));
    wrap_scr(stack.get_script())
}

pub fn hash_192b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4::blake3(&mut stack, 192, 8, Some(false));
    wrap_scr(stack.get_script())
}

pub fn hash_messages(elem_types: Vec<u32>) -> Script {
    // Altstack: [Hc, Hb, Ha]
    // Stack: [a, b, c]
    let mut loop_script = script!();
    for msg_index in 0..elem_types.len() {

        // send other elems to altstack
        let mut remaining = elem_types[msg_index+1..].to_vec();
        let mut from_altstack = script!();
        for rem_index in &remaining {
            from_altstack = script!(
                {from_altstack}
                if *rem_index == 12 {
                    {Fq12::fromaltstack()}
                } else if *rem_index == 6 {
                    {Fq6::fromaltstack()}
                } 
            );
        }
        remaining.reverse();
        let mut to_altstack = script!();
        for rem_index in &remaining {
            to_altstack = script!(
                {to_altstack}
                if *rem_index == 12 {
                    {Fq12::toaltstack()}
                } else if *rem_index == 6 {
                    {Fq6::toaltstack()}
                } 
            );
        }

        // hash remaining element
        let cur_elem = elem_types[msg_index];
        let hash_scr = script!(
            if cur_elem == 12 {
                {hash_fp12()}
            } else if cur_elem == 6 {
                {hash_fp6()}
            }
        );

        let verify_scr = script!(
            for _ in 0..Fq::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL 
            }
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)}
            if msg_index == elem_types.len()-1 {
                OP_NOT
            }
            OP_VERIFY
        );
        loop_script = script!(
            {loop_script}
            {to_altstack}
            {hash_scr}
            {from_altstack}
            {verify_scr}
        );
    }
    loop_script
}

#[cfg(test)]
mod test {

    use ark_ff::Field;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, utils::{fq12_push_not_montgomery, fq6_push_not_montgomery, fq_push_not_montgomery}}, chunk::primitves::{extern_hash_fps, extern_nibbles_to_limbs}};

    use super::*;

    #[test]
    fn test_sth() {
        let hash_scr = hash_messages(vec![12, 6]);
        let a = ark_bn254::Fq12::ONE;
        let b = ark_bn254::Fq6::ONE + ark_bn254::Fq6::ONE;
        let ahash = extern_hash_fps(a.to_base_prime_field_elements().collect(), true);
        let bhash = extern_hash_fps(b.to_base_prime_field_elements().collect(), true);
        let tap_len = hash_scr.len();
        let script = script!(
            for i in extern_nibbles_to_limbs(bhash) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(ahash) {
                {i}
            }
            {Fq::toaltstack()}
            {fq12_push_not_montgomery(a)}
            {fq6_push_not_montgomery(b)}
            {hash_scr}
            OP_TRUE
        );
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        // assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }
}
