use std::collections::HashMap;

use bitcoin_script_stack::stack::StackTracker;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::chunk::primitves::{unpack_limbs_to_nibbles,pack_nibbles_to_limbs};

use crate::hash::blake3_u4::{compress, get_flags_for_block, TablesVars};

const USE_FULL_TABLES: bool = false;

pub fn blake3_u4_compact(stack: &mut StackTracker, msg_len: u32, define_var: bool) {
    // we require that the msg_len be a multiple of 64 bytes, this makes padding unnecessary
    assert!(msg_len % 64 == 0, "Value is not a multiple of 64");

    // We require message take atmost a chunk. i.e, 1024 bytes. 
    // Currently hash of empty string is not supported. I guess we could just hardcode and return the value
    assert!(msg_len > 0 && msg_len <= 1024, "msg length must be greater than 0 and less than or equal to 1024 bytes");

    //number of msg blocks
    let num_blocks = msg_len / 64;

    if define_var {
        for i in 0..num_blocks {
            stack.define(9, &format!("msg{}p1", i));
            stack.define(9, &format!("msg{}p0", i));
        }
    }

    for i in 0..num_blocks {
        // let last_round: bool = i == num_blocks - 1;

        stack.custom(
            script!(
                {unpack_limbs_to_nibbles()}
                for _ in 0..64{
                    OP_TOALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p1", i),
        );

        stack.custom(
            script!(
                {unpack_limbs_to_nibbles()}
                for _ in 0..64{
                    OP_FROMALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        //make a hashmap of msgs
        let mut original_message = Vec::new();
        for i in 0..16 {
            let m = stack.define(8, &format!("msg_{}", i));
            original_message.push(m);
        }

        //initialize the tables
        let tables = TablesVars::new(stack, USE_FULL_TABLES);

        // create the current block message map
        let mut message = HashMap::new();
        for m in 0..16 {
            message.insert(m as u8, original_message[m as usize]);
        }

        compress(
            stack,
            i != 0,
            0,
            64,
            get_flags_for_block(i, num_blocks),
            message,
            &tables,
            8,
            i == num_blocks - 1,
        );

        //delete 8 states
        for _ in 0..8 {
            stack.drop(stack.get_var_from_stack(0));
        }

        //delete tables
        for _ in 0..5 {
            stack.drop(stack.get_var_from_stack(0));
        }

        //delete 16 msg words
        for _ in 0..16 {
            stack.drop(stack.get_var_from_stack(0));
        }
    }
}

#[cfg(test)]
mod tests {

    pub use bitcoin_script::script;
    use bitcoin_script_stack::stack::StackTracker;
    use num_traits::ToBytes;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::u4::u4_std::u4_hex_to_nibbles;
    fn test_blake3_compact(msg_len: u32) {
        //make sure that the message length is a multiple of 64 bytes
        assert!(
            msg_len % 64 == 0,
            "Message length must be a multiple of 64 bytes"
        );

        let mut stack = StackTracker::new();

        // generate random bytes as u32 numbers.
        let mut prng = ChaCha20Rng::seed_from_u64(42);
        let nu32_arr: Vec<u32> = (0..(msg_len / 4)).into_iter().map(|_| prng.gen()).collect();
        let nu32_byte_arr = nu32_arr
            .iter()
            .flat_map(|i| (i).to_le_bytes())
            .collect::<Vec<_>>();
        let input_hex_string = hex::encode(&nu32_byte_arr);

        let input_str_processed = hex::encode(
            nu32_arr
                .iter()
                .flat_map(|i| (i).to_be_bytes())
                .collect::<Vec<_>>(),
        );

        println!("Input Hex String :: {}", input_hex_string);
        println!("Input Hex String processed:: {}", input_str_processed);

        // compute the hash using the official implementation
        let expected_hex_out = blake3::hash(
            &nu32_arr
                .iter()
                .flat_map(|i| (i).to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .to_string();

        println!("Expected Hash :: {}", expected_hex_out);

        // push the random u32 numbers as nibbles and pack them
        let num_blocks = msg_len / 64;

        for i in (0..num_blocks).rev() {
            let pos_start = 64 * (2 * i) as usize;
            let pos_mid = 64 * (2 * i + 1) as usize;
            let pos_end = 64 * (2 * i + 2) as usize;

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_start..pos_mid])}
                    {pack_nibbles_to_limbs()}
                },
                &format!("msg{}p0", i),
            );

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_mid..pos_end])}
                    {pack_nibbles_to_limbs()}
                },
                &format!("msg{}p1", i),
            );
        }
        
        blake3_u4_compact(&mut stack, msg_len, false);
        //push the expected hash
        stack.var(
            64,
            script! {
                {u4_hex_to_nibbles(&expected_hex_out.chars().rev().collect::<String>())}
            },
            "expected-hash",
        );

        stack.custom(
            script! {
                for _ in 0..64{
                    OP_FROMALTSTACK
                    OP_EQUALVERIFY
                }
            },
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_compact_randominputs() {
        test_blake3_compact(64);
        test_blake3_compact(128);
        test_blake3_compact(192);
        test_blake3_compact(256);
        test_blake3_compact(64*5);
        test_blake3_compact(64*6);
        test_blake3_compact(64*7);
        test_blake3_compact(64*8);
        test_blake3_compact(64*9);
        test_blake3_compact(64*10);
        test_blake3_compact(64*11);
        test_blake3_compact(64*12);
        test_blake3_compact(64*13);
        test_blake3_compact(64*14);
        test_blake3_compact(64*15);
        test_blake3_compact(64*16); //max size for a chunk 1024 bytes
    }
    
}
