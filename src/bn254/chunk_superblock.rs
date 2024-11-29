use crate::bigint::BigIntImpl;

pub type H256 = BigIntImpl<256, 30>;

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::blockdata::block::Header;
    use bitcoin::consensus::deserialize;

    use crate::signatures::wots::wots32;
    use crate::{
        hash::{blake3::push_bytes_hex, sha256::sha256},
        pseudo::NMUL,
        signatures::wots::wots256,
        treepp::*,
    };

    mod reconstruct {
        use super::*;

        pub fn ts_from_nibbles() -> Script {
            script! {
                for _ in 1..8 { OP_TOALTSTACK }
                for _ in 1..8 {
                    { NMUL(1 << 4) } OP_FROMALTSTACK OP_ADD
                }
            }
        }

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

        pub fn h256_from_nibbles() -> Script {
            const WINDOW: u32 = 4;
            const LIMB_SIZE: u32 = 30;
            const N_DIGITS: u32 = (H256::N_BITS + WINDOW - 1) / WINDOW;

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
                for _ in 1..H256::N_LIMBS { OP_FROMALTSTACK }
                for i in 1..H256::N_LIMBS { { i } OP_ROLL }
            }
        }

        pub fn h256_from_bytes() -> Script {
            const WINDOW: u32 = 8;
            const LIMB_SIZE: u32 = 30;
            const N_DIGITS: u32 = (H256::N_BITS + WINDOW - 1) / WINDOW;

            script! {
                for i in 1..32 { { i } OP_ROLL }
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
                for _ in 1..H256::N_LIMBS { OP_FROMALTSTACK }
                for i in 1..H256::N_LIMBS { { i } OP_ROLL }
            }
        }
    }

    #[test]
    fn test_superblock_chunk() {
        const SUPERBLOCK_PERIOD: u32 = 2 * 7 * 24 * 60 * 60; // 2w in secs

        let secret_key = "0123456789abcdef";

        let ts_secret_key = format!("{secret_key}{:04x}", 0);
        let sb_secret_key = format!("{secret_key}{:04x}", 1);

        let ts_public_key = wots32::generate_public_key(&ts_secret_key);
        let sb_public_key = wots256::generate_public_key(&sb_secret_key);

        // operator
        // superblock period start timestamp
        let sb_start_ts: u32 = 1729111401; // block 865950

        // superblock hash
        let sbo_hash =
            hex::decode("00000000000000000002fbac49291329bb2b3ee40ca010265fd8d33aae49c388")
                .unwrap(); // block 866801

        // block 866950
        let sbv_hex = "00e0ff3f47d98ca4244d8c448eea183319ff74d8f585f6f5afd001000000000000000000b2115f41fa8a4adb4b4345e03c60b78cff5f5a7c175a91a6bfdde576c417cccffe8e186728f10217aac7e04a";
        let sbv_bytes = hex::decode(sbv_hex).unwrap();
        let _sbv: Header = deserialize(&sbv_bytes).unwrap();

        let sbv_ts_from_header = script! {
            for i in 0..4 {
                { 80 - 12 + 2 * i } OP_PICK
            }
            for _ in 1..4 {
                { NMUL(1 << 8) } OP_ADD
            }
        };

        let script_pub_key = script! {
            // committed superblock hash
            { wots256::compact::checksig_verify(sb_public_key) }
            { reconstruct::h256_from_nibbles() } { H256::toaltstack() }

            // committed superblock period start timestamp
            { wots32::compact::checksig_verify(ts_public_key) }
            { reconstruct::ts_from_nibbles() } OP_TOALTSTACK

            // extract superblock timestamp from header
            { sbv_ts_from_header }

            // assert: 0 < sbv.ts - sb_start_ts < superblock_period
            OP_FROMALTSTACK
            OP_SUB
            OP_DUP
            0 OP_GREATERTHAN OP_VERIFY
            { SUPERBLOCK_PERIOD } OP_LESSTHAN OP_VERIFY

            // sbv.hash()
            { sha256(80) }
            { sha256(32) }
            { reconstruct::h256_from_bytes() }

            { H256::fromaltstack() }

            // assert sb.hash < committed_sb_hash
            { H256::lessthan(1, 0) } OP_VERIFY

            OP_TRUE
        };

        let script_sig = script! {
            { push_bytes_hex(sbv_hex) }
            { wots32::compact::sign(&ts_secret_key, &sb_start_ts.to_le_bytes())}
            { wots256::compact::sign(&sb_secret_key, &sbo_hash) }
        };

        let script = script! {
            { script_sig }
            { script_pub_key }
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        println!("max stack: {}", res.stats.max_nb_stack_items);
        assert!(res.success);
    }
}
