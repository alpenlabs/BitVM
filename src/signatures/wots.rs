use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};

const WINDOW: u32 = 4;

const fn log2(n: u32) -> u32 {
    31 - n.leading_zeros()
}

const fn ceil_div(numerator: u32, denominator: u32) -> u32 {
    (numerator + denominator - 1) / denominator
}

macro_rules! impl_wots {
    ($N_BITS:literal) => {
        paste::paste! {
            pub mod [<wots $N_BITS>] {
                use super::*;

                pub const N_BITS: u32 = $N_BITS;
                pub const MAX_DIGIT: u32 = (1 << WINDOW) - 1;
                pub const M_DIGITS: u32 = ceil_div(N_BITS, WINDOW);
                pub const C_DIGITS: u32 = ceil_div(log2(M_DIGITS * MAX_DIGIT), WINDOW);
                pub const N_DIGITS: u32 = M_DIGITS + C_DIGITS;

                // compile time assertion on 1 <= WINDOW <= 8
                const _: u32 = WINDOW - 1;
                const _: u32 = 8 - WINDOW;

                // compile time assertion on N_BITS % 8 = 0 (N_BITS is divisible by byte size);
                const _: u32 = 0 - (N_BITS % 8);

                pub type PublicKey = [[u8; 20]; N_DIGITS as usize];

                /// Compute the checksum of the message's digits.
                fn checksum(message_digits: [u8; M_DIGITS as usize]) -> u32 {
                    MAX_DIGIT * M_DIGITS - message_digits.map(|d| d as u32).iter().sum::<u32>()
                }

                /// Convert a number to digits
                fn checksum_to_digits(checksum: u32) -> [u8; C_DIGITS as usize] {
                    std::array::from_fn(|i| {
                        ((checksum / (MAX_DIGIT + 1).pow(i as u32)) % (MAX_DIGIT + 1)) as u8
                    })
                }

                /// Generate the public key for the i-th digit of the message
                fn public_key_for_digit(secret: &str, digit_index: u32) -> [u8; 20] {
                    let mut secret = hex::decode(secret).expect("invalid secret key");
                    secret.push(digit_index as u8);
                    let mut hash = hash160::Hash::hash(&secret); // first secret, for 0
                    for _ in 0..MAX_DIGIT {
                        hash = hash160::Hash::hash(&hash[..]);
                    }
                    *hash.as_byte_array()
                }

                /// Compute the signature for the i-th digit of the message
                fn sign_digit(secret: &str, digit_index: u32, message_digit: u8) -> Script {
                    let mut secret = hex::decode(secret).expect("invalid secret key");
                    secret.push(digit_index as u8);
                    let mut hash = hash160::Hash::hash(&secret); // first secret, for 0
                    for _ in 0..message_digit {
                        hash = hash160::Hash::hash(&hash[..]);
                    }
                    script! {
                        { hash.as_byte_array().to_vec() }
                    }
                }

                /// Convert message bytes to digits
                fn msg_bytes_to_digits(msg_bytes: &[u8]) -> [u8; M_DIGITS as usize] {
                    let mut msg_digits = [0u8; M_DIGITS as usize];
                    for (digits, byte) in msg_digits.chunks_mut(2).zip(msg_bytes) {
                        digits[0] = byte & 0b00001111;
                        digits[1] = byte >> 4;
                    }
                    msg_digits
                }

                /// Generate wots public key
                pub fn generate_public_key(secret: &str) -> PublicKey {
                    std::array::from_fn(|i| public_key_for_digit(secret, i as u32))
                }

                pub fn sign(secret: &str, msg_bytes: &[u8]) -> Script {
                    let msg_digits = msg_bytes_to_digits(msg_bytes);
                    let mut digits = checksum_to_digits(checksum(msg_digits)).to_vec();
                    digits.append(&mut msg_digits.to_vec());
                    script! {
                        for i in 0..N_DIGITS {
                            { sign_digit(secret, i, digits[(N_DIGITS - 1 - i) as usize])}
                            { digits[(N_DIGITS - 1 - i) as usize] }
                        }
                    }
                }

                pub fn checksig_verify(public_key: PublicKey) -> Script {
                    script! {
                        for i in 0..N_DIGITS {
                            { MAX_DIGIT } OP_MIN
                            OP_DUP OP_TOALTSTACK OP_TOALTSTACK
                            for _ in 0..MAX_DIGIT {
                                OP_DUP OP_HASH160
                            }
                            OP_FROMALTSTACK
                            OP_PICK
                            { public_key[(N_DIGITS - i - 1) as usize].to_vec() }
                            OP_EQUALVERIFY

                            for _ in 0..(MAX_DIGIT + 1) / 2 { OP_2DROP }
                        }

                        // compute checksum
                        OP_FROMALTSTACK OP_DUP OP_NEGATE
                        for _ in 1..M_DIGITS {
                            OP_FROMALTSTACK OP_TUCK OP_SUB
                        }
                        { MAX_DIGIT * M_DIGITS }
                        OP_ADD

                        // pre-computed checksum
                        OP_FROMALTSTACK
                        for _ in 1..C_DIGITS {
                            for _ in 0..WINDOW {
                                OP_DUP OP_ADD
                            }
                            OP_FROMALTSTACK OP_ADD
                        }
                        // ensure checksums match
                        OP_EQUALVERIFY
                    }
                }

                pub mod compact {
                    use super::*;

                    pub fn sign(secret: &str, msg_bytes: &[u8]) -> Script {
                        let msg_digits = msg_bytes_to_digits(msg_bytes);
                        let mut digits = checksum_to_digits(checksum(msg_digits)).to_vec();
                        digits.append(&mut msg_digits.to_vec());
                        script! {
                            for i in 0..N_DIGITS {
                                { sign_digit(secret, i, digits[(N_DIGITS - 1 - i) as usize])}
                            }
                        }
                    }

                    pub fn checksig_verify(public_key: PublicKey) -> Script {
                        script! {
                            for i in 0..N_DIGITS {
                                { public_key[(N_DIGITS - i - 1) as usize].to_vec() } OP_SWAP
                                OP_2DUP OP_EQUAL
                                OP_IF { MAX_DIGIT } OP_TOALTSTACK OP_ENDIF
                                for j in 0..MAX_DIGIT {
                                    OP_HASH160
                                    OP_2DUP OP_EQUAL
                                    OP_IF { MAX_DIGIT - j - 1 } OP_TOALTSTACK OP_ENDIF
                                }
                                OP_2DROP
                            }

                            // compute checksum
                            OP_FROMALTSTACK OP_DUP OP_NEGATE
                            for _ in 1..M_DIGITS {
                                OP_FROMALTSTACK OP_TUCK OP_SUB
                            }
                            { MAX_DIGIT * M_DIGITS }
                            OP_ADD

                            // pre-computed checksum
                            OP_FROMALTSTACK

                            for _ in 1..C_DIGITS {
                                for _ in 0..WINDOW {
                                    OP_DUP OP_ADD
                                }
                                OP_FROMALTSTACK OP_ADD
                            }
                            // ensure checksums match
                            OP_EQUALVERIFY
                        }
                    }
                }
            }
        }
    };
}

impl_wots!(32);
impl_wots!(128);
impl_wots!(160);
impl_wots!(256);

#[cfg(test)]
mod tests {

    use crate::treepp::*;

    use super::{wots160, wots256, wots32};

    #[test]
    fn test_wots() {
        let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let public_key = wots32::generate_public_key(&secret);

        // let msg = "a0b1d2c3";
        // let msg_bytes = hex::decode(&msg).unwrap();

        const MESSAGE: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4,
        ];
        let msg_bytes = MESSAGE.to_vec();

        let script = script! {
            { wots256::compact::sign(&secret, &msg_bytes) }
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:3} {:?}", res.final_stack.get(i));
        }

        println!("NEXT THING");

        let script = script! {
            { wots256::sign(&secret, &msg_bytes) }
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:3} {:?}", res.final_stack.get(i));
        }
    }

    #[test]
    fn test_wots32() {
        let secret = "a01b23c45d67e89f";
        let public_key = wots32::generate_public_key(&secret);

        let msg = "a0b1d2c3";
        let msg_bytes = hex::decode(&msg).unwrap();

        let script = script! {
            { wots32::compact::sign(&secret, &msg_bytes) }
            { wots32::compact::checksig_verify(public_key) }

            for i in (0..8).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }

            { wots32::sign(&secret, &msg_bytes) }
            { wots32::checksig_verify(public_key) }

            for _ in 0..8 {
                OP_FROMALTSTACK OP_EQUALVERIFY
            }

            OP_TRUE
        };

        println!(
            "wots32: sig={}, csv={}",
            wots32::sign(&secret, &msg_bytes).len(),
            wots32::checksig_verify(public_key).len()
        );

        println!(
            "wots32:compact: sig={}, csv={}",
            wots32::compact::sign(&secret, &msg_bytes).len(),
            wots32::compact::checksig_verify(public_key).len()
        );

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_wots160() {
        let secret = "a01b23c45d67e89f";
        let public_key = wots160::generate_public_key(&secret);

        let msg = "0123456789abcdef0123456789abcdef01234567";
        let msg_bytes = hex::decode(&msg).unwrap();

        let script = script! {
            { wots160::compact::sign(&secret, &msg_bytes) }
            { wots160::compact::checksig_verify(public_key) }

            for i in (0..40).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }

            { wots160::sign(&secret, &msg_bytes) }
            { wots160::checksig_verify(public_key) }

            for _ in 0..40 {
                OP_FROMALTSTACK OP_EQUALVERIFY
            }

            OP_TRUE
        };

        println!(
            "wots160: sig={}, csv={}",
            wots160::sign(&secret, &msg_bytes).len(),
            wots160::checksig_verify(public_key).len()
        );

        println!(
            "wots160:compact: sig={}, csv={}",
            wots160::compact::sign(&secret, &msg_bytes).len(),
            wots160::compact::checksig_verify(public_key).len()
        );

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_wots256() {
        let secret = "a01b23c45d67e89f";
        let public_key = wots256::generate_public_key(&secret);

        let msg = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let msg_bytes = hex::decode(&msg).unwrap();

        let script = script! {
            { wots256::compact::sign(&secret, &msg_bytes) }
            { wots256::compact::checksig_verify(public_key) }

            for i in (0..64).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }

            { wots256::sign(&secret, &msg_bytes) }
            { wots256::checksig_verify(public_key) }

            for _ in 0..64 {
                OP_FROMALTSTACK OP_EQUALVERIFY
            }

            OP_TRUE
        };

        println!(
            "wots256: sig={}, csv={}",
            wots256::sign(&secret, &msg_bytes).len(),
            wots256::checksig_verify(public_key).len()
        );

        println!(
            "wots256:compact: sig={}, csv={}",
            wots256::compact::sign(&secret, &msg_bytes).len(),
            wots256::compact::checksig_verify(public_key).len()
        );

        let res = execute_script(script);
        assert!(res.success);
    }
}