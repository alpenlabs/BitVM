//
// Compact Winternitz Signatures
//
// In this variant, the user doesn't need to provide the message in the unlocking script.
// Instead, we calculate the message from the signature hashes.
// This reduces stack usage at the expense of script size.
//

//
// Winternitz signatures are an improved version of Lamport signatures.
// A detailed introduction to Winternitz signatures can be found
// in "A Graduate Course in Applied Cryptography" in chapter 14.3
// https://toc.cryptobook.us/book.pdf
//
// We are trying to closely follow the authors' notation here.
//

//
// BEAT OUR IMPLEMENTATION AND WIN A CODE GOLF BOUNTY!
//

use crate::{bn254::chunk_primitves::pack_nibbles_to_limbs, treepp::*};
use bitcoin::{hashes::{hash160, Hash}, opcodes::all::OP_ROLL};
use hex::decode as hex_decode;

///
const N_BITS: u32 = 256;
/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message
const N0: u32 = (N_BITS + LOG_D - 1) / LOG_D;
/// Number of digits of the checksum
const N1: usize = log(D * N0, D + 1) as usize;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;
///
const LIMB_SIZE: u32 = 29;
const N_LIMBS: u32 = 9;

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


/// Number of digits of the message

/// Number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1

/// Total number of chains


/// Generate the public key for the i-th digit of the message
pub fn public_key(secret_key: &str, digit_index: u32) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string {:?}", secret_key),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
pub fn checksum(digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * N0 - sum
}

/// Convert a number to digits
pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Compute the signature for a given message
pub fn sign(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    script! {
        for i in 0..N {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
    }
}

/// Winternitz Signature verification
///
/// Note that the script inputs are malleable.
///
/// Optimized by @SergioDemianLerner, @tomkosm
pub fn checksig_verify(secret_key: &str) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {

            { public_key(secret_key, N - 1 - digit_index) }


            // Check if hash is equal with public key and add digit to altstack.
            // We dont check if a digit was found to save space, incase we have an invalid hash
            // there will be one fewer entry in altstack and OP_FROMALTSTACK later will crash.
            // So its important to start with the altstack empty.
            // TODO: add testcase for this.
            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {D}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..D {

                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {D-i-1}

                    OP_TOALTSTACK

                OP_ENDIF
            }

            OP_2DROP
        }


        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0{
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY


        // Convert the message's digits to bytes
        // for i in 0..N0 / 2 {
        //     OP_SWAP
        //     for _ in 0..LOG_D {
        //         OP_DUP OP_ADD
        //     }
        //     OP_ADD
        //     // Push all bytes to the altstack, except for the last byte
        //     if i != (N0/2) - 1 {
        //         OP_TOALTSTACK
        //     }
        // }
        // for _ in 0..N0 / 2 - 1 {
        //     OP_FROMALTSTACK
        // }

    }
}


pub type WOTSPubKey = Vec<Vec<u8>>;

pub fn get_pub_key(secret_key: &str) -> WOTSPubKey {
    fn pubkey(secret_key: &str, digit_index: u32) -> Vec<u8> {
        let mut secret_i = match hex_decode(secret_key) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string {:?}", secret_key),
        };
    
        secret_i.push(digit_index as u8);
    
        let mut hash = hash160::Hash::hash(&secret_i);
    
        for _ in 0..D {
            hash = hash160::Hash::hash(&hash[..]);
        }
    
        let hash_bytes = hash.as_byte_array().to_vec();
        return hash_bytes
    }

    let mut pubkeys: Vec<Vec<u8>> = Vec::new();
    for digit_index in 0..N {
        let p = pubkey(secret_key, N-1-digit_index);
        pubkeys.push(p);
    }

    pubkeys
}

/// Winternitz Signature verification
///
/// Note that the script inputs are malleable.
///
/// Optimized by @SergioDemianLerner, @tomkosm
pub fn checksig_verify_fq(pub_key: WOTSPubKey) -> Script {

    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {

            { pub_key[digit_index as usize].clone() }


            // Check if hash is equal with public key and add digit to altstack.
            // We dont check if a digit was found to save space, incase we have an invalid hash
            // there will be one fewer entry in altstack and OP_FROMALTSTACK later will crash.
            // So its important to start with the altstack empty.
            // TODO: add testcase for this.
            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {D}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..D {

                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {D-i-1}

                    OP_TOALTSTACK

                OP_ENDIF
            }

            OP_2DROP
        }


        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0{
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY

        // field element reconstruction
        for i in 1..64 {
            {i} OP_ROLL
        }
        {pack_nibbles_to_limbs()}

    }
}

// pub(crate) fn field_reconstruction() -> Script {
        
//     pub fn nmul(n: u32) -> Script {
//         let n_bits = u32::BITS - n.leading_zeros();
//         let bits = (0..n_bits).map(|i| 1 & (n >> i)).collect::<Vec<_>>();
//         script! {
//             if n_bits == 0 { OP_DROP 0 }
//             else {
//                 for i in 0..bits.len()-1 {
//                     if bits[i] == 1 { OP_DUP }
//                     { crate::pseudo::OP_2MUL() }
//                 }
//                 for _ in 1..bits.iter().sum() { OP_ADD }
//             }
//         }
//     }

//     fn split_digit(window: u32, index: u32) -> Script {
//         script! {
//             // {v}
//             0                           // {v} {A}
//             OP_SWAP
//             for i in 0..index {
//                 OP_TUCK                 // {v} {A} {v}
//                 { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
//                 OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
//                 OP_TUCK                 // {v} {1/0} {A} {1/0}
//                 OP_ADD                  // {v} {1/0} {A+1/0}
//                 if i < index - 1 { { nmul(2) } }
//                 OP_ROT OP_ROT
//                 OP_IF
//                     { 1 << (window - i - 1) }
//                     OP_SUB
//                 OP_ENDIF
//             }
//             OP_SWAP
//         }
//     }

//     script!{
//         for i in (1..=N0).rev() {
//             if (i * LOG_D) % LIMB_SIZE == 0 {
//                 OP_TOALTSTACK
//             } else if (i * LOG_D) % LIMB_SIZE > 0 &&
//                         (i * LOG_D) % LIMB_SIZE < LOG_D {
//                 OP_SWAP
//                 { split_digit(LOG_D, (i * LOG_D) % LIMB_SIZE) }
//                 OP_ROT
//                 { nmul(1 << ((i * LOG_D) % LIMB_SIZE)) }
//                 OP_ADD
//                 OP_TOALTSTACK
//             } else if i != N0 {
//                 { nmul(1 << LOG_D) }
//                 OP_ADD
//             }
//         }
//         for _ in 1..N_LIMBS { OP_FROMALTSTACK }
//         for i in 1..N_LIMBS { { i } OP_ROLL }
//     }
// }


#[cfg(test)]
mod test {
    use bitcoin::opcodes::OP_TRUE;

    use crate::signatures::{winternitz, winternitz_compact};

    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_winternitz() {
        // The message to sign
        #[rustfmt::skip]
        const MESSAGE: [u8; N0 as usize] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4,
        ];
        let sig = { winternitz_compact::sign(MY_SECKEY, MESSAGE) };
        let sig2 = {winternitz::sign_digits(MY_SECKEY, MESSAGE)};
        let mut filtered_sig2 = script!{};
        for i in 0..sig2.len() {
            if i%2 == 0 {
                filtered_sig2 = filtered_sig2.push_script(sig2[i].clone().compile());
            }
        }

        
        let sc = script! {
            {filtered_sig2}
        };


        // println!("filtered sig {:?}", sig2.compile());

        // println!("sc sig {:?}", sig.compile());

        // println!("fsc sig {:?}", filtered_sig2.compile());


        // println!(
        //     "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
        //     script.len(),
        //     N0 * 4,
        //     script.len() as f64 / (N0 * 4) as f64
        // );

        // let pubkey = get_pub_key(MY_SECKEY);
        // let sc = script! {
        //     { sign(MY_SECKEY, MESSAGE) }
        //     { checksig_verify_fq(pubkey) }
        //     OP_TRUE
        // };
        let res = execute_script(sc);
        for i in 0..res.final_stack.len() {
            println!("{i:3} {:?}", res.final_stack.get(i));
        }

    }

    // TODO: test the error cases: negative digits, digits > D, ...
}
