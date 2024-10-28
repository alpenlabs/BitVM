//
// Winternitz One-time Signatures
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

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
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

const N2: usize = 20;
/// The public key type
pub type PublicKey = [[u8; N2]; N as usize];
const LIMB_SIZE: u32 = 29;
const N_LIMBS: u32 = 9;
//
// Helper functions
//
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

/// Generate a public key for the i-th digit of the message
pub fn public_key_for_digit(secret_key: &str, digit_index: u32) -> [u8; N2] {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    *hash.as_byte_array()
}

/// Generate a public key from a secret key 
pub fn generate_public_key(secret_key: &str) -> PublicKey {
    let mut public_key_array = [[0u8; N2]; N as usize];
    for i in 0..N {
        public_key_array[i as usize] = public_key_for_digit(secret_key, i);
    }
    public_key_array
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Vec<Script> {
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

    let sc1 = script! {
        { hash_bytes }
    };
    let sc2 = script! {
        { message_digit }
    };
    vec![sc1, sc2]
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
pub fn sign_digits(secret_key: &str, message_digits: [u8; N0 as usize]) -> Vec<Script> {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    let mut scs: Vec<Script> = Vec::new();
    for i in 0..N {
        for s in digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) {
            scs.push(s);
        }
    }
    scs
}

pub fn sign(secret_key: &str, message_bytes: &[u8]) -> Script {
    // Convert message to digits
    let mut message_digits = [0u8; N0 as usize];
    for (digits, byte) in message_digits.chunks_mut(2).zip(message_bytes) {
        digits[0] = byte & 0b00001111;
        digits[1] = byte >> 4;
    }

    let scs = sign_digits(secret_key, message_digits);
    let mut sc = script!{};
    for s in scs {
        sc = sc.push_script(s.compile());
    }
    sc
}

pub fn checksig_verify(public_key: &PublicKey) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { D }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..D {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { public_key[N as usize - 1 - digit_index as usize].to_vec() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(D+1)/2 {
                OP_2DROP
            }
        }

        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0 {
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


        // // Convert the message's digits to bytes
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
        // // Read the bytes from the altstack
        // for _ in 0..N0 / 2 - 1{
        //     OP_FROMALTSTACK
        // }

    }
}


#[cfg(test)]
mod test {
    use bitcoin::ScriptBuf;

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

        let public_key = generate_public_key(MY_SECKEY);

        let script = script! {
            { sign_digits(MY_SECKEY, MESSAGE) }
            { checksig_verify(&public_key) }
        };

        let sig2 = sign_digits(MY_SECKEY, MESSAGE) ;
        let mut filtered_sig2 = script!{};
        for i in 0..sig2.len() {
            if i%2 == 0 {
                filtered_sig2 = filtered_sig2.push_script(sig2[i].clone().compile());
            }
        }

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            N0 * 4,
            script.len() as f64 / (N0 * 4) as f64
        );

        let sc = script! {
            {filtered_sig2 }
            // { checksig_verify(&public_key) }

            // 0x21 OP_EQUALVERIFY
            // 0x43 OP_EQUALVERIFY
            // 0x65 OP_EQUALVERIFY
            // 0x87 OP_EQUALVERIFY
            // 0xA9 OP_EQUALVERIFY
            // 0xCB OP_EQUALVERIFY
            // 0xED OP_EQUALVERIFY
            // 0x7F OP_EQUALVERIFY
            // 0x77 OP_EQUALVERIFY
            // 0x77 OP_EQUALVERIFY

            // 0x21 OP_EQUALVERIFY
            // 0x43 OP_EQUALVERIFY
            // 0x65 OP_EQUALVERIFY
            // 0x87 OP_EQUALVERIFY
            // 0xA9 OP_EQUALVERIFY
            // 0xCB OP_EQUALVERIFY
            // 0xED OP_EQUALVERIFY
            // 0x7F OP_EQUALVERIFY
            // 0x77 OP_EQUALVERIFY
            // 0x77 OP_EQUAL
        };
        
        let comp = sc.clone().compile();
        println!("script {:?}", comp);
        let res = execute_script(sc);
        for i in 0..res.final_stack.len() {
            println!("{i:3} {:?}", res.final_stack.get(i));
        }
    }

    // TODO: test the error cases: negative digits, digits > D, ...
}
