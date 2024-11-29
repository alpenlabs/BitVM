use crate::treepp::*;
use bitcoin::ScriptBuf;

pub const BLAKE3_64B_75K_BIN: &[u8] = include_bytes!("blake3_bin/blake3_64b_75k.bin");
pub const BLAKE3_64B_84K_BIN: &[u8] = include_bytes!("blake3_bin/blake3_64b_84k.bin");
pub const BLAKE3_128B_150K_BIN: &[u8] = include_bytes!("blake3_bin/blake3_128b_150k.bin");
pub const BLAKE3_128B_168K_BIN: &[u8] = include_bytes!("blake3_bin/blake3_128b_168k.bin");
pub const BLAKE3_192B_252K_BIN: &[u8] = include_bytes!("blake3_bin/blake3_192b_252k.bin");

fn wrap(data: &[u8]) -> Script {
    script! {
        { script!().push_script(ScriptBuf::from_bytes(data.to_vec())) }
        for _ in 0..40 { OP_TOALTSTACK }
        for _ in 0..(64-40)/2 { OP_2DROP }
        for _ in 0..(64-40) { 0 }
        for _ in 0..40 { OP_FROMALTSTACK  }
    }
}

pub fn hash_64b_75k() -> Script {
    wrap(&BLAKE3_64B_75K_BIN)
}

pub fn hash_64b_84k() -> Script {
    wrap(&BLAKE3_64B_84K_BIN)
}

pub fn hash_128b_150k() -> Script {
    wrap(&BLAKE3_128B_150K_BIN)
}

pub fn hash_128b_168k() -> Script {
    wrap(&BLAKE3_128B_168K_BIN)
}

pub fn hash_192b_252k() -> Script {
    wrap(&BLAKE3_192B_252K_BIN)
}
