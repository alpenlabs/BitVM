use crate::{hash::blake3_u4, treepp::*};
use bitcoin_script_stack::stack::StackTracker;


fn wrap_scr(scr: Script) -> Script {
    script! {
        { scr }
        for _ in 0..(64-40)/2 { OP_2DROP }
        for _ in 0..(64-40) { 0 }
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
