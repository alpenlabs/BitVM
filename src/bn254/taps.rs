
// utils for push fields into stack
use crate::bn254::fq::unpack_u32_to_u8;
use crate::bn254::fq::pack_u8_to_u32;
use bitcoin::ScriptBuf;
use std::fs::File;
use std::io::{self, Read};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

pub fn read_script_from_file(file_path: &str) -> Script {
    fn read_file_to_bytes(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut all_script_bytes = Vec::new();
        file.read_to_end(&mut all_script_bytes)?;
        Ok(all_script_bytes)
    }
    //let file_path = "blake3_bin/blake3_192b_252k.bin"; // Replace with your file path
    let all_script_bytes = read_file_to_bytes(file_path).unwrap();
    let scb = ScriptBuf::from_bytes(all_script_bytes);
    let sc = script!();
    let sc = sc.push_script(scb);
    sc
}


// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb
pub fn hash_fp6() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }
        { unpack_u32_to_u8() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u8() }
        {hash_64b_75k.clone()}
        { pack_u8_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { hash_128b_168k.clone() }

            for _ in 0..9 {
                {64 + 8} OP_ROLL
            }
            {unpack_u32_to_u8()}
        { hash_64b_75k }
        {pack_u8_to_u32()}
    } 
}

pub fn hash_fp12() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_u32_to_u8() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u8() }
        {hash_64b_75k.clone()}
        { pack_u8_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}
        {pack_u8_to_u32()}

        // second part

        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}
        { pack_u8_to_u32() }
        

        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { hash_128b_168k.clone() }

        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}
        {pack_u8_to_u32()}

    } 
}

pub fn hash_fp12_192() -> Script {
    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_192b_252k = read_script_from_file("blake3_bin/blake3_192b_252k.bin");
    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }
        {unpack_u32_to_u8() }
        for _ in 0..5 {
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
        }
        {hash_192b_252k.clone()}
        {pack_u8_to_u32()}

        for _ in 0..6 {
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
        }
        {hash_192b_252k}
        for _ in 0..9 {
            {64+8} OP_ROLL
        }
        { unpack_u32_to_u8() }
        {hash_64b_75k}
        {pack_u8_to_u32()}
    }
}

// 6Fp_hash
// fp6
pub fn hash_fp12_with_hints() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }

        { unpack_u32_to_u8() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u8() }
        {hash_64b_75k.clone()}
        { pack_u8_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u8()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u8()}
        {hash_64b_75k.clone()}
        {pack_u8_to_u32()}

    } 
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::{fq::{pack_u8_to_u32, unpack_u32_to_u8}, utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine}};
    use ark_bn254::G2Affine;
    use ark_ff::AdditiveGroup;
    use ark_std::UniformRand;
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq6::Fq6;
    use crate::treepp::{script};
    use ark_ff::{Field};
    use core::ops::Mul;
    use crate::bn254::{fq12::Fq12, fq2::Fq2};

    #[test]
    fn test_hinited_sparse_dense_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let _q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let f = ark_bn254::Fq12::rand(&mut prng);
        
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_tangent = t.x.square();
        alpha_tangent /= t.y;
        alpha_tangent.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus_tangent = alpha_tangent * t.x - t.y;

        let mut f1 = f;
        let mut c1new = alpha_tangent;
        c1new.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new = bias_minus_tangent;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        f1.mul_by_034(&ark_bn254::Fq2::ONE, &c1new, &c2new);
        let (hinted_script, hints) = Fq12::hinted_mul_by_34(f, c1new, c2new);

        let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");


        let script = script! {
            for hint in hints { 
                { hint.push() }
            }

            { fq12_push_not_montgomery(f) }
            { fq2_push_not_montgomery(c1new) }
            { fq2_push_not_montgomery(c2new) }
            { fq12_push_not_montgomery(f) }
            { fq2_push_not_montgomery(c1new) }
            { fq2_push_not_montgomery(c2new) }
            { hinted_script.clone() }

            for _ in 0..12 { // save claim
                {Fq::toaltstack()}
            }

            // hash c1new and c2new
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u8()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            {hash_128b_168k.clone()}
            {pack_u8_to_u32()}

            {hash_fp12() }

            for _ in 0..12 { // save claim
                {Fq::fromaltstack()}
            }
            { hash_fp12_192() }

            OP_TRUE
        };
        let len = script.len();
        let res = execute_script(script);
        assert!(res.success);
        let mut max_stack = 0;
        max_stack = max_stack.max(res.stats.max_nb_stack_items);
        println!("Fq6::window_mul: {} @ {} stack", len, max_stack);
    }



    #[test]
    fn test_bn254_fq12_hinted_mul_split0() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul_first(12, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                // Hash_b
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_a
                {u32::from_le_bytes([131, 116, 114, 0])}
                {u32::from_le_bytes([245, 129, 139, 3])}
                {u32::from_le_bytes([132, 171, 199, 7])}
                {u32::from_le_bytes([97, 185, 93, 16])}
                {u32::from_le_bytes([161, 222, 150, 25])}
                {u32::from_le_bytes([44, 144, 71, 23])}
                {u32::from_le_bytes([139, 185, 38, 22])}
                {u32::from_le_bytes([233, 138, 103, 22])}
                {u32::from_le_bytes([9, 213, 155, 19])}
                
                // Hash_c
                {u32::from_le_bytes([82, 143, 25,0])}
                {u32::from_le_bytes([106, 69, 151, 13])}
                {u32::from_le_bytes([154, 120, 131, 27])}
                {u32::from_le_bytes([140, 55, 239, 25])}
                {u32::from_le_bytes([92, 201, 47, 28])}
                {u32::from_le_bytes([44, 174, 74, 16])}
                {u32::from_le_bytes([57, 190, 31, 19])}
                {u32::from_le_bytes([31, 231, 126, 1])}
                {u32::from_le_bytes([158, 11, 210, 2])}

                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(b) } // fp12_one
                { hinted_mul.clone() }
                { Fq6::toaltstack() }
                
                { hash_fp12()}
                //bring Hashb to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                // hash_a
                { hash_fp12_192() }
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                {Fq::fromaltstack()} // Fq_claimed from altstack
                {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
                OP_TRUE
            };

            println!("script len {}", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            for i in 0..exec_result.final_stack.len() {
                println!("{i:3} {:?}", exec_result.final_stack.get(i));
            }
            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq12::mul {} stack", max_stack);
            
        }

    }

    #[test]
    fn test_bn254_fq12_hinted_mul_split1() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul_second(12, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                // Hash_b
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_c0
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_a
                {u32::from_le_bytes([131, 116, 114, 0])}
                {u32::from_le_bytes([245, 129, 139, 3])}
                {u32::from_le_bytes([132, 171, 199, 7])}
                {u32::from_le_bytes([97, 185, 93, 16])}
                {u32::from_le_bytes([161, 222, 150, 25])}
                {u32::from_le_bytes([44, 144, 71, 23])}
                {u32::from_le_bytes([139, 185, 38, 22])}
                {u32::from_le_bytes([233, 138, 103, 22])}
                {u32::from_le_bytes([9, 213, 155, 19])}
                
                // Hash_c
                {u32::from_le_bytes([66, 234, 4, 0])}
                {u32::from_le_bytes([156, 104, 70, 7])}
                {u32::from_le_bytes([5, 60, 102, 10])}
                {u32::from_le_bytes([171, 108, 80, 11])}
                {u32::from_le_bytes([30, 94, 254, 19])}
                {u32::from_le_bytes([34, 232, 58, 11])}
                {u32::from_le_bytes([191, 101, 160, 16])}
                {u32::from_le_bytes([53, 186, 189, 25])}
                {u32::from_le_bytes([83, 33, 154, 8])}

                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(b) } // fp12_one
                { hinted_mul.clone() }
                { Fq6::toaltstack() }
                
                { hash_fp12()}
                // bring Hashb to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                // bring Hash_c0 to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq6::fromaltstack() }
                { hash_fp12_with_hints() }
                { Fq::toaltstack() } // Fq_claimed to altstack

                // hash_a
                { hash_fp12_192() }
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                {Fq::fromaltstack()} // Fq_claimed from altstack
                {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
                OP_TRUE
            };

            println!("script len {}", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            for i in 0..exec_result.final_stack.len() {
                println!("{i:3} {:?}", exec_result.final_stack.get(i));
            }
            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq12::mul {} stack", max_stack);
            
        }

    }


    #[test]
    fn test_bn254_fq12_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0u32;


        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq12::hinted_square(a);

            println!("hints len {:?}", hints.len());
            let script = script! {
           
                for hint in hints { 
                    { hint.push() }
                }
                {u32::from_le_bytes([234, 190, 118, 0])}
                {u32::from_le_bytes([135, 162, 241, 5])}
                {u32::from_le_bytes([186, 52, 155, 0])}
                {u32::from_le_bytes([162, 11, 254, 31])}
                {u32::from_le_bytes([130, 167, 61, 5])}
                {u32::from_le_bytes([178, 14, 103, 23])}
                {u32::from_le_bytes([195, 223, 134, 7])}
                {u32::from_le_bytes([68, 150, 213, 11])}
                {u32::from_le_bytes([83, 1, 19, 0])}

                {u32::from_le_bytes([234, 190, 118, 0])}
                {u32::from_le_bytes([135, 162, 241, 5])}
                {u32::from_le_bytes([186, 52, 155, 0])}
                {u32::from_le_bytes([162, 11, 254, 31])}
                {u32::from_le_bytes([130, 167, 61, 5])}
                {u32::from_le_bytes([178, 14, 103, 23])}
                {u32::from_le_bytes([195, 223, 134, 7])}
                {u32::from_le_bytes([68, 150, 213, 11])}
                {u32::from_le_bytes([83, 1, 19, 0])}

                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(a) }
                { hinted_square.clone() }
                { hash_fp12() }

                { Fq::drop() }

                { hash_fp12() }

                {Fq::drop()}
                {Fq::drop()}
                {Fq::drop()}
                OP_TRUE

            };
            println!("len {:?}", script.len());
            let exec_result = execute_script(script);

            //assert!(exec_result.success);
            for i in 0..exec_result.final_stack.len() {
                println!("{i:3} {:?}", exec_result.final_stack.get(i));
            }
            println!("stack len {:?} final len {:?}", exec_result.stats.max_nb_stack_items, exec_result.final_stack.len());
            // max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            // println!("Fq12::hinted_square: {} @ {} stack final stack {}", hinted_square.len(), max_stack,exec_result.final_stack.len());
            println!("len12 {} len12h {} len6 {}", hash_fp12().len(), hash_fp12_with_hints().len(), hash_fp6().len());
        }
    }



    #[test]
    fn test_hinted_affine_double_add_eval() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_tangent = t.x.square();
        alpha_tangent /= t.y;
        alpha_tangent.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus_tangent = alpha_tangent * t.x - t.y;

        let x = alpha_tangent.square() - t.x.double();
        let y = bias_minus_tangent - alpha_tangent * x;
        let (hinted_double_line, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
        let (hinted_check_tangent, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

        let tt = G2Affine::new(x, y);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha_chord = (tt.y - q.y) / (tt.x - q.x);
        // -bias
        let bias_minus_chord = alpha_chord * tt.x - tt.y;
        assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

        let x = alpha_chord.square() - tt.x - q.x;
        let y = bias_minus_chord - alpha_chord * x;
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p_dash_x = -p.x/p.y;
        let p_dash_y = p.y.inverse().unwrap();

        let (hinted_check_chord_t, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
        let (hinted_check_chord_q, hints_check_chord_q) = new_hinted_check_line_through_point( q.x, alpha_chord, bias_minus_chord);
        let (hinted_add_line, hints_add_line) = new_hinted_affine_add_line(tt.x, q.x, alpha_chord, bias_minus_chord);

        // affine mode as well
        let mut c1new = alpha_tangent;
        c1new.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new = bias_minus_tangent;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        let mut c1new_2 = alpha_chord;
        c1new_2.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new_2 = bias_minus_chord;
        c2new_2.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        let (hinted_ell_tangent, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
        let (hinted_ell_chord, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

        let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
        let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

        let bcsize = 6+3;
        let script = script! {
            // hints
            for hint in hints_check_tangent { 
                { hint.push() }
            }
            for hint in hints_ell_tangent { 
                { hint.push() }
            }
            for hint in hints_double_line { 
                { hint.push() }
            }
            for hint in hints_check_chord_q { 
                { hint.push() }
            }
            for hint in hints_check_chord_t { 
                { hint.push() }
            }
            for hint in hints_ell_chord { 
                { hint.push() }
            }
            for hint in hints_add_line { 
                { hint.push() }
            }

            // aux
            { fq2_push_not_montgomery(alpha_chord)}
            { fq2_push_not_montgomery(bias_minus_chord)}
            { fq2_push_not_montgomery(alpha_tangent)}
            { fq2_push_not_montgomery(bias_minus_tangent)}
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }

            // bit commits
            { fq_push_not_montgomery(p_dash_x) }
            { fq_push_not_montgomery(p_dash_y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { Fq::push_zero() } // hash
            { Fq::push_zero() } // hash
            { Fq::push_zero() } // hash
            

            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::copy(bcsize+6)} // t.x
            { Fq2::copy(bcsize+6)} // t.y
            { hinted_check_tangent }

            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(4 + 7) } // p_dash
            { hinted_ell_tangent }
            { Fq2::toaltstack() } // le.0
            { Fq2::toaltstack() } // le.1


            { Fq2::copy(bcsize+4)} // bias
            { Fq2::copy(bcsize+8)} // alpha
            { Fq2::copy(bcsize+6)} // t.x
            { hinted_double_line }
            { Fq2::toaltstack() }
            { Fq2::toaltstack()}
            // { fq2_push_not_montgomery(tt.y) }
            // { Fq2::equalverify() }
            // { fq2_push_not_montgomery(tt.x) }
            // { Fq2::equalverify() }

            { Fq2::roll(bcsize+6) } // alpha tangent drop
            { Fq2::drop() }
            { Fq2::roll(bcsize+4) } // bias tangent drop
            { Fq2::drop() }

            // hinted check chord // t.x, t.y
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::copy(8+1) } // q.x
            { Fq2::copy(8+1) } // q.y
            { hinted_check_chord_q }
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
            { Fq2::copy(2)} // t.x
            { Fq2::toaltstack() }
            { hinted_check_chord_t }


            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(10+1) } // p_dash
            { hinted_ell_chord }

            { Fq2::roll(4+bcsize+4) } // bias
            { Fq2::roll(6+bcsize+4) } // alpha
            { Fq2::copy(4+4+4+1) } //q.x
            { Fq2::fromaltstack() }
            { hinted_add_line }

            { Fq2::toaltstack() }//R
            { Fq2::toaltstack() }
            
            { Fq2::toaltstack() } //le_add
            { Fq2::toaltstack() } 

  
            { Fq::toaltstack() } //hashes
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }

            //T
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u8()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            {hash_128b_168k.clone()}

            // fetch 1 hash
            { Fq::fromaltstack()} // aux_hash
            {unpack_u32_to_u8()}
            {hash_64b_75k.clone()}
            {pack_u8_to_u32()}
            { Fq::fromaltstack()} //input_hash
            {Fq2::drop()} //{Fq::equalverify(1, 0)}

            for i in 0..13 {
                {Fq::fromaltstack()}
            }

            // Hash le
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u8()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            {hash_128b_168k.clone()}
            {pack_u8_to_u32()}
            {Fq::toaltstack()}
            
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u8()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            {hash_128b_168k.clone()}
            {pack_u8_to_u32()}
            {Fq::toaltstack()}

            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u8()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u8()}
            {hash_128b_168k.clone()}
            //{nibbles_to_fq()}

            // bring back hash
            { Fq::fromaltstack()}
            { unpack_u32_to_u8()}
            {hash_64b_75k.clone()}
            { Fq::fromaltstack()}
            { unpack_u32_to_u8()}
            {hash_64b_75k.clone()}
            {pack_u8_to_u32()}

            {Fq2::drop()} //{Fq::equalverify(1, 0)}
            OP_TRUE
        };

        let len = script.len();
        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", len, res.stats.max_nb_stack_items);
    }


}