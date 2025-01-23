
#[cfg(test)]
mod test {

    use crate::bn254::curves::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::utils::{fq2_push_not_montgomery, fq_push_not_montgomery, Hint};
    use crate::chunk::blake3compiled::hash_messages;
    use crate::chunk::element::*;
    use crate::chunk::primitves::{new_hash_g2acc_with_both_raw_le, new_hash_g2acc_with_hashed_le, pack_nibbles_to_limbs};
    use crate::chunk::taps_point_ops::*;
    use crate::chunk::primitves::{extern_hash_fps, extern_nibbles_to_limbs};
    use crate::chunk::taps_mul::*;
    use crate::chunk::taps_premiller::*;
    use crate::chunk::taps_point_eval::*;
    use crate::execute_script_without_stack_limit;
    use ark_ec::AffineRepr;
    use ark_ff::AdditiveGroup;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::treepp::*;


    #[test]
    fn test_tap_frob_fp12() {

        let power = 2;
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            false,
        );
        let hint_in = ElemFp12Acc { f, hash: fhash };
        let (hint_out, tap_frob, mut hint_script) = chunk_frob_fp12(hint_in, power);

        let f_acc_preimage_hints = Element::Fp12(hint_in).get_hash_preimage_as_hints(ElementType::Fp12v0);
        hint_script.extend_from_slice(&f_acc_preimage_hints);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_in.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };
        let hash_scr = script! {
            {hash_messages(vec![ElementType::Fp12v1, ElementType::Fp12v1])}
            OP_TRUE
        };

        let tap_len = tap_frob.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_frob}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_hash_c() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (hint_out, tap_hash_c, hint_script) = chunk_hash_c(fqvec.clone());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for f in fqvec.iter().rev() {
                {fq_push_not_montgomery(*f)}
                {Fq::toaltstack()}                
            }
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp12v1])}
            OP_TRUE
        );

        let tap_len = tap_hash_c.len() + hash_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_fq12() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (is_valid, tap_hash_c, hint_script) = chunk_verify_fq12_is_on_field(fqvec.clone());
        assert!(is_valid);
        let bitcom_scr = script!{
            for f in fqvec.iter().rev() {
                {fq_push_not_montgomery(*f)}
                {Fq::toaltstack()}                
            }
        };

        let tap_len = tap_hash_c.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    
    #[test]
    fn test_tap_hash_c2() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            false,
        );
        let hint_in = ElemFp12Acc { f, hash: fhash };
        let (hint_out, tap_hash_c2, mut hint_script) = chunk_hash_c2(hint_in);
        hint_script.extend_from_slice(&Element::Fp12(hint_in).get_hash_preimage_as_hints(ElementType::Fp12v1));

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_in.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp12v1, ElementType::Fp12v0])}
            OP_TRUE
        );

        let tap_len = tap_hash_c2.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c2}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_init_t4() {

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let (hint_out, init_t4_tap, hint_script) = chunk_init_t4(q.y.c1, q.y.c0, q.x.c1, q.x.c0);

        let bitcom_script = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

            {fq_push_not_montgomery(q.y.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c0)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c0)}
            {Fq::toaltstack()}
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G2T])}
            OP_TRUE
        );

        let tap_len = init_t4_tap.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {init_t4_tap}
            {hash_scr}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_chunk_verify_g2_on_curve() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (hint_out, init_t4_tap, hint_script) = chunk_verify_g2_on_curve(q.y.c1, q.y.c0, q.x.c1, q.x.c0);
        assert_eq!(hint_out, q.is_on_curve());
        let bitcom_script = script!{
            {fq_push_not_montgomery(q.y.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c0)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c0)}
            {Fq::toaltstack()}
        };
        let tap_len = init_t4_tap.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {init_t4_tap}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_p() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p(p.y, p.x);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}    
            {G1Affine::push_not_montgomery(p)}
            {Fq2::toaltstack()}     
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_p_from_hash() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p_from_hash(p);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}    
            for i in extern_nibbles_to_limbs(p.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };
        let preim_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_verify_p_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_is_on_curve(p.y, p.x);
        assert_eq!(p.is_on_curve(), is_valid_point);
        let bitcom_scr = script!{
            {G1Affine::push_not_montgomery(p)}
            {Fq2::toaltstack()}     
        };

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_phash_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_hash_is_on_curve(p);
        assert_eq!(p.is_on_curve(), is_valid_point);
        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(p.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}     
        };
        let preim_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_sparse_dense_mul() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let t = ark_bn254::G2Affine::rand(&mut prng);
        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let hint_t = ElemG2PointAcc { t, dbl_le, add_le };

        let dbl_blk = false;

        let (hint_out, tap_scr, mut hint_script) = chunk_sparse_dense_mul(hint_f, hint_t, dbl_blk);

        if dbl_blk {
            hint_script.extend_from_slice(&Element::G2Acc(hint_t).get_hash_preimage_as_hints(ElementType::G2DblEvalMul))
        } else {
            hint_script.extend_from_slice(&Element::G2Acc(hint_t).get_hash_preimage_as_hints(ElementType::G2AddEvalMul))
        }
        hint_script.extend_from_slice(&Element::Fp12(hint_f).get_hash_preimage_as_hints(ElementType::Fp12v0));

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_t.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let hash_script = script! {
            // Altstack: [Hg, Hf, HT]
            // Stack [T, f, g]
            if dbl_blk {
                {hash_messages(vec![ElementType::G2DblEvalMul, ElementType::Fp12v0, ElementType::Fp12v0])}
            } else {
                {hash_messages(vec![ElementType::G2AddEvalMul, ElementType::Fp12v0, ElementType::Fp12v0])}
            }
            OP_TRUE
        };

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_script}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_dense_dense_mul0() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            false,
        );
        let hint_g = ElemFp12Acc { f, hash: fhash };



        let (hint_out, tap_scr, mut hint_script) = chunk_dense_dense_mul0(hint_f, hint_g);
        let a_preimage_hints = Element::Fp12(hint_f).get_hash_preimage_as_hints(ElementType::Fp12v0);
        let b_preimage_hints = Element::Fp12(hint_g).get_hash_preimage_as_hints(ElementType::Fp12v1);
        hint_script.extend_from_slice(&a_preimage_hints);
        hint_script.extend_from_slice(&b_preimage_hints);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_g.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

        };

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v1, ElementType::Fp6])} //{hash_mul(true)}
            OP_TRUE
        );

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
            { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_dense_dense_mul1() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let g = ark_bn254::Fq12::rand(&mut prng);
        let ghash = extern_hash_fps(
            g.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            false,
        );
        let hint_g = ElemFp12Acc { f: g, hash: ghash };


        let c = hint_f.f * hint_g.f;
        let hash_c0 = extern_hash_fps(
            c.c0.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(), true);

        let hint_c0 = c.c0;


        let (hint_out, tap_scr, mut hint_script) = chunk_dense_dense_mul1(hint_f, hint_g, hint_c0);

        for f in &hint_f.f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>() {
            hint_script.push(Hint::Fq(*f));
        }
        for f in &hint_g.f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>() {
            hint_script.push(Hint::Fq(*f));
        }
        hint_script.push(Hint::Hash(extern_nibbles_to_limbs(hash_c0)));
        // hint_script.push(Hint::Hash(extern_nibbles_to_limbs(hash_c0)));

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

            for i in extern_nibbles_to_limbs(hint_c0.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_g.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

            for i in extern_nibbles_to_limbs(hint_f.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v1, ElementType::Fp6Hash, ElementType::Fp12v2])} 
            OP_TRUE
        );


        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }



    #[test]
    fn test_tap_verify_fp12_is_unity() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let g = f.inverse().unwrap();
        let ghash = extern_hash_fps(
            g.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_g = ElemFp12Acc { f: g, hash: ghash };

        let (_, tap_scr, mut hint_script) = chunk_verify_fp12_is_unity(hint_f, hint_g);

        let fvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
        for f in &fvec {
            hint_script.push(Hint::Fq(*f));
        } 

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_f.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_squaring() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let (hint_out, tap_scr, mut hint_script) = chunk_squaring(hint_f);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let hash_sc = script! {
            {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp12v0])} 
            OP_TRUE
        };

        let f_acc_preimage_hints = Element::Fp12(hint_f).get_hash_preimage_as_hints(ElementType::Fp12v0);
        hint_script.extend_from_slice(&f_acc_preimage_hints);

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_sc}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    

    #[test]
    fn test_tap_affine_double_add_eval() {
        let ate = -1;
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };


        let (hint_out, point_ops_tapscript, mut hint_script) = chunk_point_ops(
            t,
            q.y.c1, q.y.c0, q.x.c1, q.x.c0,
            p, ate);


        let hint_out_hash = extern_nibbles_to_limbs(hint_out.hashed_output());
        let hint_in_t4_hash = extern_nibbles_to_limbs(t.hashed_output());
        let hint_in_p_hash = extern_nibbles_to_limbs(p.hashed_output());

        let t4_hash_hints = Element::G2Acc(t).get_hash_preimage_as_hints(ElementType::G2DblAddEval);
        let p_hash_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);
        hint_script.extend_from_slice(&t4_hash_hints);
        hint_script.extend_from_slice(&p_hash_hints);

        let bitcom_script = script!{
            for i in hint_out_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_p_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_t4_hash {
                {i}
            }
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c0)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c0)} 
            {Fq::toaltstack()}
        };

        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, p, Rx, Ry, 0, 0, le0, le1, le1]
            {hash_messages(vec![ElementType::G2AddEval, ElementType::G1, ElementType::G2DblAddEval])}
            // [Rx, Ry, le0, le1, 0, 0]
            OP_TRUE
        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {point_ops_tapscript}
            {hash_script}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_affine_double_eval() {

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let t4acc: ElemG2PointAcc = ElemG2PointAcc { t: ark_bn254::G2Affine::rand(&mut prng), dbl_le: None, add_le: None };

        let (hint_out, point_ops_tapscript, mut hint_script) = chunk_point_dbl(t4acc, p);

        let hint_out_hash = extern_nibbles_to_limbs(hint_out.hashed_output());
        let hint_in_t4_hash = extern_nibbles_to_limbs(t4acc.hashed_output());
        let hint_in_p_hash = extern_nibbles_to_limbs(p.hashed_output());

        let t4_hash_hints = Element::G2Acc(t4acc).get_hash_preimage_as_hints(ElementType::G2DblEval);
        let p_hash_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);
        hint_script.extend_from_slice(&t4_hash_hints);
        hint_script.extend_from_slice(&p_hash_hints);
        

        let bitcom_values = script!{
            for i in hint_out_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_p_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_t4_hash {
                {i}
            }
            {Fq::toaltstack()}
        };

        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, p, Rx, Ry, le0, le1, 0, 0]
            {hash_messages(vec![ElementType::G2DblEval, ElementType::G1, ElementType::G2DblAddEval])}
            OP_TRUE

        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_values}
            {point_ops_tapscript}
            {hash_script}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    
    #[test]
    fn test_tap_affine_add_eval() {
        let ate = -1;

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        let (hint_out, point_ops_tapscript, mut hint_script) = chunk_point_add_with_frob(
            t, q.y.c1, q.y.c0, q.x.c1, q.x.c0, p, ate);


        let hint_out_hash = extern_nibbles_to_limbs(hint_out.hashed_output());
        let hint_in_t4_hash = extern_nibbles_to_limbs(t.hashed_output());
        let hint_in_p_hash = extern_nibbles_to_limbs(p.hashed_output());


        let t4_hash_hints = Element::G2Acc(t).get_hash_preimage_as_hints(ElementType::G2AddEval);
        let p_hash_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);
        hint_script.extend_from_slice(&t4_hash_hints);
        hint_script.extend_from_slice(&p_hash_hints);

        let bitcom_script = script!{
            for i in hint_out_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_p_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_t4_hash {
                {i}
            }
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c0)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c0)}
            {Fq::toaltstack()}
        };
        let hash_script = script! {
            //Altstack: [hash_out, hash_in]
            //Stack: [tx, ty, hash_inaux, Rx, Ry, 0, 0, le0, le1, le1]
            {hash_messages(vec![ElementType::G2AddEval, ElementType::G1, ElementType::G2DblAddEval])}
            // [Rx, Ry, le0, le1, 0, 0]
            OP_TRUE
        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {point_ops_tapscript}
            {hash_script}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_multiply_point_evals_on_tangent_for_fixed_g2() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);

        let (hint_out, tap_scr, mut hint_script) = chunk_multiply_point_evals_on_tangent_for_fixed_g2(p3, p2, t2, t3);

        hint_script.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p3.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p2.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}                 
        };
        let hash_scr = script! {
            {hash_messages(vec![ElementType::G1, ElementType::G1, ElementType::Fp12v1])}
            OP_TRUE
        };
        // let (nt2, nt3) = (hint_out.t2, hint_out.t3);
        // assert_eq!(nt2, (t2 + t2).into_affine());
        // assert_eq!(nt3, (t3 + t3).into_affine());

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_multiply_point_evals_on_chord_for_fixed_g2() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let ate = -1;
        let (hint_out, tap_scr, mut hint_script) = chunk_multiply_point_evals_on_chord_for_fixed_g2(p3, p2, t2, t3, q2, q3, ate);

        hint_script.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p3.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p2.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}                 
        };
        let hash_scr = script! {
            {hash_messages(vec![ElementType::G1, ElementType::G1, ElementType::Fp12v1])}
            OP_TRUE
        };

        // let (nt2, nt3) = (hint_out.t2, hint_out.t3);
        // if ate == 1 {
        //     assert_eq!(nt2, (t2 + q2).into_affine());
        //     assert_eq!(nt3, (t3 + q3).into_affine());
        // } else {
        //     assert_eq!(nt2, (t2 - q2).into_affine());
        //     assert_eq!(nt3, (t3 - q3).into_affine());
        // }


        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }



    #[test]
    fn test_tap_multiply_point_evals_on_chord_for_fixed_g2_with_frob() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let ate = 1;
        let (hint_out, tap_scr, mut hint_script) = chunk_multiply_point_evals_on_chord_for_fixed_g2_with_frob(p3, p2, t2, t3, q2, q3, ate);

        hint_script.extend_from_slice(&vec![Hint::Fq(p2.x), Hint::Fq(p2.y), Hint::Fq(p3.x), Hint::Fq(p3.y)]);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p3.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}  
            for i in extern_nibbles_to_limbs(p2.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}                 
        };

        // let (nt2, nt3) = (hint_out.t2, hint_out.t3);
        // assert_eq!( nt3, get_hint_for_add_with_frob(q3, t3, ate));
        // assert_eq!( nt2, get_hint_for_add_with_frob(q2, t2, ate));

        let hash_scr = script! {
            {hash_messages(vec![ElementType::G1, ElementType::G1, ElementType::Fp12v1])}
            OP_TRUE
        };

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_bn254_fq12_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a = ark_bn254::Fq12::rand(&mut prng);

            let hash_in = extern_hash_fps(a.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(), true);
            let (hout0,tscr0,  mut hscr0) = chunk_inv0(ElemFp12Acc { f: a, hash: hash_in });
            hscr0.extend_from_slice(&Element::Fp12(ElemFp12Acc { f: a, hash: hash_in }).get_hash_preimage_as_hints(ElementType::Fp12v0));
            
            let bscr0 = script!{
                for h in extern_nibbles_to_limbs(hout0.hashed_output() ) {
                    {h}
                }
                {Fq::toaltstack()}
                for h in extern_nibbles_to_limbs(hash_in) {
                    {h}
                }
                {Fq::toaltstack()}
            };
            let hash_scr = script!{
                {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp6])}
                OP_TRUE
            };
            let script = script! {
                for h in hscr0 {
                    { h.push() }
                }
                { bscr0 }
                { tscr0 }
                {hash_scr}
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv0 len {} and stack {}", len, res.stats.max_nb_stack_items);


            let (hout1,tscr1, mut hscr1) = chunk_inv1(hout0);
            hscr1.extend_from_slice(&Element::Fp6(hout0).get_hash_preimage_as_hints(ElementType::Fp6));

            let bscr1 = script!{
                for h in hout1.hashed_output() {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout0.hashed_output() {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };
            let hash_scr = script!{
                {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
                OP_TRUE
            };

            let script = script! {
                for h in hscr1 {
                    { h.push() }
                }
                { bscr1 }
                { tscr1 }
                {hash_scr}
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv1 len {} and stack {}", len, res.stats.max_nb_stack_items);


            let a = ElemFp12Acc { f: a, hash: hash_in };
            let (hout2,tscr2, mut hscr2) = chunk_inv2(hout1, a);
            hscr2.extend_from_slice(&Element::Fp12(a).get_hash_preimage_as_hints(ElementType::Fp12v0));
            hscr2.extend_from_slice(&Element::Fp6(hout1).get_hash_preimage_as_hints(ElementType::Fp6));
            
            assert_eq!(hout2.f, a.f.inverse().unwrap());
            let bscr2 = script!{
                for h in hout2.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout1.hashed_output() {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}                
                for h in hash_in {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };
            let hash_scr = script!{
                {hash_messages(vec![ElementType::Fp12v0, ElementType::Fp6, ElementType::Fp12v1])}
                OP_TRUE
            };
            let script = script! {
                { bscr2 }
                for h in hscr2 {
                    { h.push() }
                }
                { tscr2 }
                {hash_scr}
            };
            let len = script.len();
            let res = execute_script_without_stack_limit(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv2 len {} and stack {}", len, res.stats.max_nb_stack_items);
    }   

    // TEST G2PointAcc Hasher
    #[test]
    fn test_hash_t_with_hashed_le() {

        fn hash_g2acc_with_hashed_le() -> Script {
            script! {
                //Stack: [tx, ty, hash_inaux, hash_result]
                //T
                {Fq::toaltstack()} 
                {new_hash_g2acc_with_hashed_le()}
                {Fq::fromaltstack()}
                {Fq::equal(1, 0)}
            }
        }

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        
        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        // [t, hashed_le, hash_result]
        let scr = script!{
            {fq2_push_not_montgomery(t.t.x)}
            {fq2_push_not_montgomery(t.t.y)}
            for i in extern_nibbles_to_limbs(t.hash_le()) {
                {i}
            }
            for i in extern_nibbles_to_limbs(t.hashed_output()) {
                {i}
            }
            {hash_g2acc_with_hashed_le()}
        };

        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

    #[test]
    fn test_hash_t_with_dbl_le() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        
        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = None;
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        // [t, dbl_le, hash_result]
        let scr = script!{
            {fq2_push_not_montgomery(t.t.x)}
            {fq2_push_not_montgomery(t.t.y)}
            {fq2_push_not_montgomery(t.dbl_le.unwrap().0)}
            {fq2_push_not_montgomery(t.dbl_le.unwrap().1)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}

            for i in extern_nibbles_to_limbs(t.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}

            {new_hash_g2acc_with_both_raw_le()}
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

    #[test]
    fn test_hash_t_with_add_le() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);

        let dbl_le = None;
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        // [t, dbl_le, hash_result]
        let scr = script!{
            {fq2_push_not_montgomery(t.t.x)}
            {fq2_push_not_montgomery(t.t.y)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(t.add_le.unwrap().0)}
            {fq2_push_not_montgomery(t.add_le.unwrap().1)}

            for i in extern_nibbles_to_limbs(t.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            {new_hash_g2acc_with_both_raw_le()}
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

}

