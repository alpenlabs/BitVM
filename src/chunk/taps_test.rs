
#[cfg(test)]
mod test {

    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::utils::{fq2_push_not_montgomery, fq_push_not_montgomery};
    use crate::chunk::hint_models::*;
    use crate::chunk::primitves::{fp12_to_vec, pack_nibbles_to_limbs};
    use crate::chunk::taps_point_ops::*;
    use crate::chunk::primitves::{extern_hash_fps, extern_nibbles_to_limbs};
    use crate::chunk::taps_mul::*;
    use crate::chunk::taps_premiller::*;
    use crate::chunk::taps_point_eval::*;
    use crate::execute_script_without_stack_limit;
    use ark_ec::CurveGroup;
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
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            false,
        );
        let hint_in = ElemFp12Acc { f, hash: fhash };
        let (hint_out, hint_script) = hints_frob_fp12(hint_in, power);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_in.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_frob = tap_frob_fp12(power);

        let tap_len = tap_frob.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {tap_frob}
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
        let fqvec = vec![
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ];

        let (hint_out, hint_script) = hint_hash_c(fqvec.clone());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for f in fqvec {
                {fq_push_not_montgomery(f)}
                {Fq::toaltstack()}                
            }
        };

        let tap_hash_c = tap_hash_c();

        let tap_len = tap_hash_c.len();
        let script = script! {
            {hint_script}
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
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            false,
        );
        let hint_in = ElemFp12Acc { f, hash: fhash };
        let (hint_out, hint_script) = hint_hash_c2(hint_in);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_in.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_hash_c2 = tap_hash_c2();

        let tap_len = tap_hash_c2.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {tap_hash_c2}
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
        let init_t4_tap = tap_initT4();

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let (hint_out, hint_script) = hint_init_T4(q.y.c1, q.y.c0, q.x.c1, q.x.c0);

        let bitcom_script = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
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


        let tap_len = init_t4_tap.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_precompute_x() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, hint_script) = hints_precompute_Px(p.y, p.x, p.y.inverse().unwrap());

        let bitcom_scr = script!{
            {fq_push_not_montgomery(hint_out)}
            {Fq::toaltstack()}    
            {fq_push_not_montgomery(p.y)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p.x)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p.y.inverse().unwrap())}
            {Fq::toaltstack()}                
        };

        let tap_prex = tap_precompute_Px();

        let tap_len = tap_prex.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {tap_prex}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_y() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, hint_script) = hints_precompute_Py(p.y);

        let bitcom_scr = script!{
            {fq_push_not_montgomery(hint_out)}
            {Fq::toaltstack()}    
            {fq_push_not_montgomery(p.y)}
            {Fq::toaltstack()}                       
        };

        let tap_prey = tap_precompute_Py();

        let tap_len = tap_prey.len();
        let script = script! {
            {hint_script}
            {bitcom_scr}
            {tap_prey}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_sparse_dense_mul() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let t = ark_bn254::G2Affine::rand(&mut prng);
        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let hint_t = ElemG2PointAcc { t, dbl_le, add_le };

        let dbl_blk = true;

        let (hint_out, hint_script) = hint_sparse_dense_mul(hint_f, hint_t, dbl_blk);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_t.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_sparse_dense_mul(dbl_blk);

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_dense_dense_mul0() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            false,
        );
        let hint_g = ElemFp12Acc { f, hash: fhash };



        let (hint_out, hint_script) = hints_dense_dense_mul0(hint_f, hint_g);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_g.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_dense_dense_mul0();

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_dense_dense_mul1() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let g = ark_bn254::Fq12::rand(&mut prng);
        let ghash = extern_hash_fps(
            vec![
                g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
                g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
            ],
            false,
        );
        let hint_g = ElemFp12Acc { f: g, hash: ghash };


        let c = hint_f.f * hint_g.f;
        let hash_c = extern_hash_fps(
            vec![
                c.c0.c0.c0, c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0, c.c0.c2.c1,
            ], true);

        let hint_c0 = ElemFp12Acc {f: ark_bn254::Fq12::new(c.c0, ark_bn254::Fq6::ZERO), hash: hash_c};


        let (hint_out, hint_script) = hints_dense_dense_mul1(hint_f, hint_g, hint_c0);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_g.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_c0.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_dense_dense_mul1();

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_dense_dense_mul0_by_constant() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let f = f.inverse().unwrap();
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            false,
        );
        let hint_g = ElemFp12Acc { f, hash: fhash };



        let (hint_out, hint_script) = hints_dense_dense_mul0_by_constant(hint_f, hint_g);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_dense_dense_mul0_by_constant(hint_g.f);

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_dense_dense_mul1_by_constant() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let fhash = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let g = f.inverse().unwrap();
        let ghash = extern_hash_fps(
            vec![
                g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
                g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
            ],
            false,
        );
        let hint_g = ElemFp12Acc { f: g, hash: ghash };


        let c = hint_f.f * hint_g.f;
        let hash_c = extern_hash_fps(
            vec![
                c.c0.c0.c0, c.c0.c0.c1, c.c0.c1.c0, c.c0.c1.c1, c.c0.c2.c0, c.c0.c2.c1,
            ], true);

        let hint_c0 = ElemFp12Acc {f: ark_bn254::Fq12::new(c.c0, ark_bn254::Fq6::ZERO), hash: hash_c};


        let (hint_out, hint_script) = hints_dense_dense_mul1_by_constant(hint_f, hint_c0, hint_g);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_c0.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_dense_dense_mul1_by_constant(hint_g.f);

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hint_f = ElemFp12Acc { f, hash: fhash };

        let (hint_out, hint_script) = hint_squaring(hint_f);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hint_f.out()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_scr = tap_squaring();

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_affine_double_add_eval() {
        let ate = -1;
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        let point_ops_tapscript = tap_point_ops(ate);

        let (hint_out, hint_script) = hint_point_ops(
            t,
             q.y.c1, q.y.c0, q.x.c1, q.x.c0,
              p.y, p.x, ate);

        let bitcom_script = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(t.out()) {
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
            {fq_push_not_montgomery(p.y)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(p.x)}
            {Fq::toaltstack()}
        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {hint_script}
            {bitcom_script}
            {point_ops_tapscript}
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
        let point_ops_tapscript = tap_point_dbl();

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let t4acc: ElemG2PointAcc = ElemG2PointAcc { t: ark_bn254::G2Affine::rand(&mut prng), dbl_le: None, add_le: None };

        let (hint_out, hint_script) = hint_point_dbl(t4acc, p.y, p.x);

        let hint_out_hash = extern_nibbles_to_limbs(hint_out.out());
        let hint_in_hash = extern_nibbles_to_limbs(t4acc.out());

        let bitcom_values = script!{
            for i in hint_out_hash {
                {i}
            }
            {Fq::toaltstack()}
            for i in hint_in_hash {
                {i}
            }
            {Fq::toaltstack()}
            {fq_push_not_montgomery(p.y)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(p.x)}
            {Fq::toaltstack()}
        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {hint_script}
            {bitcom_values}
            {point_ops_tapscript}
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
        let ate = 1;
        let point_ops_tapscript = tap_point_add_with_frob(ate);

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        let (hint_out, hint_script) = hint_point_add_with_frob(
            t,
             q.y.c1, q.y.c0, q.x.c1, q.x.c0, p.y, p.x, ate);
        let bitcom_script = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(t.out()) {
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
            {fq_push_not_montgomery(p.y)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(p.x)}
            {Fq::toaltstack()}
        };

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {hint_script}
            {bitcom_script}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_double_eval_mul_for_fixed_Qs() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);

        let (hint_out, hint_script) = hint_double_eval_mul_for_fixed_Qs(p3.y, p3.x, p2.y, p2.x, t2, t3);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}    
            {fq_push_not_montgomery(p3.y)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p3.x)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p2.y)}
            {Fq::toaltstack()}           
            {fq_push_not_montgomery(p2.x)}
            {Fq::toaltstack()}                
        };

        let (tap_scr, nt2, nt3) = tap_double_eval_mul_for_fixed_Qs(t2, t3);
        assert_eq!(nt2, (t2 + t2).into_affine());
        assert_eq!(nt3, (t3 + t3).into_affine());

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_add_eval_mul_for_fixed_Qs() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let ate = -1;

        let (hint_out, hint_script) = hint_add_eval_mul_for_fixed_Qs(p3.y, p3.x, p2.y, p2.x, t2, t3, q2, q3, ate);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}    
            {fq_push_not_montgomery(p3.y)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p3.x)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p2.y)}
            {Fq::toaltstack()}           
            {fq_push_not_montgomery(p2.x)}
            {Fq::toaltstack()}                
        };

        let (tap_scr, nt2, nt3) = tap_add_eval_mul_for_fixed_Qs(t2, t3, q2, q3, ate);

        if ate == 1 {
           assert_eq!( (nt2, nt3), ((t2 + q2).into_affine(), (t3 + q3).into_affine()));
        } else {
            assert_eq!( (nt2, nt3), ((t2 - q2).into_affine(), (t3 - q3).into_affine()));
        }

        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_tap_add_eval_mul_for_fixed_Qs_with_frob() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let ate = -1;

        let (hint_out, hint_script) = hint_add_eval_mul_for_fixed_Qs_with_frob(p3.y, p3.x, p2.y, p2.x, t2, t3, q2, q3, ate);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.out()) {
                {i}
            }
            {Fq::toaltstack()}    
            {fq_push_not_montgomery(p3.y)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p3.x)}
            {Fq::toaltstack()}          
            {fq_push_not_montgomery(p2.y)}
            {Fq::toaltstack()}           
            {fq_push_not_montgomery(p2.x)}
            {Fq::toaltstack()}                
        };

        let (tap_scr, nt2, nt3) = tap_add_eval_mul_for_fixed_Qs_with_frob(t2, t3, q2, q3, ate);

        assert_eq!( (nt2, nt3), (get_hint_for_add_with_frob(q2, t2, ate), get_hint_for_add_with_frob(q3, t3, ate)));


        let tap_len = tap_scr.len();
        let script = script! {
            {hint_script}
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
    fn test_bn254_fq12_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a = ark_bn254::Fq12::rand(&mut prng);

            let hash_in = extern_hash_fps(fp12_to_vec(a), true);
            let (hout0, hscr0) = hint_inv0(ElemFp12Acc { f: a, hash: hash_in });
            let tscr0 = tap_inv0();
            let bscr0 = script!{
                for h in hout0.hash {
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
            let script = script! {
                { hscr0 }
                { bscr0 }
                { tscr0 }
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv0 len {} and stack {}", len, res.stats.max_nb_stack_items);


            let (hout1, hscr1) = hint_inv1(hout0);

            let tscr1 = tap_inv1();
            let bscr1 = script!{
                for h in hout1.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout0.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
            };

            let script = script! {
                { hscr1 }
                { bscr1 }
                { tscr1 }
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("inv1 len {} and stack {}", len, res.stats.max_nb_stack_items);



            let (hout2, hscr2) = hint_inv2(hout1, ElemFp12Acc { f: a, hash: hash_in });
            let tscr2 = tap_inv2();
            assert_eq!(hout2.f, a.inverse().unwrap());
            let bscr2 = script!{
                for h in hout2.hash {
                    {h}
                }
                {pack_nibbles_to_limbs()}
                {Fq::toaltstack()}
                for h in hout1.hash {
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

            let script = script! {
                { bscr2 }
                { hscr2 }
                { tscr2 }
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
            for i in extern_nibbles_to_limbs(t.out()) {
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

            for i in extern_nibbles_to_limbs(t.out()) {
                {i}
            }
            {hash_g2acc_with_raw_le(true)}
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
            {fq2_push_not_montgomery(t.add_le.unwrap().0)}
            {fq2_push_not_montgomery(t.add_le.unwrap().1)}

            for i in extern_nibbles_to_limbs(t.out()) {
                {i}
            }
            {hash_g2acc_with_raw_le(false)}
        };
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

    #[test]
    fn test_hash_t_with_aux_t() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);

        let dbl_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));;
        let add_le = Some((ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng)));
        let t = ElemG2PointAcc { t, dbl_le, add_le };

        //Stack: [Ht, cur_le, Hother_le, hash_result]
        let scr = script!{
            for i in extern_nibbles_to_limbs(t.hash_t()) {
                {i}
            }
            {fq2_push_not_montgomery(t.dbl_le.unwrap().0)}
            {fq2_push_not_montgomery(t.dbl_le.unwrap().1)}
            for i in extern_nibbles_to_limbs(t.hash_other_le(true)) {
                {i}
            }
            for i in extern_nibbles_to_limbs(t.out()) {
                {i}
            }
            {hash_g2acc_with_hashed_t(true)}
        };
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }
}

