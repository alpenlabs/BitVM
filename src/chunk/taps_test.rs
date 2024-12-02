
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::chunk::api::nib_to_byte_array;
    use crate::chunk::hint_models::*;
    use crate::chunk::msm::{bitcom_hash_p, hint_hash_p, tap_hash_p};
    use crate::chunk::taps::*;
    use crate::chunk::primitves::extern_hash_fps;
    use crate::chunk::taps_mul::*;
    use crate::chunk::wots::{wots_p160_get_pub_key, wots_p256_get_pub_key, WOTSPubKey};
    use crate::signatures::wots::wots160;
    use ark_ff::{AdditiveGroup, Field};
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::treepp::*;

    #[test]
    fn test_frob_fq12() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1];
        let sec_out = 0;
        let power = 4;
        let frob_scr = tap_frob_fp12(power);

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_scr = bitcom_frob_fp12(&pub_scripts, sec_out, sec_in.clone());
        
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        
        
        let hint_in: HintInFrobFp12 = HintInFrobFp12 { f };
        let (_, simulate_stack_input, maybe_wrong) = hints_frob_fp12(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in.clone(),
            hint_in,
            power,
        );

        let tap_len = frob_scr.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {frob_scr}
        };

        let res = execute_script(script);
        assert!(!res.success && res.final_stack.len() == 1);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_hash_c() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let sec_out = 0;
        let hash_c_scr = tap_hash_c();

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();
        let bitcom_scr = bitcom_hash_c(&pub_scripts, sec_out, sec_in.clone());

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
        let hint_in = HintInHashC { c: f, hashc: fhash };
        let mut sig = Sig {
            msk: Some(sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) = hint_hash_c(&mut sig, sec_out, sec_in, hint_in);

        let tap_len = hash_c_scr.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {hash_c_scr}
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
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1];
        let sec_out = 0;
        let hash_c_scr = tap_hash_c2();

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_scr = bitcom_hash_c2(&pub_scripts, sec_out, sec_in.clone());

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
        let hint_in = HintInHashC { c: f, hashc: fhash };
        let (_, simulate_stack_input, maybe_wrong) = hint_hash_c2(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = hash_c_scr.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {hash_c_scr}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_hash_T4() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_in = vec![1, 2, 3, 4];
        let sec_out = 0;
        let hash_c_scr = tap_initT4();

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!(
            "{}{:04X}",
            sec_key_for_bitcomms, sec_out
        ));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_scr = bitcom_initT4(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        //t4.y = t4.y + t4.y;
        let hint_in = HintInInitT4 { t4 };
        let (_, simulate_stack_input, maybe_wrong) = hint_init_T4(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = hash_c_scr.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {hash_c_scr}
        };

        let res = execute_script(script);

        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_precompute_Px() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let precompute_p = tap_precompute_Px();
        let sec_out = 0;
        let sec_in = vec![1, 2, 3];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_scr = bitcom_precompute_Px(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInPrecomputePx {
            p,
        };
        let (_, simulate_stack_input, maybe_wrong) = hints_precompute_Px(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = precompute_p.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {precompute_p}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_precompute_Py() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sec_out = 0;
        let sec_in = vec![1];

        let precompute_p = tap_precompute_Py();
        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_scr = bitcom_precompute_Py(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::Fq::rand(&mut prng);
        let hint_in = HintInPrecomputePy { p };
        let (_, simulate_stack_input, maybe_wrong) = hints_precompute_Py(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = precompute_p.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_scr}
            {precompute_p}
        };

        let res = execute_script(script);

        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert_eq!(res.final_stack.len(), 1);
        println!(
            "success {}, script {} stack {}",
            res.success, tap_len, res.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinited_sparse_dense_mul() {
        // compile time
        let dbl_blk = false;
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let sparse_dense_mul_script = tap_sparse_dense_mul(dbl_blk);

        let sec_out = 0;
        let sec_in = vec![1, 2];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script = bitcom_sparse_dense_mul(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let dbl_le0 = ark_bn254::Fq2::rand(&mut prng);
        let dbl_le1 = ark_bn254::Fq2::rand(&mut prng);
        let hint_in = HintInSparseDenseMul {
            a: f,
            le0: dbl_le0,
            le1: dbl_le1,
            hash_other_le: [2u8; 64],
            hash_aux_T: [3u8; 64],
        };

        let (_, simulate_stack_input, maybe_wrong) = hint_sparse_dense_mul(
            &mut &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
            dbl_blk,
        );

        let tap_len = sparse_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_script }
            { sparse_dense_mul_script }
        };

        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:3} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_hinited_dense_dense_mul0() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul0(false);

        let sec_out = 0;
        let sec_in = vec![1, 2];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_scr = bitcom_dense_dense_mul0(&pub_scripts, sec_out, sec_in.clone());


        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = ark_bn254::Fq12::rand(&mut prng); // check_is_identity true
        let h = f * g;

        let hash_f = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        ); // dense
        let hash_g = extern_hash_fps(
            vec![
                g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
                g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
            ],
            false,
        ); // sparse
        let hash_h = extern_hash_fps(
            vec![
                h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
            ],
            true,
        );

        let mut sig_cache: HashMap<u32, SigData> = HashMap::new();
        let bal: [u8; 32] = nib_to_byte_array(&hash_f).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in[0].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[0].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&hash_g).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in[1].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[1].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&hash_h).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_out.0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out.0), &bal)));



        let hint_in = HintInDenseMul0 { a: f, b: g };

        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul0(
            &mut Sig {
                msk: None,
                cache: sig_cache,
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_scr }
            { dense_dense_mul_script }
        };
        let tap_len = script.len();
        let exec_result = execute_script(script);
        println!("stack len {:?}", exec_result.final_stack.len());
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_hinited_dense_dense_mul1() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul1(false);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_script = bitcom_dense_dense_mul1(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = ark_bn254::Fq12::rand(&mut prng);
        let hint_in = HintInDenseMul1 { a: f, b: g };
        let h = f * g;

        let hash_f = extern_hash_fps(
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
            true,
        );
        let hash_g = extern_hash_fps(
            vec![
                g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
                g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
            ],
            false,
        );
    
        let hash_c0 = extern_hash_fps(
            vec![
                h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1,
            ],
            true,
        );
        let hash_c = extern_hash_fps(
            vec![
                h.c0.c0.c0, h.c0.c0.c1, h.c0.c1.c0, h.c0.c1.c1, h.c0.c2.c0, h.c0.c2.c1, h.c1.c0.c0,
                h.c1.c0.c1, h.c1.c1.c0, h.c1.c1.c1, h.c1.c2.c0, h.c1.c2.c1,
            ],
            true,
        );

        let mut sig_cache: HashMap<u32, SigData> = HashMap::new();
        let bal: [u8; 32] = nib_to_byte_array(&hash_f).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in[0].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[0].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&hash_g).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in[1].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[1].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&hash_c0).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_in[2].0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_in[2].0), &bal)));


        let bal: [u8; 32] = nib_to_byte_array(&hash_c).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        sig_cache.insert(sec_out.0, SigData::Sig160(wots160::get_signature(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out.0), &bal)));

        
        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul1(
            &mut Sig {
                msk: None,
                cache: sig_cache,
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len() + bitcom_script.len();

        println!("tap len {:?}", tap_len );
        let script = script! {
            { simulate_stack_input }
            { bitcom_script }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        println!("stack len {:?}", exec_result.final_stack.len());
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }


    #[test]
    fn test_hinited_dense_dense_mul0_by_constant() {
        // compile time
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let g = ark_bn254::Fq12::rand(&mut prng); // check_is_identity true
        // let ghash = emulate_extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        //     g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul0_by_constant(true, g);

        let sec_out = 0;
        let sec_in = vec![1];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_scr = bitcom_dense_dense_mul0_by_constant(&pub_scripts, sec_out, sec_in.clone());

        // runtime

        let f = g.inverse().unwrap(); //ark_bn254::Fq12::rand(&mut prng);

        let h = f * g;

        let hint_in = HintInDenseMul0 { a: f, b: g };

        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul0_by_constant(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_scr }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        println!("stack len {:?}", exec_result.final_stack.len());
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }



    #[test]
    fn test_hinited_dense_dense_mul1_by_constant() {
        // compile time
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let g = ark_bn254::Fq12::rand(&mut prng);
        // let ghash = emulate_extern_hash_fps(vec![g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
        //     g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1], false);
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul1_by_constant(false, g);

        let sec_out = 0;
        let sec_in = vec![1, 2];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_script = bitcom_dense_dense_mul1_by_constant(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let f = ark_bn254::Fq12::rand(&mut prng);

        let hint_in = HintInDenseMul1 { a: f, b: g };

        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul1_by_constant(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_script }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }


    #[test]
    fn test_tap_fq12_hinted_square() {
        // compile time
        let msk = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let squaring_tapscript = tap_squaring();
        let sec_out = 0;
        let sec_in = vec![1];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", msk, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", msk, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcomms_tapscript = bitcom_squaring(&pub_scripts, sec_out, sec_in.clone());

        // run time
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let ahash = extern_hash_fps(
            vec![
                a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0,
                a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1,
            ],
            true,
        );
        let hint_in: HintInSquaring = HintInSquaring { a, ahash };

        let mut sig = Sig {
            msk: Some(&msk),
            cache: HashMap::new(),
        };
        let (_, stack_data, maybe_wrong) = hint_squaring(&mut sig, sec_out, sec_in, hint_in);

        let tap_len = squaring_tapscript.len();
        let script = script! {
            { stack_data }
            { bitcomms_tapscript }
            { squaring_tapscript }
        };

        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_tap_affine_double_add_eval() {
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let ate = 1;
        let point_ops_tapscript = tap_point_ops(ate);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3, 4, 5, 6, 7];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script = bitcom_point_ops(&pub_scripts, sec_out, sec_in.clone(), ate); // cleaner if ate could be removed

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = todo!(); //ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8; 64];
        // let hint_in = HintInAdd {
        //     t,
        //     p,
        //     q,
        // };

        let mut sig = Sig {
            msk: Some(sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) = hint_point_ops(&mut sig, sec_out, sec_in, (t, p, q), ate);

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_script}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(!res.success && res.final_stack.len() == 1);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_affine_double_eval() {
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_dbl();

        let sec_out = 0;
        let sec_in = vec![1, 2, 3];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script = bitcom_point_dbl(&pub_scripts, sec_out, sec_in.clone());

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8; 64]; // mock
        let t4acc: G2PointAcc = G2PointAcc { t, dbl_le: None, add_le: None };
        // let hint_in = HintInDouble { t: t4acc, p };

        let mut sig = Sig {
            msk: Some(&sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) = hint_point_dbl(&mut sig, sec_out, sec_in.clone(), todo!());

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {simulate_stack_input}
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
    fn test_tap_affine_add_eval() {
        let ate = 1;
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let point_ops_tapscript = tap_point_add_with_frob(ate);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3, 4, 5, 6, 7];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script = bitcom_point_add_with_frob(&pub_scripts, sec_out, sec_in.clone());

        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t = todo!(); //ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hash_le_aux = [2u8; 64];
        // let hint_in = HintInAdd {
        //     t,
        //     p,
        //     q,
        // };

        let mut sig = Sig {
            msk: Some(sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) =
            hint_point_add_with_frob(&mut sig, sec_out, sec_in, (t, p, q), ate);

        let tap_len = point_ops_tapscript.len();
        let script = script! {
            {simulate_stack_input}
            {bitcom_script}
            {point_ops_tapscript}
        };

        let res = execute_script(script);
        assert!(!res.success && res.final_stack.len() == 1);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_dbl_sparse_muls() {
        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let (sparse_dbl_tapscript, _, _) = tap_double_eval_mul_for_fixed_Qs(t2, t3);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3, 4];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script =
            bitcom_double_eval_mul_for_fixed_Qs(&pub_scripts, sec_out, sec_in.clone());

        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInSparseDbl {
            t2,
            t3,
            p2: p2dash,
            p3: p3dash,
        };

        let mut sig = Sig {
            msk: Some(sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) =
            hint_double_eval_mul_for_fixed_Qs(&mut sig, sec_out, sec_in, hint_in);

        let tap_len = sparse_dbl_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            {bitcom_script}
            { sparse_dbl_tapscript }
        };

        let exec_result = execute_script(script);

        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_tap_add_sparse_muls() {
        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let ate = -1;
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let (sparse_add_tapscript, _, _) = tap_add_eval_mul_for_fixed_Qs(t2, t3, q2, q3, ate);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3, 4];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script = bitcom_add_eval_mul_for_fixed_Qs(&pub_scripts, sec_out, sec_in.clone());

        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInSparseAdd {
            t2,
            t3,
            p2: p2dash,
            p3: p3dash,
            q2,
            q3,
        };

        let mut sig = Sig {
            msk: Some(sec_key_for_bitcomms),
            cache: HashMap::new(),
        };
        let (_, simulate_stack_input, maybe_wrong) =
            hint_add_eval_mul_for_fixed_Qs(&mut sig, sec_out, sec_in, hint_in, ate);

        let tap_len = sparse_add_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_script }
            { sparse_add_tapscript }
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_tap_add_sparse_muls_with_frob() {
        // Compile time: Ts are known in advance for fixed G2 pairing
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let (sparse_add_tapscript, _, _) =
            tap_add_eval_mul_for_fixed_Qs_with_frob(t2, t3, q2, q3, 1);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3, 4];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p256_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, true);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, true)).collect();

        let bitcom_script =
            bitcom_add_eval_mul_for_fixed_Qs_with_frob(&pub_scripts, sec_out, sec_in.clone());

        // Run time
        let p2dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3dash = ark_bn254::g1::G1Affine::rand(&mut prng);
        let hint_in = HintInSparseAdd {
            t2,
            t3,
            p2: p2dash,
            p3: p3dash,
            q2,
            q3,
        };
        let (_, simulate_stack_input, maybe_wrong) = hint_add_eval_mul_for_fixed_Qs_with_frob(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
            1,
        );

        let tap_len = sparse_add_tapscript.len();

        let script = script! {
            { simulate_stack_input }
            {bitcom_script}
            { sparse_add_tapscript }
        };

        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }


    #[test]
    fn test_hinited_dense_dense_mul0_by_hash() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul0_by_hash();

        let sec_out = 0;
        let sec_in = vec![1, 2];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_scr = bitcom_dense_dense_mul0_by_hash(&pub_scripts, sec_out, sec_in.clone());

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap(); // check_is_identity true
        let ghash = extern_hash_fps(
        vec![
            g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
            g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
        ],
        false,  
        ); // sparse
        //let h = ark_bn254::Fq12::ONE;

        let hint_in = HintInDenseMulByHash0 { a: f, bhash: ghash };

        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul0_by_hash(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_scr }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        println!("stack len {:?}", exec_result.final_stack.len());
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }

    #[test]
    fn test_hinited_dense_dense_mul1_by_hash() {
        // compile time
        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dense_dense_mul_script = tap_dense_dense_mul1(false);

        let sec_out = 0;
        let sec_in = vec![1, 2, 3];

        let mut pub_scripts: HashMap<u32, WOTSPubKey> = HashMap::new();
        let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, sec_out));
        pub_scripts.insert(sec_out, pk);
        for i in &sec_in {
            let pk = wots_p160_get_pub_key(&format!("{}{:04X}", sec_key_for_bitcomms, i));
            pub_scripts.insert(*i, pk);
        }

        let sec_out = (sec_out, false);
        let sec_in: Vec<Link> = sec_in.iter().map(|x| (*x, false)).collect();

        let bitcom_script = bitcom_dense_dense_mul1_by_hash(&pub_scripts, sec_out, sec_in.clone());


        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(17);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap();

        let hash_g = extern_hash_fps(
            vec![
                g.c0.c0.c0, g.c0.c0.c1, g.c0.c1.c0, g.c0.c1.c1, g.c0.c2.c0, g.c0.c2.c1, g.c1.c0.c0,
                g.c1.c0.c1, g.c1.c1.c0, g.c1.c1.c1, g.c1.c2.c0, g.c1.c2.c1,
            ],
            false,
        );

        let hint_in = HintInDenseMulByHash1 { a: f, bhash: hash_g };

        let (_, simulate_stack_input, maybe_wrong) = hints_dense_dense_mul1_by_hash(
            &mut Sig {
                msk: Some(sec_key_for_bitcomms),
                cache: HashMap::new(),
            },
            sec_out,
            sec_in,
            hint_in,
        );

        let tap_len = dense_dense_mul_script.len();

        let script = script! {
            { simulate_stack_input }
            { bitcom_script }
            { dense_dense_mul_script }
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success && exec_result.final_stack.len() == 1);
        println!(
            "stack len {:?} script len {:?}",
            exec_result.stats.max_nb_stack_items, tap_len
        );
    }



    // #[test]
    // fn nib_reconstruction() {
    //     let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
    //     let mut prng = ChaCha20Rng::seed_from_u64(1);
    //     let pt = ark_bn254::Fq::rand(&mut prng);
    //     let pt_nib:[u8;40] = emulate_fq_to_nibbles(pt)[24..64].try_into().unwrap();
    //     let pubkey = winterntiz_compact_hash::get_pub_key(sec_key_for_bitcomms);
    //     let sig = winterntiz_compact_hash::sign(sec_key_for_bitcomms, pt_nib);
    //     let lock_script = wots_compact_hash_checksig_verify_fq(pubkey);
    //     let script = script!{
    //         {sig}
    //         {lock_script}
    //         {fq_push_not_montgomery(pt)}
    //     };
    //     println!("pt_nib {:?}", pt_nib);
    //     let tap_len = script.len();
    //     let exec_result = execute_script(script);
    //     for i in 0..exec_result.final_stack.len() {
    //         println!("{i:} {:?}", exec_result.final_stack.get(i));
    //     }
    //     assert!(exec_result.success);
    //     println!("stack len {:?} script len {:?}", exec_result.stats.max_nb_stack_items, tap_len);
    // }

    // #[test]
    // fn truncated_hashing_test() {
    //     let mut prng = ChaCha20Rng::seed_from_u64(1);
    //     let a = ark_bn254::Fq12::rand(&mut prng);
    //     let ahash = emulate_extern_hash_fps(vec![a.c0.c0.c0,a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0,a.c0.c2.c1, a.c1.c0.c0,a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0,a.c1.c2.c1], true);
    //     let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";

    //     let sig = winterntiz_compact_hash::sign(sec_key_for_bitcomms, ahash[24..64].try_into().unwrap());

    //     let pub_key = winterntiz_compact_hash::get_pub_key(sec_key_for_bitcomms);
    //     let lock = winterntiz_compact_hash::checksig_verify_fq(pub_key);

    //     let script = script!{
    //         {sig}
    //         {lock}
    //         OP_TRUE
    //     };
    //     let exec_result = execute_script(script);
    //     for i in 0..exec_result.final_stack.len() {
    //         println!("{i:} {:?}", exec_result.final_stack.get(i));
    //     }
    //     println!("ahash {:?}", ahash);
    // }
}

