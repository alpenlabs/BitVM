
#[cfg(test)]
mod test {
    use std::{collections::HashMap, io, ops::Neg};

    use crate::chunk::{config::{assign_link_ids, NUM_PUBS, NUM_U160, NUM_U256}, evaluate::*, hint_models::HintOut, primitves::{emulate_fq_to_nibbles, emulate_fr_to_nibbles}, taps::Sig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;

    use crate::{
        chunk::{
            compile::{compile, Vkey},
            config::{get_type_for_link_id, keygen},
            test_utils::{
                read_pubkey_from_file, read_scripts_from_file, write_map_to_file, write_pubkey_to_file, write_scripts_to_file, write_scripts_to_separate_files
            }, wots::{wots_p160_sign_digits, wots_p256_sign_digits},
        },
        groth16::offchain_checker::compute_c_wi,
    };

    use crate::treepp::*;

    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read, Write};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct GrothProof {
        c: ark_bn254::Fq12,
        s: ark_bn254::Fq12,
        p2: ark_bn254::G1Affine,  // vk->q2
        p4: ark_bn254::G1Affine,
        q4: ark_bn254::G2Affine,
        scalars: Vec<ark_bn254::Fr>, // msm(scalar, vk_gamma) -> p3; vk->q3
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct GrothVK {
        vk_pubs: Vec<ark_bn254::G1Affine>,
        q2: ark_bn254::G2Affine,
        q3: ark_bn254::G2Affine,
        f_fixed: ark_bn254::Fq12, // mill(p1,q1)
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    struct GrothProofBytes {
        c: Vec<u8>,
        s: Vec<u8>,
        p2: Vec<u8>,
        p4: Vec<u8>,
        q4: Vec<u8>,
        scalars: Vec<Vec<u8>>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    pub(crate) struct GrothVKBytes {
        q2: Vec<u8>,
        q3: Vec<u8>,
        vk_pubs: Vec<Vec<u8>>,
        f_fixed: Vec<u8>,
    }

    impl GrothProof {
        fn write_groth16_proof_to_file(&self, filename: &str) {
            let mut cbytes = Vec::new();
            let mut sbytes = Vec::new();
            let mut p2bytes = Vec::new();
            let mut p4bytes = Vec::new();
            let mut q4bytes = Vec::new();
            let mut scalarbytes_arr = Vec::new();
            self.c.serialize_uncompressed(&mut cbytes).unwrap();
            self.s.serialize_uncompressed(&mut sbytes).unwrap();
            self.p2.serialize_uncompressed(&mut p2bytes).unwrap();
            self.p4.serialize_uncompressed(&mut p4bytes).unwrap();
            self.q4.serialize_uncompressed(&mut q4bytes).unwrap();
            for scalar in self.scalars.clone() {
                let mut scalbytes = Vec::new();
                scalar.serialize_uncompressed(&mut scalbytes).unwrap();
                scalarbytes_arr.push(scalbytes);
            }
            let gbytes = GrothProofBytes {
                c: cbytes,
                s: sbytes,
                p2: p2bytes,
                p4: p4bytes,
                q4: q4bytes,
                scalars: scalarbytes_arr,
            };
            gbytes.write_to_file(filename).unwrap();
        }

        fn read_groth16_proof_from_file(filename: &str) -> Self {
            let gpb = GrothProofBytes::read_from_file(filename).unwrap();
            let s = Self {
                c: ark_bn254::Fq12::deserialize_uncompressed_unchecked(gpb.c.as_slice()).unwrap(),
                s: ark_bn254::Fq12::deserialize_uncompressed_unchecked(gpb.s.as_slice()).unwrap(),
                p2: ark_bn254::G1Affine::deserialize_uncompressed_unchecked(gpb.p2.as_slice())
                    .unwrap(),
                p4: ark_bn254::G1Affine::deserialize_uncompressed_unchecked(gpb.p4.as_slice())
                    .unwrap(),
                q4: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q4.as_slice())
                    .unwrap(),
                scalars: gpb
                    .scalars
                    .iter()
                    .map(|x| {
                        ark_bn254::Fr::deserialize_uncompressed_unchecked(x.as_slice()).unwrap()
                    })
                    .collect(),
            };
            s
        }
    }

    impl GrothVK {
        fn write_vk_to_file(&self, filename: &str) {
            let mut q2bytes = Vec::new();
            let mut q3bytes = Vec::new();
            let mut fbytes = Vec::new();
            let mut vkpubs_arr = Vec::new();
            self.q2.serialize_uncompressed(&mut q2bytes).unwrap();
            self.q3.serialize_uncompressed(&mut q3bytes).unwrap();
            self.f_fixed.serialize_uncompressed(&mut fbytes).unwrap();
            for vkp in self.vk_pubs.clone() {
                let mut scalbytes = Vec::new();
                vkp.serialize_uncompressed(&mut scalbytes).unwrap();
                vkpubs_arr.push(scalbytes);
            }
            let gbytes = GrothVKBytes {
                q2: q2bytes,
                q3: q3bytes,
                vk_pubs: vkpubs_arr,
                f_fixed: fbytes,
            };
            gbytes.write_to_file(filename).unwrap();
        }

        fn read_vk_from_file(filename: &str) -> Self {
            let gpb = GrothVKBytes::read_from_file(filename).unwrap();
            let s = Self {
                q2: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q2.as_slice())
                    .unwrap(),
                q3: ark_bn254::G2Affine::deserialize_uncompressed_unchecked(gpb.q3.as_slice())
                    .unwrap(),
                f_fixed: ark_bn254::Fq12::deserialize_uncompressed_unchecked(
                    gpb.f_fixed.as_slice(),
                )
                .unwrap(),
                vk_pubs: gpb
                    .vk_pubs
                    .iter()
                    .map(|x| {
                        ark_bn254::G1Affine::deserialize_uncompressed_unchecked(x.as_slice())
                            .unwrap()
                    })
                    .collect(),
            };
            s
        }
    }

    fn generate_mock_proof() -> (GrothProof, GrothVK) {
        use ark_bn254::Bn254;
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ec::pairing::Pairing;
        use ark_ff::PrimeField;
        use ark_groth16::Groth16;
        use ark_relations::lc;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
        use ark_std::{test_rng, UniformRand};
        use rand::{RngCore, SeedableRng};

        #[derive(Copy)]
        struct DummyCircuit<F: PrimeField> {
            pub a: Option<F>,
            pub b: Option<F>,
            pub num_variables: usize,
            pub num_constraints: usize,
        }

        impl<F: PrimeField> Clone for DummyCircuit<F> {
            fn clone(&self) -> Self {
                DummyCircuit {
                    a: self.a,
                    b: self.b,
                    num_variables: self.num_variables,
                    num_constraints: self.num_constraints,
                }
            }
        }

        impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let a =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                let b =
                    cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
                let c = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a * b)
                })?;
                let d = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a + b)
                })?;
                let e = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a - b)
                })?;

                for _ in 0..(self.num_variables - 3) {
                    let _ = cs
                        .new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                }

                for _ in 0..self.num_constraints - 1 {
                    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
                }

                cs.enforce_constraint(lc!(), lc!(), lc!())?;

                Ok(())
            }
        }

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let pub_commit = circuit.a.unwrap() * circuit.b.unwrap();
        let pub_commit1 = circuit.a.unwrap() + circuit.b.unwrap();
        let pub_commit2 = circuit.a.unwrap() - circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();


        // G1/G2 points for pairings
        let msm_g1 =  vk.gamma_abc_g1[0] * ark_bn254::Fr::ONE + vk.gamma_abc_g1[1] * pub_commit + vk.gamma_abc_g1[2] * pub_commit1 + vk.gamma_abc_g1[3] * pub_commit2;
        let (p3, p2, p1, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;

        let (c, s) = compute_c_wi(f);

        (
            GrothProof {
                c,
                s,
                p2,
                p4,
                q4,
                scalars: vec![pub_commit, pub_commit1, pub_commit2],
            },
            GrothVK {
                q2,
                q3,
                vk_pubs: vk.gamma_abc_g1,
                f_fixed: p1q1,
            },
        )
    }

    impl GrothVKBytes {
        fn write_to_file(&self, path: &str) -> io::Result<()> {
            let proof_encoded = serde_json::to_vec(self)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(&proof_encoded)?;
            Ok(())
        }

        fn read_from_file(path: &str) -> io::Result<Self> {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let proof = serde_json::from_slice(&buffer)?;
            Ok(proof)
        }
    }

    impl GrothProofBytes {
        fn write_to_file(&self, path: &str) -> io::Result<()> {
            let proof_encoded = serde_json::to_vec(self)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(&proof_encoded)?;
            Ok(())
        }

        fn read_from_file(path: &str) -> io::Result<Self> {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let proof = serde_json::from_slice(&buffer)?;
            Ok(proof)
        }
    }

    #[test]
    fn test_gen_groth() {
        let gp_f = "chunker_data/groth_proof.bin";
        let vk_f = "chunker_data/groth_vk.bin";
        let (mock_proof, mock_vk) = generate_mock_proof();
        mock_proof.write_groth16_proof_to_file(gp_f);
        mock_vk.write_vk_to_file(vk_f);
        let read_mock_proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let read_vk = GrothVK::read_vk_from_file(vk_f);
        assert_eq!(read_mock_proof, mock_proof);
        assert_eq!(read_vk, mock_vk);
    }

    #[test]
    fn test_operator_generates_keys() {
        let pubs_f = "chunker_data/pubkeys.json";
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pubs = keygen(master_secret);
       write_pubkey_to_file(&pubs, pubs_f).unwrap();
       let read_pubs = read_pubkey_from_file(pubs_f).unwrap();
       assert_eq!(read_pubs, pubs);
    }

    #[test]
    fn test_compile_to_taptree() {
        let vk_f = "chunker_data/groth_vk.bin";
        let pubs_f = "chunker_data/pubkeys.json";
        let pubkeys = read_pubkey_from_file(pubs_f).unwrap();
        let vk = GrothVK::read_vk_from_file(vk_f);
        let save_to_file = true;
        let p1q1 =  vk.f_fixed;
        let p3vk = vec![vk.vk_pubs[3], vk.vk_pubs[2], vk.vk_pubs[1]];
        let vky0 = vk.vk_pubs[0];
        let ops_scripts_per_link = compile(
            Vkey {
                q2: vk.q2,
                q3: vk.q3,
                p3vk: p3vk.clone(),
                p1q1,
                vky0,
            },
            &HashMap::new(), // no pubkeys needed to get ops_script
            false
        );
        
        let bitcom_scripts_per_link = compile(
            Vkey {
                q2: vk.q2,
                q3: vk.q3,
                p3vk,
                p1q1,
                vky0,
            },
            &pubkeys,
            true
        );

        let mut tap_scripts_per_link: Vec<(u32, Script)> = vec![];
        assert_eq!(ops_scripts_per_link.len(), bitcom_scripts_per_link.len());
        for i in 0..bitcom_scripts_per_link.len() {
            let sc = script!{
                {bitcom_scripts_per_link[i].1.clone()}
                {ops_scripts_per_link[i].1.clone()}
            };
            let index = ops_scripts_per_link[i].0;
            assert_eq!(index, bitcom_scripts_per_link[i].0);
            tap_scripts_per_link.push((index, sc));
        }

        if save_to_file {
            let mut script_cache = HashMap::new();
            for (k, v) in tap_scripts_per_link {
                script_cache.insert(k, vec![v]);
            }
            write_scripts_to_separate_files(script_cache, "tapnode");
        }
    }

    #[test]
    fn test_operator_generates_assertion() {
        let gp_f = "chunker_data/groth_proof.bin";
        let vk_f = "chunker_data/groth_vk.bin";
        let assert_f = "chunker_data/assert.json";
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let dump_assertions_to_file = true;

        let pub_scripts_per_link_id = &keygen(master_secret);
        let mut sig = Sig {
            msk: Some(master_secret),
            cache: HashMap::new(),
        };

        let proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let vk = GrothVK::read_vk_from_file(vk_f);
        let msm_scalar = vec![proof.scalars[2],proof.scalars[1],proof.scalars[0]];
        let msm_gs = vec![vk.vk_pubs[3],vk.vk_pubs[2],vk.vk_pubs[1]]; // vk.vk_pubs[0]
        let p3 =  vk.vk_pubs[0] * ark_bn254::Fr::ONE + vk.vk_pubs[1] * proof.scalars[0] + vk.vk_pubs[2] * proof.scalars[1] + vk.vk_pubs[3] * proof.scalars[2];

        let p3 = p3.into_affine();

        let fault = evaluate(
            &mut sig,
            pub_scripts_per_link_id,
            proof.p2,
            p3,
            proof.p4,
            vk.q2,
            vk.q3,
            proof.q4,
            proof.c,
            proof.s,
            vk.f_fixed,
            msm_scalar,
            msm_gs,
            vk.vk_pubs[0],
        );
        assert!(fault.is_none());
        if dump_assertions_to_file {
            write_scripts_to_file(sig.cache, assert_f);
        }
    }

    #[test]
    fn test_challenger_executes_disprove() {
        let chunker_data_path = "chunker_data";
        let gp_f = &format!("{chunker_data_path}/groth_proof.bin");
        let vk_f = &format!("{chunker_data_path}/groth_vk.bin");
        let assert_f = &format!("{chunker_data_path}/assert.json");
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pubs_f = &format!("{chunker_data_path}/pubkeys.json");

        let pub_scripts_per_link_id = read_pubkey_from_file(pubs_f).unwrap();
        let proof = GrothProof::read_groth16_proof_from_file(gp_f);
        let vk = GrothVK::read_vk_from_file(vk_f);
        let msm_scalar = vec![proof.scalars[2],proof.scalars[1],proof.scalars[0]];
        let msm_gs = vec![vk.vk_pubs[3], vk.vk_pubs[2], vk.vk_pubs[1]];

        let p3 =  vk.vk_pubs[0] * ark_bn254::Fr::ONE + vk.vk_pubs[1] * proof.scalars[0] + vk.vk_pubs[2] * proof.scalars[1] + vk.vk_pubs[3] * proof.scalars[2];
        let p3 = p3.into_affine();

        for index_to_corrupt in 39..90 { // m0 -> 584
            if index_to_corrupt == 50 {
                continue;
            }
            //let index_to_corrupt = 64;
            let index_is_field = get_type_for_link_id(index_to_corrupt).unwrap();
            println!(
                "load with faulty assertion ({}, {})",
                index_to_corrupt, index_is_field
            );
    
            let mut assertion = read_scripts_from_file(assert_f);
            let mut corrup_scr = wots_p160_sign_digits(
                &format!("{}{:04X}", master_secret, index_to_corrupt),
                [1u8; 40],
            );
            if index_is_field {
                corrup_scr = wots_p256_sign_digits(
                    &format!("{}{:04X}", master_secret, index_to_corrupt),
                    [1u8; 64],
                );
            }
            assertion.insert(index_to_corrupt, corrup_scr);
    
            let mut sig = Sig {
                msk: None,
                cache: assertion,
            };
    
            let fault = evaluate(
                &mut sig,
                &pub_scripts_per_link_id,
                proof.p2,
                p3,
                proof.p4,
                vk.q2,
                vk.q3,
                proof.q4,
                proof.c,
                proof.s,
                vk.f_fixed,
                msm_scalar.clone(),
                msm_gs.clone(),
                vk.vk_pubs[0],
            );
            assert!(fault.is_some());
            let fault = fault.unwrap();
            let index_to_corrupt = fault.0;
            let hints_to_disprove = fault.1;
    
            let read = read_scripts_from_file(&format!(
                "{chunker_data_path}/tapnode_{index_to_corrupt}.json"
            ));
            let read_scr = read.get(&index_to_corrupt).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            println!("Executing Disprove Node {:?}", index_to_corrupt);
    
            let script = script! {
                { hints_to_disprove.clone() }
                {tap_node}
            };
            let exec_result = execute_script(script);
            println!("Exec Result Pass: {}", exec_result.success);
            if !exec_result.success {
                println!("Exec Result Failed :");
                for i in 0..exec_result.final_stack.len() {
                    println!("{i:} {:?}", exec_result.final_stack.get(i));
                }
                panic!()
            } else {
                let mut disprove_map: HashMap<u32, Vec<Script>> = HashMap::new();
                let disprove_f = &format!("{chunker_data_path}/disprove_{index_to_corrupt}.json");
                disprove_map.insert(index_to_corrupt, vec![hints_to_disprove]);
                write_scripts_to_file(disprove_map, disprove_f);
            }
        }
        // read assertions
     }


     #[test]
     fn test_extract_values_from_hints() {
        let (link_name_to_id, facc, tacc) = assign_link_ids(NUM_PUBS, NUM_U256, NUM_U160);
        let aux_out_per_link: HashMap<String, HintOut> = HashMap::new();
        for (k, v) in aux_out_per_link {
            let x = match v {
                HintOut::Add(r) => r.out(),
                HintOut::DblAdd(r) => r.out(),
                HintOut::DenseMul0(r) => r.out(),
                HintOut::DenseMul1(r) => r.out(),
                HintOut::Double(r) => r.out(),
                HintOut::FieldElem(f) => emulate_fq_to_nibbles(f),
                HintOut::FrobFp12(f) => f.out(),
                HintOut::GrothC(r) => r.out(),
                HintOut::HashC(r) => r.out(),
                HintOut::InitT4(r) => r.out(),
                HintOut::MSM(r) => r.out(),
                HintOut::ScalarElem(r) => emulate_fr_to_nibbles(r),
                HintOut::SparseAdd(r) => r.out(),
                HintOut::SparseDbl(r) => r.out(),
                HintOut::SparseDenseMul(r) => r.out(),
                HintOut::Squaring(r) => r.out(),
            };
        }
     }

     #[test]
     fn assign_link_ids_to_array() {

     }
}

