use ark_bn254::Bn254;

use crate::signatures::wots::{wots160, wots256};
use crate::{chunk, treepp::*};

pub const N_VERIFIER_PUBLIC_INPUTS: usize = 1;
pub const N_VERIFIER_FQs: usize = 40;
pub const N_VERIFIER_HASHES: usize = 574;

pub const N_TAPLEAVES: usize = 579;

pub type WotsPublicKeys = (
    [wots256::PublicKey; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::PublicKey; N_VERIFIER_FQs],
    [wots160::PublicKey; N_VERIFIER_HASHES],
);

pub type WotsSignatures = (
    [wots256::Signature; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::Signature; N_VERIFIER_FQs],
    [wots160::Signature; N_VERIFIER_HASHES],
);

pub type ProofAssertions = (
    [[u8; 32]; N_VERIFIER_PUBLIC_INPUTS],
    [[u8; 32]; N_VERIFIER_FQs],
    [[u8; 20]; N_VERIFIER_HASHES],
);

pub struct VerificationKey {
    pub ark_vk: ark_groth16::VerifyingKey<Bn254>,
}

pub struct Proof {
    pub proof: ark_groth16::Proof<Bn254>,
    pub public_inputs: Vec<ark_bn254::Fr>,
}

pub struct Verifier {
    pub vk: VerificationKey,
}

impl Verifier {
    pub fn compile(vk: VerificationKey) -> [Script; N_TAPLEAVES] {
        let res = chunk::api::api_compile(&vk.ark_vk);
        res.try_into().unwrap()
    }

    pub fn generate_tapscripts(
        public_keys: WotsPublicKeys,
        verifier_scripts: &[Script; N_TAPLEAVES],
    ) -> [Script; N_TAPLEAVES] {
        let res = chunk::api::generate_tapscripts(public_keys, verifier_scripts);
        res.try_into().unwrap()
    }

    pub fn generate_assertions(vk: VerificationKey, proof: Proof) -> ProofAssertions {
        chunk::api::generate_assertions(proof.proof, proof.public_inputs, &vk.ark_vk)
    }

    /// Validates the groth16 proof assertion signatures and returns a tuple of (tapleaf_index, witness_script) if
    /// the proof is invalid, else returns none
    pub fn validate_assertion_signatures(
        vk: VerificationKey,
        signatures: WotsSignatures,
        pubkeys: WotsPublicKeys,
    ) -> Option<(usize, Script)> {
        let r = chunk::api::validate_assertions(
            &vk.ark_vk,
            signatures,
            pubkeys,
        );
        r
    }
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ark_bn254::Bn254;
    use ark_ec::CurveGroup;
    use ark_ff::Field;
    use rand::Rng;

    use crate::chunk::{api::mock_pubkeys, test_utils::{read_scripts_from_file, write_scripts_to_separate_files}};

    use self::{chunk::config::NUM_PUBS, mock::{compile_circuit, generate_proof}};

    use super::*;


    pub mod mock {
        use ark_bn254::{Bn254, Fr as F};
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ff::AdditiveGroup;
        use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
        use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
        use ark_std::test_rng;
        use rand::{RngCore, SeedableRng};
        use super::*;

        #[derive(Clone)]
        pub struct DummyCircuit {
            pub a: Option<F>, // Private input a
            pub b: Option<F>, // Private input b
            pub c: F,         // Public output: a * b
            pub d: F,         // Public output: a + b
            pub e: F,         // Public output: a - b
        }

        impl ConstraintSynthesizer<F> for DummyCircuit {
            fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                // Allocate private inputs a and b as witnesses
                let a = FpVar::new_witness(cs.clone(), || {
                    self.a.ok_or(SynthesisError::AssignmentMissing)
                })?;
                let b = FpVar::new_witness(cs.clone(), || {
                    self.b.ok_or(SynthesisError::AssignmentMissing)
                })?;

                // Allocate public outputs c, d, and e
                let c = FpVar::new_input(cs.clone(), || Ok(self.c))?;
                let d = FpVar::new_input(cs.clone(), || Ok(self.d))?;
                let e = FpVar::new_input(cs.clone(), || Ok(self.e))?;

                // Enforce the constraints: c = a * b, d = a + b, e = a - b
                let computed_c = &a * &b;
                let computed_d = &a + &b;
                let computed_e = &a - &b;

                computed_c.enforce_equal(&c)?;
                computed_d.enforce_equal(&d)?;
                computed_e.enforce_equal(&e)?;

                Ok(())
            }
        }

        pub fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
            type E = Bn254;
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let circuit = DummyCircuit {
                a: None,
                b: None,
                c: F::ZERO,
                d: F::ZERO,
                e: F::ZERO,
            };
            let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
            (pk, vk)
        }

        pub fn generate_proof() -> Proof {
            let (a, b) = (5, 3);
            let (c, d, e) = (a * b, a + b, a - b);

            let circuit = DummyCircuit {
                a: Some(F::from(a)),
                b: Some(F::from(b)),
                c: F::from(c),
                d: F::from(d),
                e: F::from(e),
            };

            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

            let (pk, _) = compile_circuit();

            let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            let public_inputs = vec![circuit.c, circuit.d, circuit.e];

            Proof {
                proof,
                public_inputs,
            }
        }

    }

    fn generate_new_mock_proof() -> (
        ark_groth16::Proof<Bn254>,
        Vec<ark_bn254::Fr>,
        ark_groth16::VerifyingKey<Bn254>,
    )  {
        let (_, vk) = compile_circuit();
        let proof = generate_proof();

        // change public inputs count by mergin vks
        let pubins = proof.public_inputs.clone(); // [0, 1, 2]

        let mut new_vky0 = vk.gamma_abc_g1[0] * ark_bn254::Fr::ONE;
        for i in 0..pubins.len() - N_VERIFIER_PUBLIC_INPUTS { // 0..3-1
            new_vky0 = new_vky0 + vk.gamma_abc_g1[i+1] * pubins[i];
        }
        let mut new_vky = vec![];
        let mut new_scalars = vec![];
        for i in (pubins.len() - N_VERIFIER_PUBLIC_INPUTS)..pubins.len() { // 3-1..3
            new_vky.push(vk.gamma_abc_g1[i+1]);
            new_scalars.push(pubins[i]);
        }

        let mut new_vk = vk.clone();
        new_vk.gamma_abc_g1 = vec![new_vky0.into_affine()];
        new_vk.gamma_abc_g1.extend(new_vky);

        let r = (
            proof.proof,
            new_scalars,
            new_vk
        );
        r
    }

    fn sign_assertions(assn: ProofAssertions) -> WotsSignatures {
        let (ps, fs, hs) = (assn.0, assn.1, assn.2);
        let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        
        let mut psig: Vec<wots256::Signature> = vec![];
        for i in 0..NUM_PUBS {
            let psi = wots256::get_signature(&format!("{secret}{:04x}", i), &ps[i]);
            psig.push(psi);
        }
        let psig: [wots256::Signature; NUM_PUBS] = psig.try_into().unwrap();

        let mut fsig: Vec<wots256::Signature> = vec![];
        for i in 0..fs.len() {
            let fsi = wots256::get_signature(&format!("{secret}{:04x}", 3 + i), &fs[i]);
            fsig.push(fsi);
        }
        let fsig: [wots256::Signature; N_VERIFIER_FQs] = fsig.try_into().unwrap();

        let mut hsig: Vec<wots160::Signature> = vec![];
        for i in 0..hs.len() {
            let hsi = wots160::get_signature(&format!("{secret}{:04x}", 3 + fs.len() + i), &hs[i]);
            hsig.push(hsi);
        }
        let hsig: [wots160::Signature; N_VERIFIER_HASHES] = hsig.try_into().unwrap();

        let r = (psig, fsig, hsig);
        r
    }

    #[test]
    fn test_fn_compile() {
        let (_, _, mock_vk) = generate_new_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); // 3 pub inputs

        let ops_scripts = Verifier::compile(VerificationKey { ark_vk: mock_vk });
        let mut script_cache = HashMap::new();

        for i in 0..ops_scripts.len() {
            script_cache.insert(i as u32, vec![ops_scripts[i].clone()]);
        }

        write_scripts_to_separate_files(script_cache, "tapnode");
    }

    #[test]
    fn test_fn_generate_tapscripts() {
        println!("start");

        let (_, _, mock_vk) = generate_new_mock_proof();
        println!("compiled circuit");

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); // 3 pub inputs
        let mock_pubs = mock_pubkeys();
        let ops_scripts = Verifier::compile(VerificationKey {
            ark_vk: mock_vk.clone(),
        });
        println!(
            "script.lens: {:?}",
            ops_scripts.as_ref().iter().map(|script| script.len())
        );

        let tapscripts = Verifier::generate_tapscripts(mock_pubs, &ops_scripts);
        println!(
            "tapscript.lens: {:?}",
            tapscripts.clone().map(|script| script.len())
        );

    }

    #[test]
    fn test_fn_generate_assertions() {
        let (proof, pubs, mock_vk) = generate_new_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); // 3 pub inputs
        let proof_asserts = Verifier::generate_assertions(
            VerificationKey { ark_vk: mock_vk },
            Proof {
                proof,
                public_inputs: pubs,
            },
        );
        println!("signed_asserts {:?}", proof_asserts);
        let signed_asserts = sign_assertions(proof_asserts);
    }

    #[test]
    fn test_fn_validate_assertions() {
        let (proof, pubs, mock_vk) = generate_new_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); // 3 pub inputs
        let proof_asserts = Verifier::generate_assertions(
            VerificationKey {
                ark_vk: mock_vk.clone(),
            },
            Proof {
                proof: proof.clone(),
                public_inputs: pubs.clone(),
            },
        );
        let signed_asserts = sign_assertions(proof_asserts);
        let ops_scripts = Verifier::compile(VerificationKey {
            ark_vk: mock_vk.clone(),
        });
        let mock_pubks = mock_pubkeys();

        let fault = Verifier::validate_assertion_signatures(
            VerificationKey { ark_vk: mock_vk },
            signed_asserts,
            mock_pubks,
        );
        assert!(fault.is_none());
    }

    fn corrupt(proof_asserts: &mut ProofAssertions, random: Option<usize>) {
        let mut rng = rand::thread_rng();

        // Generate a random number between 1 and 100 (inclusive)
        let mut index = rng.gen_range(0..N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs + N_VERIFIER_HASHES);
        if random.is_some() {
            index = random.unwrap();
        }
        let mut scramble: [u8;32] = [1u8; 32];
        scramble[16] = 37;
        let mut scramble2: [u8;20] = [1u8; 20];
        scramble2[10] = 37;
        println!("corrupted assertion at index {}", index);
        if index < N_VERIFIER_PUBLIC_INPUTS {
            if index == 0 {
                proof_asserts.0[0] = scramble;
            } else if index == 1 {
                proof_asserts.0[1] = scramble;
            } else {
                proof_asserts.0[2] = scramble;
            }
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs {
            let index = index - N_VERIFIER_PUBLIC_INPUTS;
            proof_asserts.1[index] = scramble;
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs + N_VERIFIER_HASHES {
            let index = index - N_VERIFIER_PUBLIC_INPUTS - N_VERIFIER_FQs;
            proof_asserts.2[index] = scramble2;
        }
    }

    // #[test]
    // fn test_fn_disprove_invalid_assertions() {
    //     let (proof, pubs, mock_vk) = generate_new_mock_proof();
    //     assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS+1); // 3 pub inputs
    //                                               //let mut proof_asserts = Verifier::generate_assertions(VerificationKey { ark_vk: mock_vk.clone() }, Proof { proof: proof.clone(), public_inputs: pubs.clone() }, );
    //                                               // corrupt some assertion value randomly

    //     let mut op_scripts = vec![];
    //     println!("load scripts from file");
    //     for index in 0..N_TAPLEAVES {
    //         let read = read_scripts_from_file(&format!("chunker_data/tapnode_{index}.json"));
    //         let read_scr = read.get(&(index as u32)).unwrap();
    //         assert_eq!(read_scr.len(), 1);
    //         let tap_node = read_scr[0].clone();
    //         op_scripts.push(tap_node);
    //     }
    //     println!("done");
    //     let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap();

    //     let mock_pubks = mock_pubkeys();
    //     let verifier_scripts = Verifier::generate_tapscripts(mock_pubks, &ops_scripts);


    //     for i in 0..100 {
    //         println!("ITERATION {:?}", i);
    //         let mut proof_asserts = new_mock_asserts();
    //         corrupt(&mut proof_asserts, Some(i));
    //         let signed_asserts = sign_assertions(proof_asserts);
    
    //         let fault = Verifier::validate_assertion_signatures(
    //             VerificationKey { ark_vk: mock_vk.clone() },
    //             signed_asserts,
    //             mock_pubks,
    //         );
    //         if fault.is_some() {
    //             let (index, hint_script) = fault.unwrap();
    //             println!("taproot index {:?}", index);
    //             let scr = script!(
    //                 {hint_script}
    //                 {verifier_scripts[index].clone()}
    //             );
    //             let res = execute_script(scr);
    //             for i in 0..res.final_stack.len() {
    //                 println!("{i:} {:?}", res.final_stack.get(i));
    //             }
    //             assert!(res.success);
    //         }
    //     }
 
    // }


}
