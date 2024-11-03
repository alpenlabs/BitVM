use ark_bn254::Bn254;

use crate::signatures::wots::{wots160, wots256};
use crate::{chunk, treepp::*};

pub const N_VERIFIER_PUBLIC_INPUTS: usize = 3;
pub const N_VERIFIER_FQs: usize = 40;
pub const N_VERIFIER_HASHES: usize = 574;

pub const N_TAPLEAVES: usize = 579;

pub type WotsPublicKeys = (
    (wots256::PublicKey, wots256::PublicKey, wots256::PublicKey),
    [wots256::PublicKey; N_VERIFIER_FQs],
    [wots160::PublicKey; N_VERIFIER_HASHES],
);

pub type WotsSignatures = (
    (wots256::Signature, wots256::Signature, wots256::Signature),
    [wots256::Signature; N_VERIFIER_FQs],
    [wots160::Signature; N_VERIFIER_HASHES],
);

pub type ProofAssertions = (
    [[u8; 32]; 3],
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

    /// Validates the groth16 proof assertion signatures and returns a tuple of (tapleaf_index, tapleaf_script, and witness_script) if
    /// the proof is invalid, else returns none
    pub fn validate_assertion_signatures(
        proof: Proof,
        vk: VerificationKey,
        signatures: WotsSignatures,
        pubkeys: WotsPublicKeys,
        verifier_scripts: &[Script; N_TAPLEAVES],
    ) -> Option<(u32, Script, Script)> {
        let r = chunk::api::validate_assertions(
            proof.proof,
            proof.public_inputs,
            &vk.ark_vk,
            signatures,
            pubkeys,
            verifier_scripts,
        );
        r
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use rand::Rng;

    use super::*;

    fn generate_mock_proof() -> (
        ark_groth16::Proof<Bn254>,
        Vec<ark_bn254::Fr>,
        ark_groth16::VerifyingKey<Bn254>,
    ) {
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

        (proof, vec![pub_commit, pub_commit1, pub_commit2], vk)
    }

    fn mock_pubkeys() -> WotsPublicKeys {
        let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";

        let pub0 = wots256::generate_public_key(&format!("{secret}{:04x}", 0));
        let pub1 = wots256::generate_public_key(&format!("{secret}{:04x}", 1));
        let pub2 = wots256::generate_public_key(&format!("{secret}{:04x}", 2));
        let mut fq_arr = vec![];
        for i in 0..N_VERIFIER_FQs {
            let p256 = wots256::generate_public_key(&format!("{secret}{:04x}", 3 + i));
            fq_arr.push(p256);
        }
        let mut h_arr = vec![];
        for i in 0..N_VERIFIER_HASHES {
            let p160 =
                wots160::generate_public_key(&format!("{secret}{:04x}", N_VERIFIER_FQs + 3 + i));
            h_arr.push(p160);
        }
        let wotspubkey: WotsPublicKeys = (
            (pub0, pub1, pub2),
            fq_arr.try_into().unwrap(),
            h_arr.try_into().unwrap(),
        );
        wotspubkey
    }

    fn sign_assertions(assn: ProofAssertions) -> WotsSignatures {
        let (ps, fs, hs) = (assn.0, assn.1, assn.2);
        let secret = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let ps0 = wots256::get_signature(&format!("{secret}{:04x}", 0), &ps[0]);
        let ps1 = wots256::get_signature(&format!("{secret}{:04x}", 1), &ps[1]);
        let ps2 = wots256::get_signature(&format!("{secret}{:04x}", 2), &ps[2]);

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

        let r = ((ps0, ps1, ps2), fsig, hsig);
        r
    }

    #[test]
    fn test_fn_compile() {
        let (_, _, mock_vk) = generate_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == 4); // 3 pub inputs

        let _ops_scripts = Verifier::compile(VerificationKey { ark_vk: mock_vk });
    }

    #[test]
    fn test_fn_generate_tapscripts() {
        println!("start");

        let (_, _, mock_vk) = generate_mock_proof();
        println!("compiled circuit");

        assert!(mock_vk.gamma_abc_g1.len() == 4); // 3 pub inputs
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
            tapscripts.map(|script| script.len())
        );
    }

    #[test]
    fn test_fn_generate_assertions() {
        let (proof, pubs, mock_vk) = generate_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == 4); // 3 pub inputs
        let proof_asserts = Verifier::generate_assertions(
            VerificationKey { ark_vk: mock_vk },
            Proof {
                proof,
                public_inputs: pubs,
            },
        );
        let signed_asserts = sign_assertions(proof_asserts);
    }

    #[test]
    fn test_fn_validate_assertions() {
        let (proof, pubs, mock_vk) = generate_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == 4); // 3 pub inputs
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
        let verifer_scripts = Verifier::generate_tapscripts(mock_pubks, &ops_scripts);

        let fault = Verifier::validate_assertion_signatures(
            Proof {
                proof,
                public_inputs: pubs,
            },
            VerificationKey { ark_vk: mock_vk },
            signed_asserts,
            mock_pubks,
            &verifer_scripts,
        );
        assert!(fault.is_none());
    }

    fn corrupt(proof_asserts: &mut ProofAssertions) {
        let mut rng = rand::thread_rng();

        // Generate a random number between 1 and 100 (inclusive)
        let random_number =
            rng.gen_range(0..N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs + N_VERIFIER_HASHES);
        println!("corrupted assertion at index {}", random_number);
        if random_number < N_VERIFIER_PUBLIC_INPUTS {
            let index = random_number;
            if index == 0 {
                proof_asserts.0[0] = [1u8; 32];
            } else if index == 1 {
                proof_asserts.0[1] = [1u8; 32];
            } else {
                proof_asserts.0[2] = [1u8; 32];
            }
        } else if random_number < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs {
            let index = random_number - N_VERIFIER_PUBLIC_INPUTS;
            proof_asserts.1[index] = [1u8; 32];
        } else if random_number < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQs + N_VERIFIER_HASHES {
            let index = random_number - N_VERIFIER_PUBLIC_INPUTS - N_VERIFIER_FQs;
            proof_asserts.2[index] = [1u8; 20];
        }
    }

    #[test]
    fn test_fn_disprove_invalid_assertions() {
        let (proof, pubs, mock_vk) = generate_mock_proof();
        assert!(mock_vk.gamma_abc_g1.len() == 4); // 3 pub inputs
        let mut proof_asserts = Verifier::generate_assertions(
            VerificationKey {
                ark_vk: mock_vk.clone(),
            },
            Proof {
                proof: proof.clone(),
                public_inputs: pubs.clone(),
            },
        );
        // corrupt some assertion value randomly
        corrupt(&mut proof_asserts);
        let signed_asserts = sign_assertions(proof_asserts);
        let ops_scripts = Verifier::compile(VerificationKey {
            ark_vk: mock_vk.clone(),
        });
        let mock_pubks = mock_pubkeys();
        let verifer_scripts = Verifier::generate_tapscripts(mock_pubks, &ops_scripts);

        let fault = Verifier::validate_assertion_signatures(
            Proof {
                proof,
                public_inputs: pubs,
            },
            VerificationKey { ark_vk: mock_vk },
            signed_asserts,
            mock_pubks,
            &verifer_scripts,
        );
        let (index, hint_script, ops_script) = fault.unwrap();
        println!("taproot index {:?}", index);
        let scr = script!(
            {hint_script}
            {ops_script}
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }

    #[test]
    fn test_hello() {
        println!("hello");
    }
}
