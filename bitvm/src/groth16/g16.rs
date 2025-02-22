use ark_bn254::{Bn254, Fr};

use crate::chunk::api::{NUM_PUBS, NUM_TAPS, NUM_U160, NUM_U256};
use crate::signatures::wots_api::{wots160, wots256};
use crate::{chunk, treepp::*};

pub const N_VERIFIER_PUBLIC_INPUTS: usize = NUM_PUBS;
pub const N_VERIFIER_FQS: usize = NUM_U256;
pub const N_VERIFIER_HASHES: usize = NUM_U160;
pub const N_TAPLEAVES: usize = NUM_TAPS;

pub type Proof = ark_groth16::Proof<Bn254>;
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;

pub type PublicInputs = [Fr; N_VERIFIER_PUBLIC_INPUTS];

pub type PublicKeys = (
    [wots256::PublicKey; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::PublicKey; N_VERIFIER_FQS],
    [wots160::PublicKey; N_VERIFIER_HASHES],
);

pub type Signatures = (
    [wots256::Signature; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::Signature; N_VERIFIER_FQS],
    [wots160::Signature; N_VERIFIER_HASHES],
);

pub type Assertions = (
    [[u8; 32]; N_VERIFIER_PUBLIC_INPUTS],
    [[u8; 32]; N_VERIFIER_FQS],
    [[u8; 20]; N_VERIFIER_HASHES],
);

pub fn compile_verifier(vk: VerifyingKey) -> [Script; N_TAPLEAVES] {
    chunk::api::api_generate_partial_script(&vk).try_into().unwrap()
}

pub fn generate_disprove_scripts(
    public_keys: PublicKeys,
    partial_disprove_scripts: &[Script; N_TAPLEAVES],
) -> [Script; N_TAPLEAVES] {
    chunk::api::api_generate_full_tapscripts(public_keys, partial_disprove_scripts)
        .try_into()
        .unwrap()
}

pub fn generate_proof_assertions(vk: VerifyingKey, proof: Proof, public_inputs: PublicInputs) -> Assertions {
    chunk::api::generate_assertions(proof, public_inputs.to_vec(), &vk)
}

pub fn generate_proof_signature(vk: VerifyingKey, proof: Proof, public_inputs: PublicInputs, secret: Vec<String>) -> Signatures {
    chunk::api::generate_signatures(proof, public_inputs.to_vec(), &vk, secret)
}

/// Validates the groth16 proof assertion signatures and returns a tuple of (tapleaf_index, witness_script) if
/// the proof is invalid, else returns none
pub fn verify_signed_assertions(
    vk: VerifyingKey,
    public_keys: PublicKeys,
    signatures: Signatures,
    disprove_scripts: &[Script; N_TAPLEAVES],
) -> Option<(usize, Script)> {
    chunk::api::validate_assertions(&vk,signatures,public_keys, disprove_scripts)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ark_ec::{pairing::Pairing, AffineRepr};
    
    
    use ark_serialize::CanonicalDeserialize;
    use bitcoin::ScriptBuf;
    use rand::Rng;

    use crate::{chunk::{api::{api_generate_full_tapscripts, api_generate_partial_script, generate_signatures, validate_assertions}, api_runtime_utils::get_pubkeys}, groth16::g16::test::test_utils::{read_scripts_from_file, write_scripts_to_file, write_scripts_to_separate_files}, treepp};


    use self::{ test_utils::{read_map_from_file, write_map_to_file}};

    use super::*;


    mod test_utils {
        use crate::treepp::*;
        use bitcoin::ScriptBuf;
        use std::collections::HashMap;
        use std::error::Error;
        use std::fs::File;
        use std::io::BufReader;
        use std::io::Write;


        pub(crate) fn write_map_to_file(
            map: &HashMap<u32, Vec<Vec<u8>>>,
            filename: &str,
        ) -> Result<(), Box<dyn Error>> {
            // Serialize the map to a JSON string
            let json = serde_json::to_string(map)?;

            // Write the JSON string to a file
            let mut file = File::create(filename)?;
            file.write_all(json.as_bytes())?;
            Ok(())
        }

        pub(crate) fn read_map_from_file(
            filename: &str,
        ) -> Result<HashMap<u32, Vec<Vec<u8>>>, Box<dyn Error>> {
            let file = File::open(filename)?;
            let reader = BufReader::new(file);
            let map = serde_json::from_reader(reader)?;
            Ok(map)
        }

        pub fn write_scripts_to_file(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
            let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            for (k, v) in sig_cache {
                let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
                buf.insert(k, vs);
            }
            write_map_to_file(&buf, file).unwrap();
        }

        pub fn write_scripts_to_separate_files(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
            let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            std::fs::create_dir_all("bridge_data/chunker_data")
                .expect("Failed to create directory structure");

            for (k, v) in sig_cache {
                let file = format!("bridge_data/chunker_data/{file}_{k}.json");
                let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
                buf.insert(k, vs);
                write_map_to_file(&buf, &file).unwrap();
                buf.clear();
            }
        }

        pub fn read_scripts_from_file(file: &str) -> HashMap<u32, Vec<Script>> {
            let mut scr: HashMap<u32, Vec<Script>> = HashMap::new();
            let f = read_map_from_file(file).unwrap();
            for (k, v) in f {
                let vs: Vec<Script> = v
                    .into_iter()
                    .map(|x| {
                        let sc = script! {};
                        let bf = ScriptBuf::from_bytes(x);
                        
                        sc.push_script(bf)
                    })
                    .collect();
                scr.insert(k, vs);
            }
            scr
        }

    }

    pub mod mock {
        use super::*;
        use ark_bn254::Bn254;
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ff::{BigInt, PrimeField};
        use ark_groth16::{Groth16, ProvingKey};
        use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}};
        use ark_std::test_rng;
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
            fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
                let c = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
    
                    Ok(a * b)
                })?;
    
                for _ in 0..(self.num_variables - 3) {
                    let _ =
                        cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                }
    
                for _ in 0..self.num_constraints - 1 {
                    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
                }
    
                cs.enforce_constraint(lc!(), lc!(), lc!())?;
    
                Ok(())
            }
        }

        pub fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey) {
            type E = Bn254;
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let (a, b): (u32, u32) = (5, 6);
            let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(a)).unwrap()),
                b: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(b)).unwrap()),
                num_variables: 10,
                num_constraints: 1 << 6,
            };

            let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
            (pk, vk)
        }

        pub fn generate_proof() -> (Proof, PublicInputs) {
            type E = Bn254;

            let (a, b): (u32, u32) = (5, 6);

            //let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(a)).unwrap()),
                b: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(b)).unwrap()),
                num_variables: 10,
                num_constraints: 1 << 6,
            };

            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

            let (pk, _) = compile_circuit();
            let pub_c = circuit.a.unwrap() * circuit.b.unwrap();

            let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
            let public_inputs = [pub_c];

            (proof, public_inputs)
        }
    }

    #[derive(Clone, Debug, borsh::BorshDeserialize, borsh::BorshSerialize)]
    pub struct BitVMCache {
        pubkeys: PublicKeys,
        signatures: Signatures,
        disprove_scripts: Vec<Vec<u8>>,
    }

    impl BitVMCache {
        pub fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
            let serialized = borsh::to_vec(&self).unwrap();
            std::fs::write(path, serialized).map_err(|e| {
                println!("Failed to save BitVM cache: {}", e);
                e
            })
        }

        pub fn load_from_file(path: &str) -> Result<Self, std::io::Error> {
            let bytes = std::fs::read(path).map_err(|e| {
                println!("Failed to read BitVM cache: {}", e);
                e
            })?;

            let x = borsh::BorshDeserialize::try_from_slice(&bytes).unwrap();
            Ok(x)
        }
    }

    const MOCK_SECRET: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";

    fn sign_assertions(assn: Assertions) -> Signatures {
        let (ps, fs, hs) = (assn.0, assn.1, assn.2);
        let secret = MOCK_SECRET;
        
        let mut psig: Vec<wots256::Signature> = vec![];
        for i in 0..NUM_PUBS {
            let psi = wots256::get_signature(&format!("{secret}{:04x}", i), &ps[i]);
            psig.push(psi);
        }
        let psig: [wots256::Signature; NUM_PUBS] = psig.try_into().unwrap();

        let mut fsig: Vec<wots256::Signature> = vec![];
        for i in 0..fs.len() {
            let fsi = wots256::get_signature(&format!("{secret}{:04x}", NUM_PUBS + i), &fs[i]);
            fsig.push(fsi);
        }
        let fsig: [wots256::Signature; N_VERIFIER_FQS] = fsig.try_into().unwrap();

        let mut hsig: Vec<wots160::Signature> = vec![];
        for i in 0..hs.len() {
            let hsi =
                wots160::get_signature(&format!("{secret}{:04x}", NUM_PUBS + fs.len() + i), &hs[i]);
            hsig.push(hsi);
        }
        let hsig: [wots160::Signature; N_VERIFIER_HASHES] = hsig.try_into().unwrap();

        
        (psig, fsig, hsig)
    }

    // Step 1: Anyone can Generate Operation (mul & hash) part of tapscript: same for all vks
    #[test]
    fn test_fn_compile() {
        let (_, mock_vk) = mock::compile_circuit();
        
        assert_eq!(mock_vk.gamma_abc_g1.len(), NUM_PUBS + 1); 

        let ops_scripts = compile_verifier(mock_vk);
        let mut script_cache = HashMap::new();

        for i in 0..ops_scripts.len() {
            script_cache.insert(i as u32, vec![ops_scripts[i].clone()]);
        }

        write_scripts_to_separate_files(script_cache, "tapnode");
    }

    pub fn mock_pubkeys(mock_secret: &str) -> PublicKeys {

        let mut pubins = vec![];
        for i in 0..NUM_PUBS {
            pubins.push(wots256::generate_public_key(&format!("{mock_secret}{:04x}", i)));
        }
        let mut fq_arr = vec![];
        for i in 0..N_VERIFIER_FQS {
            let p256 = wots256::generate_public_key(&format!("{mock_secret}{:04x}", NUM_PUBS + i));
            fq_arr.push(p256);
        }
        let mut h_arr = vec![];
        for i in 0..N_VERIFIER_HASHES {
            let p160 = wots160::generate_public_key(&format!("{mock_secret}{:04x}", N_VERIFIER_FQS + NUM_PUBS + i));
            h_arr.push(p160);
        }
        let wotspubkey: PublicKeys = (
            pubins.try_into().unwrap(),
            fq_arr.try_into().unwrap(),
            h_arr.try_into().unwrap(),
        );
        wotspubkey
    }

    // Step 2: Operator Generates keypairs and broadcasts pubkeys for a Bitvm setup; 
    // Anyone can create Bitcomm part of tapscript; yields complete tapscript
    #[test]
    fn test_fn_generate_tapscripts() {
        println!("start");

        let (_, mock_vk) = mock::compile_circuit();
        println!("compiled circuit");

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); 
        let mock_pubs = mock_pubkeys(MOCK_SECRET);
        let mut op_scripts = vec![];

        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");

        for i in 0..N_TAPLEAVES {
            println!("taps_len {}", op_scripts[i].len());
        }

        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap(); //compile_verifier(mock_vk);

        let tapscripts = generate_disprove_scripts(mock_pubs, &ops_scripts);
        println!(
            "tapscript.lens: {:?}",
            tapscripts.clone().map(|script| script.len())
        );
 

    }

    // Step 3: Operator Generates Assertions, Signs it and submit on chain
    #[test]
    fn test_fn_generate_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);
        let proof_asserts = generate_proof_assertions(mock_vk, proof, public_inputs);
        println!("signed_asserts {:?}", proof_asserts);
   
        std::fs::create_dir_all("bridge_data/chunker_data")
        .expect("Failed to create directory structure");
    
        write_asserts_to_file(proof_asserts, "bridge_data/chunker_data/assert.json");
        let _signed_asserts = sign_assertions(proof_asserts);
    }

    // Step 3: Operator Generates Assertions, Signs it and submit on chain
    #[test]
    fn test_fn_generate_signatures() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);
        let secrets = (0..NUM_PUBS + NUM_U256 + NUM_U160)
            .map(|idx| format!("{MOCK_SECRET}{:04x}", idx))
            .collect::<Vec<String>>();
        let _ = generate_proof_signature(mock_vk, proof, public_inputs, secrets);
        //println!("signed_asserts {:?}", proof_asserts);
    
        // std::fs::create_dir_all("bridge_data/chunker_data")
        // .expect("Failed to create directory structure");
    
        // write_asserts_to_file(proof_asserts, "bridge_data/chunker_data/assert.json");
        // let _signed_asserts = sign_assertions(proof_asserts);
    }

    #[test]
    fn test_fn_validate_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);

        let mut op_scripts = vec![];
        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");
        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap();

       let mock_pubks = mock_pubkeys(MOCK_SECRET);
       let verifier_scripts = generate_disprove_scripts(mock_pubks, &ops_scripts);

    //     // let proof_asserts = generate_proof_assertions(mock_vk.clone(), proof, public_inputs);
        let proof_asserts = read_asserts_from_file("bridge_data/chunker_data/assert.json");
        let signed_asserts = sign_assertions(proof_asserts);
    //     let mock_pubks = mock_pubkeys(MOCK_SECRET);

        println!("verify_signed_assertions");
        let fault = verify_signed_assertions(mock_vk, mock_pubks, signed_asserts, &verifier_scripts);
        assert!(fault.is_none());
    }

    

    fn corrupt(proof_asserts: &mut Assertions, random: Option<usize>) {
        let mut rng = rand::thread_rng();

        // Generate a random number between 1 and 100 (inclusive)
        let mut index = rng.gen_range(0..N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES);
        if random.is_some() {
            index = random.unwrap();
        }
        // WARN: KNOWN ISSUE: scramble: [u8; 32] = [255; 32]; fails because tapscripts do not check that the asserted value is a field element 
        // A 256 bit number is not a field element. For now, this prototype only supports corruption that is still a field element
        let mut scramble: [u8; 32] = [0u8; 32];
        scramble[16] = 37;
        let mut scramble2: [u8; 20] = [0u8; 20];
        scramble2[10] = 37;
        println!("corrupted assertion at index {}", index);
        if index < N_VERIFIER_PUBLIC_INPUTS {
            if index == 0 {
                if proof_asserts.0[0] == scramble {
                    scramble[16] += 1;
                }
                proof_asserts.0[0] = scramble;
            } 
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS {
            let index = index - N_VERIFIER_PUBLIC_INPUTS;
            if proof_asserts.1[index] == scramble {
                scramble[16] += 1;
            }
            proof_asserts.1[index] = scramble;
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES {
            let index = index - N_VERIFIER_PUBLIC_INPUTS - N_VERIFIER_FQS;
            if proof_asserts.2[index] == scramble2 {
                scramble2[10] += 1;
            }
            proof_asserts.2[index] = scramble2;
        }
    }

    // Step 4: Challenger finds fault given signatures
    #[test]
    fn test_fn_disprove_invalid_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert_eq!(mock_vk.gamma_abc_g1.len(), NUM_PUBS+1); 

        let mut op_scripts = vec![];
        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");
        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap();

        let mock_pubks = mock_pubkeys(MOCK_SECRET);
        let verifier_scripts = generate_disprove_scripts(mock_pubks, &ops_scripts);


        let total = N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES;
        for i in 0..1{ //total {
            println!("ITERATION {:?}", i);
            let mut proof_asserts = read_asserts_from_file("bridge_data/chunker_data/assert.json");
            corrupt(&mut proof_asserts, Some(i));
            let signed_asserts = sign_assertions(proof_asserts);
    
            let fault = verify_signed_assertions(mock_vk.clone(), mock_pubks, signed_asserts, &verifier_scripts);
            assert!(fault.is_some());
            if fault.is_some() {
                let (index, hint_script) = fault.unwrap();
                println!("taproot index {:?}", index);
                let scr = script!(
                    {hint_script.clone()}
                    {verifier_scripts[index].clone()}
                );
                let res = execute_script(scr);
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
                let mut disprove_map: HashMap<u32, Vec<Script>> = HashMap::new();
                let disprove_f = &format!("bridge_data/chunker_data/disprove_{index}.json");
                disprove_map.insert(index as u32, vec![hint_script]);
                write_scripts_to_file(disprove_map, disprove_f);
                assert!(res.success);
            }
        }
    }

    fn write_asserts_to_file(proof_asserts: Assertions, filename: &str) {
        //let proof_asserts = mock_asserts();
        let mut proof_vec: Vec<Vec<u8>> = vec![];
        for k in proof_asserts.0 {
            proof_vec.push(k.to_vec());
        }
        for k in proof_asserts.1 {
            proof_vec.push(k.to_vec());
        }
        for k in proof_asserts.2 {
            proof_vec.push(k.to_vec());
        }
        let mut obj: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        obj.insert(0, proof_vec);

        write_map_to_file(&obj, filename).unwrap();
    }

    fn read_asserts_from_file(filename: &str) -> Assertions {
        let res = read_map_from_file(filename).unwrap();
        let proof_vec = res.get(&0).unwrap();
        
        let mut assert1 = vec![];
        for i in 0..N_VERIFIER_PUBLIC_INPUTS {
            let v:[u8;32] = proof_vec[i].clone().try_into().unwrap();
            assert1.push(v);
        }
        let assert1: [[u8; 32]; N_VERIFIER_PUBLIC_INPUTS] = assert1.try_into().unwrap();

        let mut assert2 = vec![];
        for i in 0..N_VERIFIER_FQS {
            let v:[u8;32] = proof_vec[N_VERIFIER_PUBLIC_INPUTS + i].clone().try_into().unwrap();
            assert2.push(v);
        }
        let assert2: [[u8; 32]; N_VERIFIER_FQS] = assert2.try_into().unwrap();

        let mut assert3 = vec![];
        for i in 0..N_VERIFIER_HASHES {
            let v:[u8;20] = proof_vec[N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + i].clone().try_into().unwrap();
            assert3.push(v);
        }
        let assert3: [[u8; 20]; N_VERIFIER_HASHES] = assert3.try_into().unwrap();
        (assert1, assert2, assert3)
    }




    #[test]
    fn full_e2e_execution() {
        println!("Use mock groth16 proof");
        let vk_bytes = [
            115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162,
            65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198,
            247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120,
            207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25,
            185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123,
            7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100,
            17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146,
            45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51,
            95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228,
            89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218,
            111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29,
            184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2,
            218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196,
            156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134,
            158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226,
            127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217,
            116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183,
            164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172,
            108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70,
            66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43,
            145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41,
            199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188,
            59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67,
            204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2,
            0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158,
            0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80,
            204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58,
            10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207,
            78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193,
            21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163,
            80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161,
        ]
        .to_vec();
        let proof_bytes: Vec<u8> = [
            162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90,
            122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218,
            218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122,
            206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94,
            59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226,
            132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29,
            120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183,
            5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63,
            133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157,
            82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214,
            220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255,
            188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2,
            133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131,
            92, 103, 103, 176, 212, 223, 177, 242, 94, 14,
        ]
        .to_vec();
        let scalar = [
            232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88,
            129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
        ]
        .to_vec();

        let proof: ark_groth16::Proof<Bn254> =
            ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> =
            ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        println!("STEP 1 GENERATE TAPSCRIPTS");
        let secret_key: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
        let secrets = (0..NUM_PUBS + NUM_U256 + NUM_U160)
            .map(|idx| format!("{secret_key}{:04x}", idx))
            .collect::<Vec<String>>();
        let bitvm_cache_result = BitVMCache::load_from_file("bitvm_cache.borsh");
        let bitvm_cache = match bitvm_cache_result {
            Ok(bitvm_cache) => bitvm_cache,
            Err(_) => {
                let pubkeys = get_pubkeys(secrets.clone());
                let proof_sigs = generate_signatures(proof, scalars.to_vec(), &vk, secrets.clone());

                // let proof_sigs = bitvm_cache.signatures;
                // let pubkeys = bitvm_cache.pubkeys;

                let partial_scripts = api_generate_partial_script(&vk);
                // let mut proof_asserts = get_assertions_from_signature(proof_sigs);

                let disprove_scripts = api_generate_full_tapscripts(pubkeys, &partial_scripts);

                let bitvm_cache = BitVMCache {
                    pubkeys: pubkeys.clone(),
                    signatures: proof_sigs.clone(),
                    disprove_scripts: disprove_scripts
                        .iter()
                        .map(|x| x.clone().compile().as_bytes().to_vec())
                        .collect(),
                };

                bitvm_cache.save_to_file("bitvm_cache.borsh").unwrap();
                bitvm_cache
            }
        };

        let x = bitvm_cache.signatures;
        println!("x: {:?}", x);

        let disprove_scripts: Vec<Script> = bitvm_cache.disprove_scripts
            .iter()
            .map(|x| {
                let mut scr = script!();
                scr = scr.push_script(ScriptBuf::from_bytes(x.to_vec()));
                scr
            })
            .collect();

        println!("Disprove scripts len: {}", disprove_scripts.len());
        println!("Num taps: {}", NUM_TAPS);
        // println!("Witness length: {}", witnesses.len());
        let y = validate_assertions(
            &vk,
            x,
            bitvm_cache.pubkeys,
            &disprove_scripts.try_into().unwrap(),
        );
        println!("y: {:?}", y);
    }
}
