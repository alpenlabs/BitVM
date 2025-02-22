use std::fs;

use crate::chunk::api_compiletime_utils::{
    append_bitcom_locking_script_to_partial_scripts, generate_partial_script,
    partial_scripts_from_segments,
};
use crate::chunk::api_runtime_utils::{
    execute_script_from_assertion, execute_script_from_signature, get_assertion_from_segments, get_assertions_from_signature, get_pubkeys, get_segments_from_assertion, get_segments_from_groth16_proof, get_signature_from_assertion
};

use crate::signatures::signing_winternitz::winternitz_message_checksig_verify;
use crate::signatures::wots_api::{wots160, wots256};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::{Bn, BnConfig};
use bitcoin::key::Keypair;
use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    witness, Address, Amount, Network, OutPoint, ScriptBuf, TapLeafHash, TapNodeHash, TapSighash,
    TapTweakHash, Transaction, XOnlyPublicKey,
};
use bitcoin_script::builder;
use secp256k1::{schnorr, SECP256K1};
use serde::{Deserialize, Serialize};
use type_conversion_utils::utils_raw_witnesses_from_signatures;


pub const ATE_LOOP_COUNT: &[i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 20;
pub const NUM_U160: usize = 380;
const VALIDATING_TAPS: usize = 1;
const HASHING_TAPS: usize = NUM_U160;
pub const NUM_TAPS: usize = HASHING_TAPS + VALIDATING_TAPS;

pub type PublicInputs = [ark_bn254::Fr; NUM_PUBS];

pub type PublicKeys = (
    [wots256::PublicKey; NUM_PUBS],
    [wots256::PublicKey; NUM_U256],
    [wots160::PublicKey; NUM_U160],
);

pub type Signatures = (
    [wots256::Signature; NUM_PUBS],
    [wots256::Signature; NUM_U256],
    [wots160::Signature; NUM_U160],
);

pub type Assertions = (
    [[u8; 32]; NUM_PUBS],
    [[u8; 32]; NUM_U256],
    [[u8; 20]; NUM_U160],
);

// Step 1
// The function takes public parameters (here verifying key) and generates partial script
// partial script is essentially disprove script minus the bitcommitment locking script
pub fn api_generate_partial_script(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    generate_partial_script(vk)
}

// Step 2
// given public keys and the partial scripts generated in api_generate_partial_script()
// it generates the complete disprove scripts
pub fn api_generate_full_tapscripts(
    inpubkeys: PublicKeys,
    ops_scripts_per_link: &[Script],
) -> Vec<Script> {
    println!("api_generate_full_tapscripts; append_bitcom_locking_script_to_partial_scripts");
    let taps_per_link =
        append_bitcom_locking_script_to_partial_scripts(inpubkeys, ops_scripts_per_link.to_vec());
    assert_eq!(ops_scripts_per_link.len(), taps_per_link.len());
    taps_per_link
}

// Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_assertions(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Assertions {
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    let assts = get_assertion_from_segments(&segments);
    let exec_res = execute_script_from_assertion(&segments, assts);
    if exec_res.is_some() {
        let fault = exec_res.unwrap();
        println!(
            "execute_script_from_assertion return fault at script index {}",
            fault.0
        );
        panic!();
    } else {
        println!("generate_assertions; validated assertion by executing all scripts");
    }
    assts
}

// Alternate Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_signatures(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    secrets: Vec<String>,
) -> Signatures {
    println!("generate_signatures; get_segments_from_groth16_proof");
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    println!("generate_signatures; get_assertion_from_segments");
    let assn = get_assertion_from_segments(&segments);
    println!("generate_signatures; get_signature_from_assertion");
    let sigs = get_signature_from_assertion(&assn, secrets.clone());
    println!("generate_signatures; get_pubkeys");
    let pubkeys = get_pubkeys(secrets);

    println!("generate_signatures; partial_scripts_from_segments");
    let partial_scripts: Vec<Script> = partial_scripts_from_segments(&segments)
        .into_iter()
        .collect();
    let partial_scripts: [Script; NUM_TAPS] = partial_scripts.try_into().unwrap();
    println!("generate_signatures; append_bitcom_locking_script_to_partial_scripts");
    let disprove_scripts =
        append_bitcom_locking_script_to_partial_scripts(pubkeys, partial_scripts.to_vec());
    let disprove_scripts: [Script; NUM_TAPS] = disprove_scripts.try_into().unwrap();

    println!("generate_signatures; execute_script_from_signature");
    let exec_res = execute_script_from_signature(&segments, sigs, &disprove_scripts);
    if exec_res.is_some() {
        let fault = exec_res.unwrap();
        println!(
            "execute_script_from_assertion return fault at script index {}",
            fault.0
        );
        panic!();
    } else {
        println!("generate_signatures; validated signatures by executing all scripts");
    }
    sigs
}

// Step 4
// validate signed assertions
// returns index of disprove script generated in Step 2
// and the witness required to execute this Disprove Script incase of failure
pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    _inpubkeys: PublicKeys,
    disprove_scripts: &[Script; NUM_TAPS],
) -> Option<(usize, Script)> {
    println!("validate_assertions; get_assertions_from_signature");
    let asserts = get_assertions_from_signature(signed_asserts);
    println!("validate_assertions; get_segments_from_assertion");
    let (success, segments) = get_segments_from_assertion(asserts, vk.clone());
    if !success {
        println!("invalid tapscript at segment {}", segments.len());
    }
    println!("validate_assertions; execute_script_from_signature");
    let exec_result = execute_script_from_signature(&segments, signed_asserts, disprove_scripts);
    assert_eq!(
        success,
        exec_result.is_none(),
        "ensure script execution matches rust execution match"
    );
    exec_result
}

pub fn api_get_signature_from_assertion(assn: &Assertions, secrets: Vec<String>) -> Signatures {
    get_signature_from_assertion(assn, secrets)
}

pub fn api_get_assertions_from_signature(signed_asserts: Signatures) -> Assertions {
    get_assertions_from_signature(signed_asserts)
}

pub mod type_conversion_utils {
    use crate::chunk::api::Signatures;
    use crate::{
        chunk::api::{NUM_PUBS, NUM_U160, NUM_U256},
        execute_script,
        signatures::{
            signing_winternitz::WinternitzPublicKey,
            wots_api::{wots160, wots256},
        },
        treepp::Script,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    use super::PublicKeys;

    pub type RawWitness = Vec<Vec<u8>>;

    #[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
    pub struct RawProof {
        pub proof: ark_groth16::Proof<ark_bn254::Bn254>,
        pub public: Vec<ark_bn254::Fr>,
        pub vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    }

    impl Default for RawProof {
        fn default() -> Self {
            // note this proof shouldn't be used in onchain environment
            let serialize_data = "687a30a694bb4fb69f2286196ad0d811e702488557c92a923c19499e9c1b3f0105f749dae2cd41b2d9d3998421aa8e86965b1911add198435d50a08892c7cd01a47c01cbf65ccc3b4fc6695671734c3b631a374fbf616e58bcb0a3bd59a9030d7d17433d53adae2232f9ac3caa5c67053d7a728714c81272a8a51507d5c43906010000000000000043a510e31de87bdcda497dfb3ea3e8db414a10e7d4802fc5dddd26e18d2b3a279c3815c2ec66950b63e60c86dc9a2a658e0224d55ea45efe1f633be052dc7d867aff76a9e983210318f1b808aacbbba1dc04b6ac4e6845fa0cc887aeacaf5a068ab9aeaf8142740612ff2f3377ce7bfa7433936aaa23e3f3749691afaa06301fd03f043c097556e7efdf6862007edf3eb868c736d917896c014c54754f65182ae0c198157f92e667b6572ba60e6a52d58cb70dbeb3791206e928ea5e65c6199d25780cedb51796a8a43e40e192d1b23d0cfaf2ddd03e4ade7c327dbc427999244bf4b47b560cf65d672c86ef448eb5061870d3f617bd3658ad6917d0d32d9296020000000000000008f167c3f26c93dbfb91f3077b66bc0092473a15ef21c30f43d3aa96776f352a33622830e9cfcb48bdf8d3145aa0cf364bd19bbabfb3c73e44f56794ee65dc8a";
            let bytes = hex::decode(serialize_data).unwrap();
            RawProof::deserialize_compressed(&*bytes).unwrap()
        }
    }

    pub fn utils_signatures_from_raw_witnesses(raw_wits: &Vec<RawWitness>) -> Signatures {
        fn raw_witness_to_sig(sigs: RawWitness) -> Vec<([u8; 20], u8)> {
            let mut sigs_vec: Vec<([u8; 20], u8)> = Vec::new();
            for i in (0..sigs.len()).step_by(2) {
                let preimage: [u8; 20] = if sigs[i].len() == 0 {
                    [0; 20]
                } else {
                    sigs[i].clone().try_into().unwrap()
                };
                let digit_arr: [u8; 1] = if sigs[i + 1].len() == 0 {
                    [0]
                } else {
                    sigs[i + 1].clone().try_into().unwrap()
                };
                sigs_vec.push((preimage, digit_arr[0]));
            }
            sigs_vec
        }

        assert_eq!(raw_wits.len(), NUM_PUBS + NUM_U256 + NUM_U160);
        let mut asigs = vec![];
        for i in 0..NUM_PUBS {
            let a: wots256::Signature = raw_witness_to_sig(raw_wits[i].clone()).try_into().unwrap();
            asigs.push(a);
        }
        let mut bsigs = vec![];
        for i in 0..NUM_U256 {
            let a: wots256::Signature = raw_witness_to_sig(raw_wits[i + NUM_PUBS].clone())
                .try_into()
                .unwrap();
            bsigs.push(a);
        }
        let mut csigs = vec![];
        for i in 0..NUM_U160 {
            let a: wots160::Signature =
                raw_witness_to_sig(raw_wits[i + NUM_PUBS + NUM_U256].clone())
                    .try_into()
                    .unwrap();
            csigs.push(a);
        }
        let asigs = asigs.try_into().unwrap();
        let bsigs = bsigs.try_into().unwrap();
        let csigs = csigs.try_into().unwrap();
        (asigs, bsigs, csigs)
    }

    pub fn utils_raw_witnesses_from_signatures(signatures: &Signatures) -> Vec<RawWitness> {
        // Helper: Convert a signature (which can be converted into Vec<([u8;20], u8)>)
        // back into its RawWitness representation.
        fn sig_to_raw_witness<T>(signature: T) -> RawWitness
        where
            T: Into<Vec<([u8; 20], u8)>>,
        {
            let sig_pairs: Vec<([u8; 20], u8)> = signature.into();
            let mut raw = Vec::with_capacity(sig_pairs.len() * 2);
            for (preimage, digit) in sig_pairs {
                // In the original conversion an empty vector was used to represent [0;20].
                // So we "invert" that: if preimage is all zeroes, output an empty vector.
                raw.push(if preimage == [0; 20] {
                    vec![]
                } else {
                    preimage.to_vec()
                });
                // Similarly, if the digit is 0 then output an empty vector.
                raw.push(if digit == 0 { vec![] } else { vec![digit] });
            }
            raw
        }

        // Assume Signatures is a tuple: (asigs, bsigs, csigs) where:
        // - asigs: Vec<wots256::Signature> of length NUM_PUBS
        // - bsigs: Vec<wots256::Signature> of length NUM_U256
        // - csigs: Vec<wots160::Signature> of length NUM_U160 (or NUM_PUBS if they are equal)
        let (asigs, bsigs, csigs) = signatures;
        let mut raw_wits = Vec::with_capacity(asigs.len() + bsigs.len() + csigs.len());

        for sig in asigs {
            raw_wits.push(sig_to_raw_witness(sig));
        }
        for sig in bsigs {
            raw_wits.push(sig_to_raw_witness(sig));
        }
        for sig in csigs {
            raw_wits.push(sig_to_raw_witness(sig));
        }

        raw_wits
    }

    pub fn script_to_witness(scr: Script) -> Vec<Vec<u8>> {
        let res = execute_script(scr);
        let wit = res.final_stack.0.iter_str().fold(vec![], |mut vector, x| {
            vector.push(x);
            vector
        });
        wit
    }

    pub fn utils_typed_pubkey_from_raw(
        commits_public_keys: Vec<&WinternitzPublicKey>,
    ) -> PublicKeys {
        let mut apubs = vec![];
        let mut bpubs = vec![];
        let mut cpubs = vec![];
        for idx in 0..commits_public_keys.len() {
            let f = commits_public_keys[idx];
            if idx < NUM_PUBS {
                let p: wots256::PublicKey = f.public_key.clone().try_into().unwrap();
                apubs.push(p);
            } else if idx < NUM_PUBS + NUM_U256 {
                let p: wots256::PublicKey = f.public_key.clone().try_into().unwrap();
                bpubs.push(p);
            } else if idx < NUM_PUBS + NUM_U256 + NUM_U160 {
                let p: wots160::PublicKey = f.public_key.clone().try_into().unwrap();
                cpubs.push(p);
            }
        }

        let pks: PublicKeys = (
            apubs.try_into().unwrap(),
            bpubs.try_into().unwrap(),
            cpubs.try_into().unwrap(),
        );
        pks
    }
}

pub fn get_operator_taproot_address(
    operator_xonly_pubkey: XOnlyPublicKey,
    network: Network,
) -> (Address, TaprootSpendInfo) {
    let builder = TaprootBuilder::new()
        .finalize(SECP256K1, operator_xonly_pubkey)
        .unwrap();

    let address = Address::p2tr(SECP256K1, operator_xonly_pubkey, None, network);
    (address, builder)
}

pub fn get_aseert_address_from_script(
    script: Script,
    operator_xonly_pubkey: XOnlyPublicKey,
    network: Network,
) -> (Address, TaprootSpendInfo, ScriptBuf) {
    let script = script.compile();
    let builder = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(SECP256K1, operator_xonly_pubkey)
        .unwrap();

    let address = Address::p2tr(
        SECP256K1,
        operator_xonly_pubkey,
        builder.merkle_root(),
        network,
    );

    (address, builder, script)
}

pub fn get_disprove_address_from_scripts(
    scripts: Vec<ScriptBuf>,
    operator_xonly_pubkey: XOnlyPublicKey,
    network: Network,
) -> Address {
    let num_scripts = scripts.len();
    let builder = TaprootBuilder::new();
    let deepest_layer_depth: u8 = ((num_scripts - 1).ilog2() + 1) as u8;

    let num_empty_nodes_in_final_depth = 2_usize.pow(deepest_layer_depth.into()) - num_scripts;
    let num_nodes_in_final_depth = num_scripts - num_empty_nodes_in_final_depth;

    let builder = (0..num_scripts).fold(builder, |acc, i| {
        let is_node_in_last_minus_one_depth = (i >= num_nodes_in_final_depth) as u8;

        acc.add_leaf(
            deepest_layer_depth - is_node_in_last_minus_one_depth,
            scripts[i].clone(),
        )
        .expect("algorithm tested to be correct")
    });

    let tree_info = builder
        .finalize(SECP256K1, operator_xonly_pubkey)
        .expect("algorithm tested to be correct");

    let address = Address::p2tr(
        SECP256K1,
        operator_xonly_pubkey,
        tree_info.merkle_root(),
        network,
    );

    address
}

pub fn get_assert_addresses(
    pubkeys: PublicKeys,
    operator_xonly_pubkey: XOnlyPublicKey,
    network: Network,
) -> Vec<(Address, TaprootSpendInfo, ScriptBuf)> {
    let mut assert_addresses = vec![];
    for i in 0..NUM_PUBS {
        let script = script! {
            {operator_xonly_pubkey}
            OP_CHECKSIGVERIFY
            {wots256::checksig_verify(pubkeys.0[i])}
            for _ in 0..32*2 {
                OP_DROP
            }
            OP_TRUE
        };

        assert_addresses.push(get_aseert_address_from_script(
            script,
            operator_xonly_pubkey,
            network,
        ));
    }

    let step = 5;
    for i in (0..NUM_U256).step_by(step) {
        let script = script! {
            {operator_xonly_pubkey}
            OP_CHECKSIGVERIFY
            for j in i..i+step {
                {wots256::checksig_verify(pubkeys.1[j])}
                for _ in 0..32*2 {
                    OP_DROP
                }
            }
            OP_TRUE
        };
        assert_addresses.push(get_aseert_address_from_script(
            script,
            operator_xonly_pubkey,
            network,
        ));
    }

    let step = 10;
    for i in (0..NUM_U160).step_by(step) {
        let script = script! {
            {operator_xonly_pubkey}
            OP_CHECKSIGVERIFY
            for j in i..i+step {
                {wots160::checksig_verify(pubkeys.2[j])}
                for _ in 0..20*2 {
                    OP_DROP
                }
            }
            OP_TRUE
        };
        assert_addresses.push(get_aseert_address_from_script(
            script,
            operator_xonly_pubkey,
            network,
        ));
    }
    assert_addresses
}

pub fn sign_with_tweak(
    keypair: Keypair,
    sighash: TapSighash,
    merkle_root: Option<TapNodeHash>,
) -> schnorr::Signature {
    use bitcoin::hashes::Hash;
    SECP256K1.sign_schnorr(
        &bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array()),
        &keypair
            .add_xonly_tweak(
                &SECP256K1,
                &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, merkle_root)
                    .to_scalar(),
            )
            .unwrap(),
    )
}

pub fn schnorr_sign(keypair: Keypair, sighash: TapSighash) -> schnorr::Signature {
    use bitcoin::hashes::Hash;
    SECP256K1.sign_schnorr(
        &bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array()),
        &keypair,
    )
}

pub fn get_mini_assert_tx(
    index: usize,
    assert_begin_txid: bitcoin::Txid,
    operator_taproot_address: &Address,
    operator_keypair: Keypair,
    assert_addresses: &[(Address, TaprootSpendInfo, ScriptBuf)],
    raw_witness: &[Vec<Vec<u8>>],
) -> Transaction {
    let mut mini_assert_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint {
                txid: assert_begin_txid,
                vout: index as u32,
            },
            script_sig: ScriptBuf::default(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(330),
            script_pubkey: operator_taproot_address.script_pubkey(),
        }],
    };

    let prevouts = vec![bitcoin::TxOut {
        value: Amount::from_sat(2_300_000),
        script_pubkey: assert_addresses[index].0.script_pubkey(),
    }];

    let mut sighash_cache = bitcoin::sighash::SighashCache::new(mini_assert_tx.clone());

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            TapLeafHash::from_script(
                assert_addresses[index].2.as_script(),
                LeafVersion::TapScript,
            ),
            bitcoin::TapSighashType::Default,
        )
        .unwrap();

    let sig = schnorr_sign(operator_keypair, sighash);

    let spend_control_block = assert_addresses[index]
        .1
        .control_block(&(assert_addresses[index].2.clone(), LeafVersion::TapScript))
        .unwrap();

    let mut witness = bitcoin::Witness::new();
    raw_witness
        .iter()
        .rev()
        .for_each(|raw_witnes| raw_witnes.iter().for_each(|x| witness.push(x.clone())));
    witness.push(sig.serialize());
    witness.push(assert_addresses[index].2.as_script());
    witness.push(spend_control_block.serialize());

    mini_assert_tx.input[0].witness = witness;

    mini_assert_tx
}

pub fn get_raw_signed_transactions(
    funding_outpoint: OutPoint,
    pubkeys: PublicKeys,
    operator_xonly_pubkey: XOnlyPublicKey,
    operator_keypair: Keypair,
    proof_sigs: Signatures,
    disprove_scripts: &[ScriptBuf],
    network: Network,
) -> Vec<Transaction> {
    use bitcoin::hashes::Hash;

    let (operator_taproot_address, operator_taproot_builder) =
        get_operator_taproot_address(operator_xonly_pubkey, network);
    let assert_addresses = get_assert_addresses(pubkeys, operator_xonly_pubkey, network);

    let mut assert_begin_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        }],
        output: assert_addresses
            .iter()
            .map(|(address, _, _)| bitcoin::TxOut {
                value: Amount::from_sat(2_300_000),
                script_pubkey: address.script_pubkey(),
            })
            .collect(),
    };
    let prevouts = vec![bitcoin::TxOut {
        value: Amount::from_sat(100_000_000),
        script_pubkey: operator_taproot_address.script_pubkey(),
    }];

    let mut sighash_cache = bitcoin::sighash::SighashCache::new(assert_begin_tx.clone());
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let sig = sign_with_tweak(operator_keypair, sighash, None);

    let mut witness = bitcoin::Witness::new();
    witness.push(sig.serialize());

    assert_begin_tx.input[0].witness = witness;

    let assert_begin_txid = assert_begin_tx.compute_txid();

    let raw_witness = utils_raw_witnesses_from_signatures(&proof_sigs);

    let mini_assert_tx = get_mini_assert_tx(
        0,
        assert_begin_txid,
        &operator_taproot_address,
        operator_keypair,
        &assert_addresses,
        &raw_witness[0..1],
    );

    let mut all_txs = vec![assert_begin_tx, mini_assert_tx];

    let step = 5;
    for i in (0..NUM_U256).step_by(step) {
        let mini_assert_tx = get_mini_assert_tx(
            i / step + 1,
            assert_begin_txid,
            &operator_taproot_address,
            operator_keypair,
            &assert_addresses,
            &raw_witness[i + NUM_PUBS..i + step + NUM_PUBS],
        );
        all_txs.push(mini_assert_tx);
    }

    let step = 10;
    for i in (0..NUM_U160).step_by(step) {
        let mini_assert_tx = get_mini_assert_tx(
            i / step + 5,
            assert_begin_txid,
            &operator_taproot_address,
            operator_keypair,
            &assert_addresses,
            &raw_witness[i + NUM_PUBS + NUM_U256..i + step + NUM_PUBS + NUM_U256],
        );
        all_txs.push(mini_assert_tx);
    }

    let final_tx_inputs = all_txs[1..]
        .iter()
        .map(|tx| OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        })
        .collect::<Vec<_>>();

    let disprove_address = get_disprove_address_from_scripts(
        disprove_scripts.to_vec(),
        operator_xonly_pubkey,
        network,
    );

    let mut final_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: final_tx_inputs
            .iter()
            .map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::default(),
                sequence: bitcoin::Sequence::ZERO,
                witness: bitcoin::Witness::new(),
            })
            .collect(),
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(330),
            script_pubkey: disprove_address.script_pubkey(),
        }],
    };

    let prevouts = vec![
        bitcoin::TxOut {
            value: Amount::from_sat(330),
            script_pubkey: operator_taproot_address.script_pubkey(),
        };
        all_txs.len() - 1
    ];

    let mut sighash_cache = bitcoin::sighash::SighashCache::new(final_tx.clone());
    for i in 0..final_tx.input.len() {
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                i,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();

        let sig = sign_with_tweak(operator_keypair, sighash, None);

        let mut witness = bitcoin::Witness::new();
        witness.push(sig.serialize());

        final_tx.input[i].witness = witness;
    }

    all_txs.push(final_tx);

    all_txs
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
        fs::write(path, serialized).map_err(|e| {
            println!("Failed to save BitVM cache: {}", e);
            e
        })
    }

    pub fn load_from_file(path: &str) -> Result<Self, std::io::Error> {
        let bytes = fs::read(path).map_err(|e| {
            println!("Failed to read BitVM cache: {}", e);
            e
        })?;

        let x = borsh::BorshDeserialize::try_from_slice(&bytes).unwrap();
        Ok(x)
    }
}

#[cfg(test)]
mod test {
    use crate::chunk::api::type_conversion_utils::{
        utils_raw_witnesses_from_signatures, utils_signatures_from_raw_witnesses,
    };
    use crate::chunk::api::Signatures;
    // use crate::chunk::api::{
    //     get_operator_taproot_address, get_raw_signed_transactions, BitVMCache, Signatures,
    // };
    use crate::chunk::api_runtime_utils::{get_pubkeys, get_signature_from_assertion};
    use crate::groth16::constants::S;
    use crate::groth16::g16::{get_operator_taproot_address, BitVMCache};
    use crate::treepp::Script;
    use ark_bn254::Bn254;
    use ark_serialize::CanonicalDeserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{ScriptBuf, Txid};
    use bitcoin_script::script;
    use bitcoincore_rpc::RpcApi;
    // use bitcoincore_rpc::RpcApi;
    use rand::Rng;

    use crate::{
        chunk::{
            api::{
                api_generate_full_tapscripts, api_generate_partial_script, generate_signatures,
                validate_assertions, Assertions,
            },
            api::{NUM_PUBS, NUM_TAPS, NUM_U160, NUM_U256},
            api_runtime_utils::get_assertions_from_signature,
        },
        execute_script,
    };

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

        // generate assert addresses
        use std::str::FromStr;
        let network = bitcoin::network::Network::Testnet4;

        let operator_secret_key =
            "d0d5603a31ddbef5ecc1d75b45012704e57121b7eba0c1d7e104863fbf178838";
        let operator_keypair = bitcoin::key::Keypair::from_str(operator_secret_key).unwrap();
        let operator_xonly_pubkey = operator_keypair.x_only_public_key().0;

        let (operator_taproot_address, operator_taproot_builder) =
            get_operator_taproot_address(operator_xonly_pubkey, network);

        let disprove_scripts: Vec<_> = bitvm_cache
            .disprove_scripts
            .iter()
            .map(|x| ScriptBuf::from(x.clone()))
            .collect();

        println!(
            "Send funds to operator_taproot_address: {:?}",
            operator_taproot_address
        );
        // return;

        // let funding_outpoint = bitcoin::OutPoint::new(
        //     Txid::from_str("a17e459d42d6a37a96e53c6a280097517be50349f9346b4867d6436184a31954")
        //         .unwrap(),
        //     0,
        // );

        // let all_txs = get_raw_signed_transactions(
        //     funding_outpoint,
        //     bitvm_cache.pubkeys,
        //     operator_xonly_pubkey,
        //     operator_keypair,
        //     bitvm_cache.signatures,
        //     &disprove_scripts,
        //     network,
        // );

        // // print!("testmempoolaccept '[");
        // for tx in all_txs.iter() {
        //     println!("/usr/local/bin/bitcoin-cli -regtest -rpcport=48333 -rpcuser=admin -rpcpassword=admin sendrawtransaction {};", hex::encode(bitcoin::consensus::serialize(tx)));
        // }

        let fetch_from_cache = true;
        let sigs = if fetch_from_cache {
            bitvm_cache.signatures
        } else {
            let x = utils_raw_witnesses_from_signatures(&bitvm_cache.signatures);
            println!("x: {:?}", x);
    
            let assert_end_txid =
                Txid::from_str("8ea73a1eee3104d832f6f0868ff2b57103f9091b7e1607dffe214ca8ebc42c87")
                    .unwrap();
            let rpc = bitcoincore_rpc::Client::new(
                "http://localhost:48333",
                bitcoincore_rpc::Auth::UserPass("admin".to_string(), "admin".to_string()),
            )
            .unwrap();
            let tx = rpc.get_raw_transaction(&assert_end_txid, None).unwrap();
            println!("tx: {:?}", tx);
            let mut witnesses = Vec::new();
            for (i, input) in tx.input.iter().enumerate() {
                println!("vin: {:?}", input);
                let input_txid = input.previous_output.txid;
                let input_tx = rpc.get_raw_transaction(&input_txid, None).unwrap();
                let witness_elements: Vec<Vec<u8>> = input_tx.input[0]
                    .witness
                    .iter()
                    .map(|w| w.to_vec())
                    .collect();
                let witness_elements_without_last_three =
                    witness_elements[..witness_elements.len() - 3].to_vec();
                println!("witness: {:?}", witness_elements_without_last_three);
                if i == 0 {
                    witnesses.push(witness_elements_without_last_three);
                } else if i < 5 {
                    let chunks = witness_elements_without_last_three
                        .chunks_exact(witness_elements_without_last_three.len() / 5);
                    let vec_of_chunks: Vec<Vec<Vec<u8>>> = chunks.map(|chunk| chunk.to_vec()).collect();
                    witnesses.extend(vec_of_chunks);
                } else {
                    let chunks = witness_elements_without_last_three
                        .chunks_exact(witness_elements_without_last_three.len() / 10);
                    let vec_of_chunks: Vec<Vec<Vec<u8>>> = chunks.map(|chunk| chunk.to_vec()).collect();
                    witnesses.extend(vec_of_chunks);
                }
            }
            println!("witnesses: {:?}", witnesses);
            println!("Witness length: {}", witnesses.len());
            let x: Signatures = utils_signatures_from_raw_witnesses(&witnesses);
            println!("x: {:?}", x);
            x
        };


        let disprove_scripts: Vec<Script> = disprove_scripts
            .iter()
            .map(|x| {
                script! {
                    {x.clone().as_bytes().to_vec()}
                }
            })
            .collect();

        println!("Disprove scripts len: {}", disprove_scripts.len());
        println!("Num taps: {}", NUM_TAPS);

        let y = validate_assertions(
            &vk,
            sigs,
            bitvm_cache.pubkeys,
            &disprove_scripts.try_into().unwrap(),
        );
        println!("y: {:?}", y);
        // print!("]'\n");
        // println!("txs: {:?}", txs);
        return;

        // let pubkeys = bitvm_cache.pubkeys;
        // let proof_sigs = bitvm_cache.signatures;
        // let disprove_scripts = bitvm_cache.disprove_scripts;

        // corrupt_at_random_index(&mut proof_asserts);

        // let corrupt_signed_asserts = get_signature_from_assertion(&proof_asserts, secrets);
        // let disprove_scripts: [Script; NUM_TAPS] = disprove_scripts.try_into().unwrap();

        // let invalid_tap =
        //     validate_assertions(&vk, corrupt_signed_asserts, pubkeys, &disprove_scripts);
        // assert!(invalid_tap.is_some());
        // let (index, hint_script) = invalid_tap.unwrap();
        // println!("STEP 4 EXECUTING DISPROVE SCRIPT at index {}", index);
        // let scr = script!(
        //     {hint_script.clone()}
        //     {disprove_scripts[index].clone()}
        // );
        // let res = execute_script(scr);
        // if res.final_stack.len() > 1 {
        //     println!("Stack ");
        //     for i in 0..res.final_stack.len() {
        //         println!("{i:} {:?}", res.final_stack.get(i));
        //     }
        // }

        // assert_eq!(res.final_stack.len(), 1);
        // assert!(res.success);
        // println!("DONE");

        // fn corrupt_at_random_index(proof_asserts: &mut Assertions) {
        //     let mut rng = rand::thread_rng();
        //     let index = rng.gen_range(0..NUM_PUBS + NUM_U256 + NUM_U160);
        //     let mut scramble: [u8; 32] = [0u8; 32];
        //     scramble[16] = 37;
        //     let mut scramble2: [u8; 20] = [0u8; 20];
        //     scramble2[10] = 37;
        //     println!("demo: manually corrupt assertion at index at {:?}", index);
        //     if index < NUM_PUBS {
        //         if index == 0 {
        //             if proof_asserts.0[0] == scramble {
        //                 scramble[16] += 1;
        //             }
        //             proof_asserts.0[0] = scramble;
        //         }
        //     } else if index < NUM_PUBS + NUM_U256 {
        //         let index = index - NUM_PUBS;
        //         if proof_asserts.1[index] == scramble {
        //             scramble[16] += 1;
        //         }
        //         proof_asserts.1[index] = scramble;
        //     } else if index < NUM_PUBS + NUM_U256 + NUM_U160 {
        //         let index = index - NUM_PUBS - NUM_U256;
        //         if proof_asserts.2[index] == scramble2 {
        //             scramble2[10] += 1;
        //         }
        //         proof_asserts.2[index] = scramble2;
        //     }
        // }
    }
}