use ark_groth16::{Proof, VerifyingKey};
use bitcoin_script::script;
use itertools::Itertools;
use std::{collections::BTreeMap, rc::Rc};
use crate::{chunk::assigner::{get_assertions, get_intermediates, get_proof}, groth16::g16::Signatures, signatures::{signing_winternitz::{generate_winternitz_witness, WinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs}, wots::wots256}, treepp::Script};
use super::{assigner::Intermediates, element::InputProof, elements::{CompressedStateObject, ElementTrait, RawWitness}, primitives::HashBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct RawProof {
    pub proof: Proof<ark_bn254::Bn254>,
    pub public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    pub vk: VerifyingKey<ark_bn254::Bn254>,
}

/// Implement `BCAssinger` to adapt with bridge.
#[allow(clippy::borrowed_box)]
pub trait BCAssigner: Default {
    /// check hash
    fn create_hash(&mut self, id: &str);
    /// return a element of
    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness;
    /// output sciprt for all elements, used by assert transaction
    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>>;
    /// output witness for all elements, used by assert transaction
    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>>;
    /// recover hashes from witnesses
    fn recover_from_witnesses(
        &mut self,
        witnesses: Signatures,
        vk: VerifyingKey<ark_bn254::Bn254>,
    ) -> (Intermediates, InputProof);
}

#[derive(Default)]
pub struct BridgeAssigner {
    bc_map: BTreeMap<String, usize>,
    commits_secrets: BTreeMap<String, WinternitzSecret>,
    commits_publickeys: BTreeMap<String, WinternitzPublicKey>,
    recoverd_witness_store: Option<Signatures>,
}

impl BridgeAssigner {
    pub fn new_operator(commits_secrets: BTreeMap<String, WinternitzSecret>) -> Self {
        Self {
            bc_map: BTreeMap::new(),
            commits_publickeys: commits_secrets
                .iter()
                .map(|(k, v)| (k.clone(), v.into()))
                .collect(),
            commits_secrets,
            recoverd_witness_store: None,
        }
    }

    pub fn new_variable_tracer() -> Self {
        Self::default()
    }

    pub fn new_watcher(commits_publickeys: BTreeMap<String, WinternitzPublicKey>) -> Self {
        Self {
            bc_map: BTreeMap::new(),
            commits_secrets: BTreeMap::new(),
            commits_publickeys,
            recoverd_witness_store: None,
        }
    }

    pub fn all_intermediate_variables(&mut self) -> BTreeMap<String, usize> {
        // let proof = RawProof::default();
        // let _ = groth16_verify_to_segments(self, &proof.public, &proof.proof, &proof.vk);
        self.bc_map.clone()
    }
}
impl BCAssigner for BridgeAssigner {
     /// check hash
     fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), 0);
     }
     /// return a element of
     fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
        // is_whether var or hash and add locking script
        // wots256::checksig_verify(self.commits_publickeys.get(key).unwrap());
        script!()
     }
     fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        // either i have the witness store
        // calculate signature raw witness by calling sign method
        if self.recoverd_witness_store.is_some() {
            // return self
            //     .recoverd_witness_store
            //     .unwrap()
            //     .get(element.id())
            //     .unwrap()
            //     .clone();
        }

        assert!(self.commits_secrets.contains_key(element.id()));
        let secret_key = self.commits_secrets.get(element.id()).unwrap();


        let msg = element.to_hash().serialize_to_byte_array();
        let message = msg.as_slice();

        let signing_input = WinternitzSigningInputs {
            message,
            signing_key: secret_key,
        };

        generate_winternitz_witness(&signing_input).to_vec()
     }
     /// output sciprt for all elements, used by assert transaction
     fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
        // 
        vec![]
     }
     /// output witness for all elements, used by assert transaction
     fn all_intermediate_witnesses(
         &self,
         elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
     ) -> Vec<Vec<RawWitness>> {
        todo!()
     }

     /// recover hashes from witnesses
     fn recover_from_witnesses(
         &mut self,
         witnesses: Signatures,
         vk: VerifyingKey<ark_bn254::Bn254>,
     ) -> (Intermediates, InputProof) {

        // witness to assertion type
        let typed_assertions = get_assertions(witnesses);
        let proof = get_proof(&typed_assertions);
        let intermediates = get_intermediates(&typed_assertions);
        (intermediates, proof)
     }
}