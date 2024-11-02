use crate::signatures::wots::{wots160, wots256, wots32};
use crate::treepp::*;

pub const N_VERIFIER_PUBLIC_INPUTS: usize = 3;
pub const N_VERIFIER_FQs: usize = 48;
pub const N_VERIFIER_HASHES: usize = 598;

pub const N_TAPLEAVES: usize = 602;

type WotsPublicKeys = (
    (wots32::PublicKey, wots256::PublicKey, wots256::PublicKey),
    [wots256::PublicKey; N_VERIFIER_FQs],
    [wots160::PublicKey; N_VERIFIER_HASHES],
);

type WotsSignatures = (
    (wots32::Signature, wots256::Signature, wots256::Signature),
    [wots256::Signature; N_VERIFIER_FQs],
    [wots160::Signature; N_VERIFIER_HASHES],
);

type ProofPublicInputs = (u32, [u8; 32], [u8; 32]);

type Groth16ProofAssertions = (
    ProofPublicInputs,
    [[u8; 32]; N_VERIFIER_FQs],
    [[u8; 32]; N_VERIFIER_HASHES],
);

fn groth16_proof_assertions_to_signatures(secret_key: &str) -> WotsSignatures {
    todo!()
}

struct VerificationKey {}

struct Proof {}

pub struct Verifier {
    pub vk: VerificationKey,
}

impl Verifier {
    pub fn new(vk: VerificationKey) -> Self {
        Self { vk }
    }

    pub fn compile() -> [Script; N_TAPLEAVES] {
        todo!()
    }

    pub fn generate_tapscripts(
        public_keys: WotsPublicKeys,
        verifier_scripts: [Script; N_TAPLEAVES],
    ) -> [Script; 602] {
        todo!()
    }

    pub fn generate_assertions(proof: Proof) -> Groth16ProofAssertions {
        todo!()
    }

    /// Validates the groth16 proof assertion signatures and returns a tuple of (tapleaf_index, tapleaf_script, and witness_script) if
    /// the proof is invalid, else returns none
    pub fn validate_assertion_signatures(
        public_keys: WotsPublicKeys,
        signatures: WotsSignatures,
        verifier_scripts: [Script; N_TAPLEAVES],
    ) -> Option<(u32, Script, Script)> {
        todo!()
    }
}
