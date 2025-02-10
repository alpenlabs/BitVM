use std::{any::Any, str::FromStr};

use crate::{bigint::U256, bn254::{fq::Fq, utils::Hint}, chunk::{primitives::extern_hash_nibbles}, chunker::common::extract_witness_from_stack, execute_script};
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{BigInteger, Field, PrimeField};
use crate::treepp::Script;
use bitcoin_script::script;
use num_bigint::{BigInt, BigUint};
use super::{compile::NUM_PUBS, element::{ElemFp6, ElemG1Point, ElemG2Eval, ElemU256}, primitives::{extern_bigint_to_nibbles, extern_hash_fps, extern_nibbles_to_bigint, extern_nibbles_to_limbs, HashBytes}};

pub type RawWitness = Vec<Vec<u8>>;
use crate::{chunker::assigner::BCAssigner};
use std::fmt::Debug;

/// FqElements are used in the chunker, representing muliple Fq.
#[derive(Debug, Clone)]
pub struct FqElement {
    pub identity: String,
    pub size: usize,
    pub witness_data: Vec<Hint>,
    pub data: Option<DataType>,
}

/// Achieve witness depth, `9` is the witness depth of `U254`
impl FqElement {
    fn witness_size(&self) -> usize {
        self.size * 9
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DataType {
    Fp6Data(ElemFp6), 
    G2EvalData(ElemG2Eval),
    G1Data(ElemG1Point),
    U256Data(ark_ff::BigInt<4>),
}

pub enum CompressedStateObject {
    Hash(HashBytes),
    U256(ark_ff::BigInt<4>)
}

impl CompressedStateObject {
    fn as_hint_type(self) -> Hint {
        match self {
            CompressedStateObject::Hash(h) => Hint::Hash(extern_nibbles_to_limbs(h)),
            CompressedStateObject::U256(f) => {
                let fuint: BigUint = f.into();
                let fint: BigInt = BigInt::from_biguint(num_bigint::Sign::Plus, fuint);
                Hint::U256(fint)
            }
        }
    }

    pub(crate) fn serialize_to_byte_array(self) -> Vec<u8> {
        fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
        
            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
                msg_bytes.push(byte);
            }
        
            msg_bytes
        }
        match self {
            CompressedStateObject::Hash(h) => {
                let bal: [u8; 32] = nib_to_byte_array(&h).try_into().unwrap();
                let bal: [u8; 20] = bal[12..32].try_into().unwrap();
                bal.to_vec()
            }
            CompressedStateObject::U256(n) => {
                let n = extern_bigint_to_nibbles(n);
                let bal: [u8; 32] = nib_to_byte_array(&n).try_into().unwrap();
                bal.to_vec()
            }
        }
    }

    pub(crate)  fn deserialize_from_byte_array(byte_array: Vec<u8>) -> Self {
        assert!(byte_array.len() == 20 || byte_array.len() == 32);
        fn byte_array_to_nib(bytes: &[u8]) -> Vec<u8> {
            let mut nibbles = Vec::with_capacity(bytes.len() * 2);
            for &b in bytes {
                let low = b & 0x0F;
                let high = b >> 4;
                nibbles.push(low);
                nibbles.push(high);
            }
            nibbles
        }
       if byte_array.len() == 20 {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; 40] = nib_arr.try_into().unwrap();
            let mut padded_nibs = [0u8; 64]; // initialize with zeros
            padded_nibs[24..64].copy_from_slice(&nib_arr[0..40]);
            CompressedStateObject::Hash(padded_nibs)
       } else {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; 64] = nib_arr.try_into().unwrap();
            let fint = extern_nibbles_to_bigint(nib_arr);
            CompressedStateObject::U256(fint)
       }
    }


}

impl DataType {

    pub fn hashed_output(self) -> CompressedStateObject {
        match self {
            DataType::G2EvalData(r) => {
                let hash_t = r.hash_t();
                let hash_le = r.hash_le();
                let hash = extern_hash_nibbles(vec![hash_t, hash_le]);
                CompressedStateObject::Hash(hash)
            },
            DataType::Fp6Data(r) => {
                let hash = extern_hash_fps(
                    r.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
                );
                CompressedStateObject::Hash(hash)
            }
            DataType::U256Data(f) => {
                CompressedStateObject::U256(f)
            },
            DataType::G1Data(r) => {
                let hash = extern_hash_fps(vec![r.x, r.y]);
                CompressedStateObject::Hash(hash)
            }
        }
    }
}

/// This trait defines the intermediate values
pub trait ElementTrait: Debug {
    /// Fill data by a specific value
    fn fill_with_data(&mut self, x: DataType);
    /// Convert the intermediate values to witness
    fn to_witness(&self) -> Vec<Hint>;
    /// Convert the intermediate values from witness.
    /// If witness is none, return none.
    fn to_data(&self) -> Option<DataType>;
    /// Hash witness by blake3, return witness of Hash
    fn to_hash(&self) -> CompressedStateObject;
    /// Size of element by Fq
    fn size(&self) -> usize;
    /// Witness size of element by u32
    fn witness_size(&self) -> usize;
    /// Return the name of identity.
    fn id(&self) -> &str;
}


macro_rules! impl_element_trait {
    ($element_type:ident, $data_type:ident, $size:expr, $as_hints:expr) => {
        #[derive(Clone, Debug)]
        pub struct $element_type(FqElement);

        impl $element_type {
            /// Create a new element by using bitcommitment assigner
            pub fn new<F: BCAssigner>(assigner: &mut F, id: &str) -> Self {
                assigner.create_hash(id);
                Self {
                    0: FqElement {
                        identity: id.to_owned(),
                        size: $size,
                        witness_data: vec![],
                        data: None,
                    },
                }
            }

            pub fn new_dummy(id: &str) -> Self {
                Self {
                    0: FqElement {
                        identity: id.to_owned(),
                        size: $size,
                        witness_data: vec![],
                        data: None,
                    },
                }
            }
        }

        /// impl element for Fq6
        impl ElementTrait for $element_type {
            fn fill_with_data(&mut self, x: DataType) {
                match x {
                    DataType::$data_type(fq6_data) => {
                        self.0.witness_data = $as_hints(fq6_data);
                        self.0.data = Some(x)
                    }
                    _ => panic!("fill wrong data {:?}", x.type_id()),
                }
            }

            fn to_witness(&self) -> Vec<Hint> {
                self.0.witness_data.clone()
            }

            fn to_data(&self) -> Option<DataType> {
                self.0.data.clone()
            }

            fn to_hash(&self) -> CompressedStateObject {
                assert!(self.0.data.is_some());
                self.0.data.unwrap().hashed_output()
            }

            fn size(&self) -> usize {
                self.0.size
            }

            fn witness_size(&self) -> usize {
                self.0.witness_size()
            }

            fn id(&self) -> &str {
                &self.0.identity
            }
        }
    };
}

impl_element_trait!(Fp6Type, Fp6Data, 6, as_hints_fq6type_fq6data);
impl_element_trait!(G2EvalPointType, G2EvalData, 4+1, as_hints_g2evalpointtype_g2evaldata);
impl_element_trait!(G2EvalMulType, G2EvalData, 14+1, as_hints_g2evalmultype_g2evaldata);
impl_element_trait!(G2EvalType, G2EvalData, 14+4, as_hints_g2evaltype_g2evaldata);
impl_element_trait!(FieldElemType, U256Data, 1, as_hints_fieldelemtype_u256data);
impl_element_trait!(ScalarElemType, U256Data, 1, as_hints_scalarelemtype_u256data);
impl_element_trait!(G1Type, G1Data, 2, as_hints_g1type_g1data);



fn as_hints_fq6type_fq6data(elem: ElemFp6) -> Vec<Hint> {
    let hints: Vec<Hint> = elem.to_base_prime_field_elements().into_iter().map(Hint::Fq).collect();
    hints
}

fn as_hints_g2evalpointtype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let hints = vec![
        Hint::Fq(g.t.x.c0),
        Hint::Fq(g.t.x.c1),
        Hint::Fq(g.t.y.c0),
        Hint::Fq(g.t.y.c1),
        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
    ];
    hints
}

fn as_hints_g2evalmultype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let mut hints: Vec<Hint> = g.apb
        .iter()
        .flat_map(|pt| [pt.c0, pt.c1]) // each point gives two values
        .chain(g.ab.to_base_prime_field_elements().into_iter())
        .chain(g.p2le.iter().flat_map(|pt| [pt.c0, pt.c1]))
        .chain(g.res_hint.to_base_prime_field_elements().into_iter())
        .map(Hint::Fq)
        .collect();
    hints.push(Hint::Hash(extern_nibbles_to_limbs(g.hash_t())));
    hints
}

fn as_hints_g2evaltype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let mut hints = vec![
        Hint::Fq(g.t.x.c0),
        Hint::Fq(g.t.x.c1),
        Hint::Fq(g.t.y.c0),
        Hint::Fq(g.t.y.c1),
        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
    ];
    let and_hints: Vec<Hint> = g.apb
        .iter()
        .flat_map(|pt| [pt.c0, pt.c1]) // each point gives two values
        .chain(g.ab.to_base_prime_field_elements().into_iter())
        .chain(g.p2le.iter().flat_map(|pt| [pt.c0, pt.c1]))
        .chain(g.res_hint.to_base_prime_field_elements().into_iter())
        .map(Hint::Fq)
        .collect();
    hints.extend_from_slice(&and_hints);
    hints
}


fn as_hints_fieldelemtype_u256data(elem: ElemU256) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_scalarelemtype_u256data(elem: ElemU256) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_g1type_g1data(r: ElemG1Point) -> Vec<Hint> {
    let hints = vec![Hint::Fq(r.x), Hint::Fq(r.y)];
    hints
}
