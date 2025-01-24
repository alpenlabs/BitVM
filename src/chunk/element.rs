use crate::{bn254::utils::Hint, chunk::primitves::extern_hash_nibbles};
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, Field, MontFp};
use super::primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles, extern_hash_fps, extern_nibbles_to_limbs, HashBytes};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Element {
    Fp12(ElemFp12Acc), // 2,4, 2, 4
    Fp6(ElemFp6), // 6
    G2Acc(ElemG2PointAcc),
    FieldElem(ElemFq), // 1
    ScalarElem(ElemFr), // 1
    G1(ElemG1Point), // 2
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ElementType {
    Fp12v0, // 6, 6
    Fp12v2, // 6, 1
    Fp6,
    Fp6Hash,
    G2T, // 4
    G2DblEval, // 4, 4
    G2DblAddEval, // 4,4,4
    G2AddEval, // 4,4
    G2DblEvalMul,
    G2AddEvalMul,
    FieldElem, // 1
    ScalarElem, // 1
    G1, // 2
}

impl ElementType {
    pub fn num_limbs(&self) -> usize {
        match self {
            ElementType::G2AddEval => 4 + 4 + 1,
            ElementType::G2DblAddEval => 4 + 4 + 4,
            ElementType::G2T => 4 + 1,
            ElementType::G2DblEvalMul => 4 + 1 + 1,
            ElementType::G2AddEvalMul => 4 + 1 + 1,
            ElementType::G2DblEval => 4 + 4 + 1,
            ElementType::Fp12v0 => 12,
            ElementType::Fp12v2 => 6 + 1,
            ElementType::Fp6 => 6,
            ElementType::Fp6Hash => 1,
            ElementType::FieldElem => 0,
            ElementType::G1 => 2,
            ElementType::ScalarElem => 0,
        }
    }
}

impl Element {
    pub fn output_is_field_element(&self) -> bool {
        match *self {
            Element::FieldElem(_) => true, 
            Element::ScalarElem(_) => true, 
            _ => false,
        }
    }

    pub fn hashed_output(&self) -> HashBytes {
        match self {
            Element::G2Acc(r) => r.hashed_output(),
            Element::Fp12(r) => r.hashed_output(),
            Element::Fp6(r) => {
                extern_hash_fps(
                    r.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
                    true,
                )
            },
            Element::FieldElem(f) => f.hashed_output(),
            Element::G1(r) => r.hashed_output(),
            Element::ScalarElem(r) => r.hashed_output(),
        }
    }

    pub fn get_hash_preimage_as_hints(&self, elem_type: ElementType) -> Vec<Hint> {
        match elem_type {
            ElementType::G2AddEval => {
                if let Element::G2Acc(g) = self {
                    vec![
                        Hint::Fq(g.t.x.c0),
                        Hint::Fq(g.t.x.c1),
                        Hint::Fq(g.t.y.c0),
                        Hint::Fq(g.t.y.c1),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
                    ]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::G2DblAddEval => {
                if let Element::G2Acc(g) = self {
                    vec![
                        Hint::Fq(g.t.x.c0),
                        Hint::Fq(g.t.x.c1),
                        Hint::Fq(g.t.y.c0),
                        Hint::Fq(g.t.y.c1),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
                    ]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::G2DblEval => {
                if let Element::G2Acc(g) = self {
                    vec![
                        Hint::Fq(g.t.x.c0),
                        Hint::Fq(g.t.x.c1),
                        Hint::Fq(g.t.y.c0),
                        Hint::Fq(g.t.y.c1),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
                    ]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::G2DblEvalMul => {
                if let Element::G2Acc(g) = self {
                    let (dbl_le_0, dbl_le_1) = g.dbl_le.unwrap();
                    vec![
                        Hint::Fq(dbl_le_0.c0),
                        Hint::Fq(dbl_le_0.c1),
                        Hint::Fq(dbl_le_1.c0),
                        Hint::Fq(dbl_le_1.c1),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_other_le(true))),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_t())),
                    ]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::G2AddEvalMul => {
                if let Element::G2Acc(g) = self {
                    let (add_le_0, add_le_1) = g.add_le.unwrap();
                    vec![
                        Hint::Fq(add_le_0.c0),
                        Hint::Fq(add_le_0.c1),
                        Hint::Fq(add_le_1.c0),
                        Hint::Fq(add_le_1.c1),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_other_le(false))),
                        Hint::Hash(extern_nibbles_to_limbs(g.hash_t())),
                    ]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::Fp12v0 => {
                if let Element::Fp12(r) = self {
                    r.f.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect()
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::Fp12v0=> {
                if let Element::Fp12(r) = self {
                    r.f.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect()
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::Fp12v2 => vec![],
            ElementType::Fp6 => {
                if let Element::Fp6(r) = self {
                    r.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect()
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::Fp6Hash => {
                if let Element::Fp6(r) = self {
                    let rhash = extern_hash_fps(
                        r.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
                        true,
                    );
                    vec![Hint::Hash(extern_nibbles_to_limbs(rhash))]
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::G1 => {
                if let Element::G1(r) = self {
                    vec![Hint::Fq(r.x), Hint::Fq(r.y)]
                } else {
                    panic!();
                    vec![]
                }
            }
            ElementType::FieldElem => vec![],
            ElementType::ScalarElem => vec![],
            ElementType::G2T => vec![],
        }
    }

    

}

#[derive(Debug)]
pub(crate) struct EvalIns {
    pub(crate) p2: G1Affine,
    pub(crate) p4: G1Affine,
    pub(crate) q4: G2Affine,
    pub(crate) c: ark_bn254::Fq12,
    pub(crate) s: ark_bn254::Fq12,
    pub(crate) ks: Vec<ark_bn254::Fr>,
}

#[derive(Debug)]
pub(crate) enum ElementConversionError {
    /// Returned when an attempt to convert an `Element` variant into a type that
    /// does not match its stored variant is made.
    InvalidVariantConversion {
        attempted: &'static str,
        found: &'static str,
    },
}

/// Helper macro to reduce repetitive code for `TryFrom<Element>`.
macro_rules! impl_try_from_element {
    ($t:ty, { $($variant:ident),+ }) => {
        impl TryFrom<Element> for $t {
            type Error = ElementConversionError;

            fn try_from(value: Element) -> Result<Self, Self::Error> {
                match value {
                    $(
                        Element::$variant(v) => Ok(v),
                    )+
                    other => {
                        Err(ElementConversionError::InvalidVariantConversion {
                        attempted: stringify!($t),
                        found: stringify!(other),
                    })},
                }
            }
        }
    };
}

impl_try_from_element!(ElemFp12Acc, { Fp12, Fp12, Fp12 });
impl_try_from_element!(ElemFp6, { Fp6 });
impl_try_from_element!(ElemG2PointAcc, { G2Acc, G2Acc, G2Acc, G2Acc });
impl_try_from_element!(ElemFq, { FieldElem });
impl_try_from_element!(ElemFr, { ScalarElem });
impl_try_from_element!(ElemG1Point, { G1 });

pub type ElemFq = ark_bn254::Fq;
pub type ElemFr = ark_bn254::Fr;

pub(crate) type ElemFp6 = ark_bn254::Fq6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ElemFp12Acc {
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) hash: HashBytes,
}

impl ElemTraitExt for ElemFp12Acc {
    fn hashed_output(&self) -> HashBytes {
         self.hash
    }

    fn mock() -> Self {
        let f = ark_bn254::Fq12::ONE;
        let hash = extern_hash_fps(
            f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        ElemFp12Acc { f, hash }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct ElemG2PointAcc {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) dbl_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
    pub(crate) add_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
}

impl ElemG2PointAcc {
    pub(crate) fn hash_t(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1], true)
    }

    pub(crate) fn hash_le(&self) -> HashBytes {
        let zero = ark_bn254::Fq::ZERO;
        let mut hash_dbl_le = extern_hash_fps(vec![zero, zero, zero, zero], true);
        let mut hash_add_le = hash_dbl_le.clone();
        let mut hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);

        if self.dbl_le.is_some() || self.add_le.is_some() {
            if self.dbl_le.is_some() {
                let (dbl_le0, dbl_le1) = self.dbl_le.unwrap();
                hash_dbl_le = extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
            }
            if self.add_le.is_some() {
                let add_le = self.add_le.unwrap();
                hash_add_le = extern_hash_fps(vec![add_le.0.c0, add_le.0.c1, add_le.1.c0, add_le.1.c1], true);
            }
            hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        }
        hash_le
    }

    pub(crate) fn hash_other_le(&self, dbl: bool) -> [u8; 64] {
        let zero = ark_bn254::Fq::ZERO;
        let hash_dbl_le = extern_hash_fps(vec![zero, zero, zero, zero], true);
        let hash_add_le = hash_dbl_le.clone();

        if dbl && self.add_le.is_none() {
            return hash_add_le;
        }
        if !dbl && self.dbl_le.is_none() {
            return hash_dbl_le;
        }

        let le = if dbl {
            self.add_le.unwrap()
        } else {
            self.dbl_le.unwrap()
        };
        extern_hash_fps(vec![le.0.c0, le.0.c1, le.1.c0, le.1.c1], true)
    }



}

impl ElemTraitExt for ElemG2PointAcc {
    fn hashed_output(&self) -> HashBytes {
        let hash_t = self.hash_t();
        let hash_le = self.hash_le();
        let hash = extern_hash_nibbles(vec![hash_t, hash_le], true);
        hash
    }

    fn mock() -> Self {
        let q4xc0: ark_bn254::Fq = MontFp!("18327300221956260726652878806040774028373651771658608258634994907375058801387");
        let q4xc1: ark_bn254::Fq = MontFp!("2791853351403597124265928925229664715548948431563105825401192338793643440152"); 
        let q4yc0: ark_bn254::Fq = MontFp!("9203020065248672543175273161372438565462224153828027408202959864555260432617");
        let q4yc1: ark_bn254::Fq = MontFp!("21242559583226289516723159151189961292041850314492937202099045542257932723954");
        let tx = ark_bn254::Fq2::new(q4xc0, q4xc1);
        let ty =  ark_bn254::Fq2::new(q4yc0, q4yc1);
        let t = ark_bn254::G2Affine::new(tx, ty);
        ElemG2PointAcc { t, dbl_le: Some((tx, ty)), add_le: Some((tx, ty)) }
    }
}

// Define the type alias
pub type ElemG1Point = ark_bn254::G1Affine;

pub type ElemG2Point = (ark_bn254::Fq2, ark_bn254::Fq2);

// Define a trait to extend the functionality
pub(crate) trait ElemTraitExt {
    fn hashed_output(&self) -> HashBytes;
    fn mock() -> Self;
}

// Implement the trait for ark_bn254::G1Affine
impl ElemTraitExt for ElemG1Point {
    fn hashed_output(&self) -> HashBytes {
        extern_hash_fps(vec![self.x, self.y], true)
    }

    fn mock() -> Self {
        let g1x: ark_bn254::Fq = MontFp!("5567084537907487155917146166615783238769284480674905823618779044732684151587");
        let g1y: ark_bn254::Fq = MontFp!("6500138522353517220105129525103627482682148482121078429366182801568786680416");
        ark_bn254::G1Affine::new(g1x, g1y)
    }
}

// Implement the trait for ark_bn254::G1Affine
impl ElemTraitExt for ElemG2Point {
    fn hashed_output(&self) -> HashBytes {
        extern_hash_fps(vec![self.0.c0, self.0.c1, self.1.c0, self.1.c1], true)
    }

    fn mock() -> Self {
        let g1x: ark_bn254::Fq = MontFp!("5567084537907487155917146166615783238769284480674905823618779044732684151587");
        let g1y: ark_bn254::Fq = MontFp!("6500138522353517220105129525103627482682148482121078429366182801568786680416");
        (ark_bn254::Fq2::new(g1x, g1x), ark_bn254::Fq2::new(g1y, g1y))
    }
}

impl ElemTraitExt for ElemFq {
    fn mock() -> Self {
        ark_bn254::Fq::ONE
    }
    fn hashed_output(&self) -> HashBytes {
        extern_fq_to_nibbles(*self)
    }
}


impl ElemTraitExt for ElemFr {
    fn mock() -> Self {
        ark_bn254::Fr::ONE
    }
    fn hashed_output(&self) -> HashBytes {
        extern_fr_to_nibbles(*self)
    }
}


impl ElemTraitExt for ElemFp6 {
    fn hashed_output(&self) -> HashBytes {
        let hash = extern_hash_fps(
            self.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
            true,
        );
        hash
    }

    fn mock() -> Self {
        let f = ark_bn254::Fq6::ONE;
        f
    }
}