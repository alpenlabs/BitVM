use crate::chunk::primitves::extern_hash_nibbles;
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, Field, MontFp};
use super::primitves::{extern_fq_to_nibbles, extern_fr_to_nibbles, extern_hash_fps, HashBytes};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Element {
    Fp12v0(ElemFp12Acc), // 2,4, 2, 4
    Fp12v1(ElemFp12Acc),  // 6, 6
    Fp12v2(ElemFp12Acc), // 6, 1
    G2T(ElemG2PointAcc), // 4
    G2DblEval(ElemG2PointAcc), // 4, 4
    G2DblAddEval(ElemG2PointAcc), // 4,4,4
    G2AddEval(ElemG2PointAcc), // 4,4
    SparseEval(ElemSparseEval), // 6, 6
    FieldElem(ElemFq), // 1
    ScalarElem(ElemFr), // 1
    HashBytes(ElemHashBytes), // 1
    MSMG1(ElemG1Point), // 2
    MSMG2(ElemG2Point), // 4
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ElementType {
    Fp12v0, // 2,4, 2, 4
    Fp12v1,  // 6, 6
    Fp12v2, // 6, 1
    Fp6,
    G2T, // 4
    G2DblEval, // 4, 4
    G2DblAddEval, // 4,4,4
    G2AddEval, // 4,4
    SparseEval, // 6, 6
    FieldElem, // 1
    ScalarElem, // 1
    HashBytes, // 1
    MSMG1, // 2
    MSMG2, // 4
}

impl ElementType {
    pub fn num_limbs(&self) -> usize {
        match self {
            ElementType::G2AddEval => 4 + 4 + 1,
            ElementType::G2DblAddEval => 4 + 4 + 4,
            ElementType::G2T => 4 + 1,
            ElementType::G2DblEval => 4 + 4 + 1,
            ElementType::Fp12v0 => 12,
            ElementType::Fp12v1 => 12,
            ElementType::Fp12v2 => 6 + 1,
            ElementType::Fp6 => 6,
            ElementType::FieldElem => 1,
            ElementType::MSMG1 => 2,
            ElementType::MSMG2 => 4,
            ElementType::ScalarElem => 1,
            ElementType::SparseEval => 12,
            ElementType::HashBytes => 1,
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

    pub fn element_type(&self) -> ElementType {
        match self {
            Element::G2AddEval(_) => ElementType::G2AddEval, 
            Element::G2DblAddEval(_) => ElementType::G2DblAddEval,
            Element::G2T(_) => ElementType::G2T,
            Element::G2DblEval(_) => ElementType::G2DblEval,
            Element::Fp12v0(_) => ElementType::Fp12v0, // 2, 4
            Element::Fp12v1(_) => ElementType::Fp12v1, // 6
            Element::Fp12v2(_) => ElementType::Fp12v2, // 6,1
            Element::FieldElem(_) => ElementType::FieldElem,
            Element::MSMG1(_) => ElementType::MSMG1,
            Element::MSMG2(_) => ElementType::MSMG2,
            Element::ScalarElem(_) => ElementType::ScalarElem,
            Element::SparseEval(_) => ElementType::SparseEval,
            Element::HashBytes(_) => ElementType::HashBytes,
        }
    }

    pub fn hashed_output(&self) -> HashBytes {
        match self {
            Element::G2AddEval(r) => r.hashed_output(),
            Element::G2DblAddEval(r) => r.hashed_output(),
            Element::G2T(r) => r.hashed_output(),
            Element::G2DblEval(r) => r.hashed_output(),
            Element::Fp12v0(r) => r.hashed_output(),
            Element::Fp12v1(r) => r.hashed_output(),
            Element::Fp12v2(r) => r.hashed_output(),
            Element::FieldElem(f) => f.hashed_output(),
            Element::MSMG1(r) => r.hashed_output(),
            Element::MSMG2(r) => r.hashed_output(),
            Element::ScalarElem(r) => r.hashed_output(),
            Element::SparseEval(r) => r.hashed_output(),
            Element::HashBytes(r) => r.hashed_output(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EvalIns {
    pub(crate) p2: G1Affine,
    pub(crate) p3: G1Affine,
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

impl_try_from_element!(ElemFp12Acc, { Fp12v0, Fp12v1, Fp12v2 });
impl_try_from_element!(ElemG2PointAcc, { G2T, G2DblEval, G2DblAddEval, G2AddEval });
impl_try_from_element!(ElemSparseEval, { SparseEval });
impl_try_from_element!(ElemFq, { FieldElem });
impl_try_from_element!(ElemFr, { ScalarElem });
impl_try_from_element!(ElemHashBytes, { HashBytes });
impl_try_from_element!(ElemG1Point, { MSMG1 });

pub type ElemFq = ark_bn254::Fq;
pub type ElemFr = ark_bn254::Fr;
pub type ElemHashBytes = HashBytes;

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
            vec![
                f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
                f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
            ],
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
        let mut hash_le = [0u8; 64];
        if self.dbl_le.is_some() || self.add_le.is_some() {
            let mut hash_dbl_le = [0u8; 64];
            if self.dbl_le.is_some() {
                let (dbl_le0, dbl_le1) = self.dbl_le.unwrap();
                hash_dbl_le = extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
            }
            let mut hash_add_le = [0u8; 64];
            if self.add_le.is_some() {
                let add_le = self.add_le.unwrap();
                hash_add_le = extern_hash_fps(vec![add_le.0.c0, add_le.0.c1, add_le.1.c0, add_le.1.c1], true);
            }
            hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        }
        hash_le
    }

    pub(crate) fn hash_other_le(&self, dbl: bool) -> [u8; 64] {
        if (dbl && self.add_le.is_none()) || (!dbl && self.dbl_le.is_none()) {
            return [0u8; 64];
        }
        let mut le = (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
        if dbl {
            le = self.add_le.unwrap();
        } else {
            le = self.dbl_le.unwrap();
        }
        let (le0, le1) = le;
        let le = extern_hash_fps(vec![le0.c0, le0.c1, le1.c0, le1.c1], true);
        le
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ElemSparseEval {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: ark_bn254::G2Affine,
    pub(crate) f: ElemFp12Acc,
}

impl ElemSparseEval {
    pub(crate) fn hashed_output(&self) -> HashBytes {
        self.f.hash
    }

    pub(crate) fn mock() -> Self {
        let t = ark_bn254::G2Affine::identity();
        Self { t2: t, t3: t, f: ElemFp12Acc::mock() }
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


impl ElemTraitExt for HashBytes {
    fn mock() -> Self {
        [0u8; 64]
    }
    fn hashed_output(&self) -> HashBytes {
        *self
    }
}