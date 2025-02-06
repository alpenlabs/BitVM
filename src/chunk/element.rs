use crate::{bn254::utils::Hint, chunk::primitves::extern_hash_nibbles};
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, Field, MontFp, PrimeField};
use super::{compile::NUM_PUBS, primitves::{extern_bigint_to_nibbles, extern_hash_fps, extern_nibbles_to_limbs, HashBytes}};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Element {
    Fp6(ElemFp6), // 6
    G2Eval(ElemG2Eval),
    G1(ElemG1Point), // 2
    U256(ark_ff::BigInt<4>), // 1
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ElementType {
    Fp6,
    G2EvalPoint,
    G2EvalMul,
    G2Eval,
    FieldElem, // 1
    ScalarElem, // 1
    G1, // 2
}

impl ElementType {
    pub fn num_limbs(&self) -> usize {
        match self {
            ElementType::Fp6 => 6,
            ElementType::FieldElem => 0,
            ElementType::G1 => 2,
            ElementType::ScalarElem => 0,
            ElementType::G2EvalPoint => 4 + 1,
            ElementType::G2EvalMul => 14 + 1,
            ElementType::G2Eval => 14 + 4,
        }
    }
}

impl Element {
    pub fn output_is_field_element(&self) -> bool {
        match *self {
            Element::U256(_) => true, 
            _ => false,
        }
    }

    pub fn hashed_output(&self) -> HashBytes {
        match self {
            Element::G2Eval(r) => r.hashed_output(),
            Element::Fp6(r) => {
                extern_hash_fps(
                    r.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
                )
            },
            Element::U256(f) => f.hashed_output(),
            Element::G1(r) => r.hashed_output(),
        }
    }

    pub fn get_hash_preimage_as_hints(&self, elem_type: ElementType) -> Vec<Hint> {
        match elem_type {
            ElementType::G2EvalPoint => {
                if let Element::G2Eval(g) = self {
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
            ElementType::G2EvalMul => {
                if let Element::G2Eval(g) = self {
                    let mut hs = vec![];
                    let hint_apb: Vec<Hint> = vec![g.apb[0].c0, g.apb[0].c1, g.apb[1].c0, g.apb[1].c1].into_iter().map(|f| Hint::Fq(f)).collect();
                    let hint_ab: Vec<Hint> = g.ab.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect();
                    let hint_p2le: Vec<Hint> = vec![g.p2le[0].c0, g.p2le[0].c1, g.p2le[1].c0, g.p2le[1].c1].into_iter().map(|f| Hint::Fq(f)).collect();
                    let hint_res: Vec<Hint> = g.res_hint.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect();
                    hs.extend_from_slice(&hint_apb);
                    hs.extend_from_slice(&hint_ab);
                    hs.extend_from_slice(&hint_p2le);
                    hs.extend_from_slice(&hint_res);
                    hs.push(Hint::Hash(extern_nibbles_to_limbs(g.hash_t())));
                    hs
                } else {
                    panic!();
                    vec![]
                }
            },
            ElementType::Fp6 => {
                if let Element::Fp6(r) = self {
                    r.to_base_prime_field_elements().into_iter().map(|f| Hint::Fq(f)).collect()
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
            ElementType::G2Eval => vec![],
        }
    }

    

}

#[derive(Debug)]
pub(crate) struct InputProof {
    pub(crate) p2: G1Affine,
    pub(crate) p4: G1Affine,
    pub(crate) q4: G2Affine,
    pub(crate) c: ark_bn254::Fq6,
    pub(crate) s: ark_bn254::Fq6,
    pub(crate) ks: Vec<ark_bn254::Fr>,
}

impl InputProof {
    pub(crate) fn to_raw(&self) -> InputProofRaw {
        let p2x = self.p2.x.into_bigint();
        let p2y = self.p2.y.into_bigint();
        let p4x = self.p4.x.into_bigint();
        let p4y = self.p4.y.into_bigint();
        let q4x0 = self.q4.x.c0.into_bigint();
        let q4x1 = self.q4.x.c1.into_bigint();
        let q4y0 = self.q4.y.c0.into_bigint();
        let q4y1 = self.q4.y.c1.into_bigint();
        let c: Vec<ark_ff::BigInt<4>> = self.c.to_base_prime_field_elements().map(|f| f.into_bigint()).collect();
        let s: Vec<ark_ff::BigInt<4>> = self.s.to_base_prime_field_elements().map(|f| f.into_bigint()).collect();
        let ks: Vec<ark_ff::BigInt<4>> = self.ks.iter().map(|f| f.into_bigint()).collect();

        InputProofRaw {
            p2: [p2x, p2y],
            p4: [p4x, p4y],
            q4: [q4x0, q4x1, q4y0, q4y1],
            c: c.try_into().unwrap(),
            s: s.try_into().unwrap(),
            ks: ks.try_into().unwrap(),
        }
    }

    pub(crate) fn from_raw(raw: InputProofRaw) -> InputProof {
        let mod_q = ark_bn254::Fq::MODULUS;
        let mod_r = ark_bn254::Fr::MODULUS;
        raw.p2.iter().for_each(|f| assert!(*f < mod_q));
        raw.p4.iter().for_each(|f| assert!(*f < mod_q));
        raw.q4.iter().for_each(|f| assert!(*f < mod_q));
        raw.c.iter().for_each(|f| assert!(*f < mod_q));
        raw.s.iter().for_each(|f| assert!(*f < mod_q));
        raw.ks.iter().for_each(|f| assert!(*f < mod_r));
        InputProof {
            p2: ark_bn254::G1Affine::new_unchecked(raw.p2[0].clone().into(), raw.p2[1].clone().into()),
            p4: ark_bn254::G1Affine::new_unchecked(raw.p4[0].clone().into(), raw.p4[1].clone().into()),
            q4: ark_bn254::G2Affine::new_unchecked(
                ark_bn254::Fq2::new(raw.q4[0].clone().into(), raw.q4[1].clone().into()), 
                ark_bn254::Fq2::new(raw.q4[2].clone().into(), raw.q4[3].clone().into()),
            ),
            c: ark_bn254::Fq6::from_base_prime_field_elems(raw.c.into_iter().map(|f| ark_bn254::Fq::from(f)).collect::<Vec<ark_bn254::Fq>>()).unwrap(),
            s: ark_bn254::Fq6::from_base_prime_field_elems(raw.s.into_iter().map(|f| ark_bn254::Fq::from(f)).collect::<Vec<ark_bn254::Fq>>()).unwrap(),
            ks: raw.ks.into_iter().map(|f| ark_bn254::Fr::from(f)).collect::<Vec<ark_bn254::Fr>>(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct InputProofRaw {
    pub(crate) p2: [ark_ff::BigInt<4>; 2],
    pub(crate) p4: [ark_ff::BigInt<4>; 2],
    pub(crate) q4: [ark_ff::BigInt<4>; 4],
    pub(crate) c: [ark_ff::BigInt<4>; 12],
    pub(crate) s: [ark_ff::BigInt<4>; 12],
    pub(crate) ks: [ark_ff::BigInt<4>; NUM_PUBS],
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

impl_try_from_element!(ElemFp6, { Fp6 });
impl_try_from_element!(ElemU256, { U256 });
impl_try_from_element!(ElemG1Point, { G1 });
impl_try_from_element!(ElemG2Eval, { G2Eval });

pub(crate) type ElemU256 = ark_ff::BigInt<4>;
pub(crate) type ElemFp6 = ark_bn254::Fq6;


#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct ElemG2Eval {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) p2le: [ark_bn254::Fq2;2],
    pub(crate) ab: ark_bn254::Fq6,
    pub(crate) apb: [ark_bn254::Fq2;2],
    pub(crate) res_hint: ark_bn254::Fq6,
    //g+f, fg, p2le
}

impl ElemG2Eval {
    pub(crate) fn hash_t(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1])
    }

    pub(crate) fn hash_le(&self) -> HashBytes {
        let mut le = vec![];
        le.extend_from_slice(&vec![self.apb[0].c0, self.apb[0].c1, self.apb[1].c0, self.apb[1].c1]);
        le.extend_from_slice(&self.ab.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>());
        le.extend_from_slice(&vec![self.p2le[0].c0, self.p2le[0].c1, self.p2le[1].c0, self.p2le[1].c1]);
        extern_hash_fps(le)
    }
}

impl ElemTraitExt for ElemG2Eval {
    fn hashed_output(&self) -> HashBytes {
        let hash_t = self.hash_t();
        let hash_le = self.hash_le();
        let hash = extern_hash_nibbles(vec![hash_t, hash_le]);
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
        ElemG2Eval { t, p2le: [ark_bn254::Fq2::ONE; 2], apb:[ark_bn254::Fq2::ONE; 2], ab: ark_bn254::Fq6::ONE, res_hint: ark_bn254::Fq6::ONE }
    }
}

// Define the type alias
pub type ElemG1Point = ark_bn254::G1Affine;

// Define a trait to extend the functionality
pub(crate) trait ElemTraitExt {
    fn hashed_output(&self) -> HashBytes;
    fn mock() -> Self;
}

// Implement the trait for ark_bn254::G1Affine
impl ElemTraitExt for ElemG1Point {
    fn hashed_output(&self) -> HashBytes {
        extern_hash_fps(vec![self.x, self.y])
    }

    fn mock() -> Self {
        let g1x: ark_bn254::Fq = MontFp!("5567084537907487155917146166615783238769284480674905823618779044732684151587");
        let g1y: ark_bn254::Fq = MontFp!("6500138522353517220105129525103627482682148482121078429366182801568786680416");
        ark_bn254::G1Affine::new(g1x, g1y)
    }
}

impl ElemTraitExt for ElemU256 {
    fn mock() -> Self {
        ark_ff::BigInt::<4>::one()
    }
    fn hashed_output(&self) -> HashBytes {
        extern_bigint_to_nibbles(*self)
    }
}



impl ElemTraitExt for ElemFp6 {
    fn hashed_output(&self) -> HashBytes {
        let hash = extern_hash_fps(
            self.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
        );
        hash
    }

    fn mock() -> Self {
        let f = ark_bn254::Fq6::ONE;
        f
    }
}