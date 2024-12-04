use crate::chunk::primitves::extern_hash_nibbles;
use ark_bn254::{G1Affine, G2Affine};
use ark_ff::AdditiveGroup;
use super::primitves::extern_hash_fps;
use super::taps::HashBytes;

#[derive(Debug, Clone)]
pub(crate) enum Element {
    Fp12(ElemFp12Acc),
    G2Acc(ElemG2PointAcc),
    SparseEval(ElemSparseEval),
    FieldElem(ElemFq),
    ScalarElem(ElemFr),
    HashBytes(ElemHashBytes),
    MSM(ElemG1Point),
}

pub type ElemFq = ark_bn254::Fq;
pub type ElemFr = ark_bn254::Fr;
pub type ElemHashBytes = HashBytes;

#[derive(Debug, Clone)]
pub(crate) struct ElemFp12Acc {
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) hash: HashBytes,
}

impl ElemFp12Acc {
    pub(crate) fn out(&self) -> HashBytes {
         self.hash
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ElemG2PointAcc {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) dbl_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
    pub(crate) add_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
}

impl ElemG2PointAcc {
    pub(crate) fn out(&self) -> HashBytes {
        let hash_t = extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1], true);
        let hash_le = self.hash_le();
        let hash = extern_hash_nibbles(vec![hash_t, hash_le], true);
        hash
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

#[derive(Debug, Clone)]
pub(crate) struct ElemSparseEval {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: ark_bn254::G2Affine,
    pub(crate) f: ElemFp12Acc,
}

impl ElemSparseEval {
   pub(crate) fn out(&self) -> HashBytes {
        self.f.hash
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ElemG1Point {
    pub(crate) t: ark_bn254::G1Affine,
}

impl ElemG1Point {
    pub(crate) fn out(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x, self.t.y], true)
    }
}
