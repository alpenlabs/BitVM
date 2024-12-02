use crate::chunk::primitves::extern_hash_nibbles;
use ark_bn254::{G1Affine, G2Affine};
use super::msm::HintOutMSM;
use super::primitves::extern_hash_fps;
use super::taps::HashBytes;

#[derive(Debug, Clone)]
pub(crate) enum HintOut {
    Fp12(Fp12Acc),
    G2Acc(G2PointAcc),
    SparseEval(SparseEval),

    FieldElem(ark_bn254::Fq),
    ScalarElem(ark_bn254::Fr),
    HashBytes(HashBytes),

    MSM(HintOutMSM),
}



pub(crate) struct HintInDouble {
    pub(crate) t: G2PointAcc,
    pub(crate) p: ark_bn254::G1Affine,
}

impl HintInDouble {
    pub(crate) fn from_g2point(g: G2PointAcc, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        HintInDouble {
            t: g,
            p: ark_bn254::G1Affine::new_unchecked(gpx, gpy)
        }
    }
}


// POINT ADD
#[derive(Debug, Clone)]
pub(crate) struct HintInAdd {
    pub(crate) t: G2PointAcc,
    pub(crate) p: ark_bn254::G1Affine,
    pub(crate) q: ark_bn254::G2Affine,
}

impl HintInAdd {
    pub(crate) fn from_g2point(
        g: G2PointAcc,
        gp: ark_bn254::G1Affine,
        q: ark_bn254::G2Affine,
    ) -> Self {
        HintInAdd {
            t: g,
            p: gp,
            q,
        }
    }
}

pub(crate) struct HintInSparseEvals {
    pub(crate) p2x: ark_bn254::Fq,
    pub(crate) p2y: ark_bn254::Fq,
    pub(crate) p3x: ark_bn254::Fq,
    pub(crate) p3y: ark_bn254::Fq,

    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: ark_bn254::G2Affine,
    pub(crate) q2: Option<ark_bn254::G2Affine>,
    pub(crate) q3: Option<ark_bn254::G2Affine>,
}

impl HintInSparseEvals {
    pub(crate) fn from_groth_and_aux(
        p2: ark_bn254::G1Affine,
        p3: ark_bn254::G1Affine,
        t2: ark_bn254::G2Affine,
        t3: ark_bn254::G2Affine,
        q2: Option<ark_bn254::G2Affine>,
        q3: Option<ark_bn254::G2Affine>,
    ) -> Self {
        Self {
            t2,
            t3,
            p2x: p2.x,
            p2y: p2.y,
            p3x: p3.x,
            p3y: p3.y,
            q2,
            q3,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SparseEval {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: ark_bn254::G2Affine,
    pub(crate) f: Fp12Acc,
}

impl SparseEval {
   pub(crate) fn out(&self) -> HashBytes {
        self.f.hash
    }
}

// PREMILLER



pub(crate) struct HintInHashP { // r (gp3) = t(msm) + q(vk0)
    pub(crate) rx: ark_bn254::Fq,
    pub(crate) ry: ark_bn254::Fq,
    pub(crate) tx: ark_bn254::Fq,
    pub(crate) ty: ark_bn254::Fq,
    pub(crate) q: ark_bn254::G1Affine,
}


pub(crate) struct HintInHashC {
    pub(crate) c: ark_bn254::Fq12,
    pub(crate) hash: HashBytes,
}
impl HintInHashC {
    pub(crate) fn from_fp12(g: Fp12Acc) -> Self {
        HintInHashC {
            c: g.f,
            hash: g.hash,
        }
    }

    pub(crate) fn from_fp12_vec(gs: Vec<ark_bn254::Fq>) -> Self {
        let hash = extern_hash_fps(gs.clone(), false);
        HintInHashC {
            c: ark_bn254::Fq12::new(
                ark_bn254::Fq6::new(
                    ark_bn254::Fq2::new(gs[11], gs[10]),
                    ark_bn254::Fq2::new(gs[9], gs[8]),
                    ark_bn254::Fq2::new(gs[7], gs[6]),
                ),
                ark_bn254::Fq6::new(
                    ark_bn254::Fq2::new(gs[5], gs[4]),
                    ark_bn254::Fq2::new(gs[3], gs[2]),
                    ark_bn254::Fq2::new(gs[1], gs[0]),
                ),
            ),
            hash,
        }
    }
}

pub(crate) struct HintInPrecomputePy {
    pub(crate) p: ark_bn254::Fq,
}

impl HintInPrecomputePy {
    pub(crate) fn from_point(g: ark_bn254::Fq) -> Self {
        Self { p: g }
    }
}

pub(crate) struct HintInPrecomputePx {
    pub(crate) px: ark_bn254::Fq,
    pub(crate) py: ark_bn254::Fq,
}

impl HintInPrecomputePx {
    pub(crate) fn from_points(v: Vec<ark_bn254::Fq>) -> Self {
        Self {
            px: v[1],
            py: v[0],
        }
    }
}


pub(crate) struct HintInInitT4 {
    pub(crate) q4y1: ark_bn254::Fq,
    pub(crate) q4y0: ark_bn254::Fq,
    pub(crate) q4x1: ark_bn254::Fq,
    pub(crate) q4x0: ark_bn254::Fq,
}

impl HintInInitT4 {
    pub(crate) fn from_groth_q4(cs: Vec<ark_bn254::Fq>) -> Self {
        assert_eq!(cs.len(), 4);
        //Q4y1,Q4y0,Q4x1,Q4x0
        Self { q4y1: cs[0], q4y0: cs[1], q4x1: cs[2], q4x0: cs[3] }

    }
}

pub(crate) struct HintInFrobFp12 {
    pub(crate) f: ark_bn254::Fq12,
}

impl HintInFrobFp12 {
    pub(crate) fn from_fp12(g: Fp12Acc) -> Self {
        Self { f: g.f }
    }
}


pub(crate) struct HintInSparseDenseMul {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) le0: ark_bn254::Fq2,
    pub(crate) le1: ark_bn254::Fq2,
    pub(crate) hash_other_le: HashBytes,
    pub(crate) hash_aux_t: HashBytes,
}

impl HintInSparseDenseMul {
    pub(crate) fn from_double_add_top(g: G2PointAcc, sq: Fp12Acc) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let mut hash_other_le = [0u8; 64];
        if g.add_le.is_some() {
            let (add_le0, add_le1) = g.add_le.unwrap();
            hash_other_le =
                extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        }
        return HintInSparseDenseMul {
            a: sq.f,
            le0: g.dbl_le.unwrap().0,
            le1: g.dbl_le.unwrap().1,
            hash_other_le,
            hash_aux_t: hash_t,
        };
    }

    pub(crate) fn from_add(g: G2PointAcc, dmul: Fp12Acc) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let mut hash_other_le = [0u8; 64];
        if g.dbl_le.is_some() {
            let (dbl_le0, dbl_le1) = g.dbl_le.unwrap();
            hash_other_le = extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        }
        return HintInSparseDenseMul {
            a: dmul.f,
            le0: g.add_le.unwrap().0,
            le1: g.add_le.unwrap().1,
            hash_other_le,
            hash_aux_t: hash_t,
        };
    }
}


pub(crate) struct HintInDenseMul0 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
}

impl HintInDenseMul0 {
    pub(crate) fn from_fp12_le(c: Fp12Acc, d: SparseEval) -> Self {
        Self { a: c.f, b: d.f.f }
    }
    pub(crate) fn from_fp12_fp12(c: Fp12Acc, d: Fp12Acc) -> Self {
        Self { a: c.f, b: d.f }
    }
}

pub(crate) struct HintInDenseMul1 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
    // hash_aux_c0: HashBytes,
}

impl HintInDenseMul1 {
    pub(crate) fn from_fp12_le(c: Fp12Acc, d: SparseEval) -> Self {
        Self { a: c.f, b: d.f.f }
    }
    pub(crate) fn from_fp12_fp12(c: Fp12Acc, d: Fp12Acc) -> Self {
        Self { a: c.f, b: d.f }
    }
}

pub(crate) struct HintInSquaring {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) ahash: HashBytes,
}

impl HintInSquaring {
    pub(crate) fn from_fp12(g: Fp12Acc) -> Self {
        HintInSquaring {
            a: g.f,
            ahash: g.hash,
        }
    }
}


#[derive(Debug, Clone)]
pub(crate) struct Fp12Acc {
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) hash: HashBytes,
}

impl Fp12Acc {
    pub(crate) fn out(&self) -> HashBytes {
         self.hash
    }

    pub(crate) fn from_fp12_vec(gs: Vec<ark_bn254::Fq>) -> Self {
        let hash = extern_hash_fps(gs.clone(), false);
        let c = 
            ark_bn254::Fq12::new(
                ark_bn254::Fq6::new(
                    ark_bn254::Fq2::new(gs[11], gs[10]),
                    ark_bn254::Fq2::new(gs[9], gs[8]),
                    ark_bn254::Fq2::new(gs[7], gs[6]),
                ),
                ark_bn254::Fq6::new(
                    ark_bn254::Fq2::new(gs[5], gs[4]),
                    ark_bn254::Fq2::new(gs[3], gs[2]),
                    ark_bn254::Fq2::new(gs[1], gs[0]),
                ),
            );
        Fp12Acc { f: c, hash }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct G2PointAcc {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) dbl_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
    pub(crate) add_le: Option<(ark_bn254::Fq2, ark_bn254::Fq2)>,
}

impl G2PointAcc {
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


    pub(crate) fn hash_t(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1], true)
    }

    pub(crate) fn hash_other_le(&self, dbl: bool) -> [u8; 64] {
        if (dbl && self.add_le.is_none()) || (!dbl && self.dbl_le.is_none()) {
            return [0u8; 64];
        }
        let mut le = self.dbl_le.unwrap();
        if dbl {
            le = self.add_le.unwrap();
        }
        let (le0, le1) = le;
        let le = extern_hash_fps(vec![le0.c0, le0.c1, le1.c0, le1.c1], true);
        le
    }
}

pub(crate) struct HintInDenseMulByHash1 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) bhash: HashBytes,
}

pub(crate) struct HintInDenseMulByHash0 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) bhash: HashBytes,
}