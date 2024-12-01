use crate::chunk::primitves::extern_hash_nibbles;
use ark_bn254::{G1Affine, G2Affine};
use super::msm::HintOutMSM;
use super::primitves::extern_hash_fps;
use super::taps::HashBytes;

#[derive(Debug, Clone)]
pub(crate) enum HintOut {
    Squaring(HintOutFp12),
    Double(HintOutDouble),
    DblAdd(HintOutDblAdd),
    SparseDbl(HintOutSparseDbl),
    SparseAdd(HintOutSparseAdd),
    SparseDenseMul(HintOutFp12),
    DenseMul0(HintOutFp12),
    DenseMul1(HintOutFp12),

    FieldElem(ark_bn254::Fq),
    ScalarElem(ark_bn254::Fr),
    GrothC(HintOutFp12), // c, s, cinv
    HashC(HintOutFp12),
    InitT4(HintOutInitT4),
    HashBytes(HashBytes),

    FrobFp12(HintOutFp12),
    Add(HintOutAdd),

    MSM(HintOutMSM),
}



pub(crate) struct HintInDouble {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) p: ark_bn254::G1Affine,
    pub(crate) hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

impl HintInDouble {
    pub(crate) fn from_initT4(it: HintOutInitT4, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        HintInDouble {
            t: it.t4,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: it.hash_le_aux,
        }
    }
    pub(crate) fn from_double(g: HintOutDouble, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInDouble {
            t: g.t,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: hash_le,
        }
    }

    pub(crate) fn from_doubleadd(g: HintOutDblAdd, gpx: ark_bn254::Fq, gpy: ark_bn254::Fq) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInDouble {
            t: g.t,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: hash_le,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDouble {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) dbl_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    pub(crate) hash_add_le_aux: HashBytes,
    pub(crate) hash_out: HashBytes,
}

impl HintOutDouble {
    pub(crate) fn out(&self) -> HashBytes {
        self.hash_out
    }
}


// POINT ADD
#[derive(Debug, Clone)]
pub(crate) struct HintInAdd {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) p: ark_bn254::G1Affine,
    pub(crate) q: ark_bn254::G2Affine,
    pub(crate) hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

impl HintInAdd {
    pub(crate) fn from_double(
        g: HintOutDouble,
        gpx: ark_bn254::Fq,
        gpy: ark_bn254::Fq,
        q: ark_bn254::G2Affine,
    ) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInAdd {
            t: g.t,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: hash_le,
            q,
        }
    }

    pub(crate) fn from_add(
        g: HintOutAdd,
        gpx: ark_bn254::Fq,
        gpy: ark_bn254::Fq,
        q: ark_bn254::G2Affine,
    ) -> Self {
        let (add_le0, add_le1) = g.add_le;
        let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_dbl_le = g.hash_dbl_le_aux;
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInAdd {
            t: g.t,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: hash_le,
            q,
        }
    }

    pub(crate) fn from_doubleadd(
        g: HintOutDblAdd,
        gpx: ark_bn254::Fq,
        gpy: ark_bn254::Fq,
        q: ark_bn254::G2Affine,
    ) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInAdd {
            t: g.t,
            p: G1Affine::new_unchecked(gpx, gpy),
            hash_le_aux: hash_le,
            q,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutAdd {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) add_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    pub(crate) hash_dbl_le_aux: HashBytes,
    pub(crate) hash_out: HashBytes,
}

impl HintOutAdd {
   pub(crate) fn out(&self) -> HashBytes {
        self.hash_out
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintInDblAdd {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) p: ark_bn254::G1Affine,
    pub(crate) q: ark_bn254::G2Affine,
    pub(crate) hash_le_aux: HashBytes,
    //hash_in: HashBytes, // in = Hash([Hash(T), Hash_le_aux])
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutDblAdd {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) dbl_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    pub(crate) add_le: (ark_bn254::Fq2, ark_bn254::Fq2),
    pub(crate) hash: HashBytes,
}

impl HintInDblAdd {
    pub(crate) fn from_initT4(
        it: HintOutInitT4,
        gp: ark_bn254::G1Affine,
        gq: ark_bn254::G2Affine,
    ) -> Self {
        HintInDblAdd {
            t: it.t4,
            p: gp,
            hash_le_aux: it.hash_le_aux,
            q: gq,
        }
    }
    pub(crate) fn from_double(
        g: HintOutDouble,
        gp: ark_bn254::G1Affine,
        gq: ark_bn254::G2Affine,
    ) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le = g.hash_add_le_aux;
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInDblAdd {
            t: g.t,
            p: gp,
            hash_le_aux: hash_le,
            q: gq,
        }
    }

    pub(crate) fn from_doubleadd(
        g: HintOutDblAdd,
        gp: ark_bn254::G1Affine,
        gq: ark_bn254::G2Affine,
    ) -> Self {
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let (add_le0, add_le1) = g.add_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        let hash_le = extern_hash_nibbles(vec![hash_dbl_le, hash_add_le], true);
        HintInDblAdd {
            t: g.t,
            p: gp,
            hash_le_aux: hash_le,
            q: gq,
        }
    }
}

impl HintOutDblAdd {
   pub(crate) fn out(&self) -> HashBytes {
        self.hash
    }
}

pub(crate) struct HintInSparseDbl {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine,
    pub(crate) p2: G1Affine,
    pub(crate) p3: G1Affine,
}

impl HintInSparseDbl {
    pub(crate) fn from_groth_and_aux(
        p2: ark_bn254::G1Affine,
        p3: ark_bn254::G1Affine,
        aux_t2: ark_bn254::G2Affine,
        aux_t3: ark_bn254::G2Affine,
    ) -> Self {
        Self {
            t2: aux_t2,
            t3: aux_t3,
            p2,
            p3,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HintOutSparseDbl {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine,
    pub(crate) f: HintOutFp12,
}

impl HintOutSparseDbl {
   pub(crate) fn out(&self) -> HashBytes {
        self.f.hash
    }
}
pub(crate) struct HintInSparseAdd {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine,
    pub(crate) p2: G1Affine,
    pub(crate) p3: G1Affine,
    pub(crate) q2: ark_bn254::G2Affine,
    pub(crate) q3: G2Affine,
}

impl HintInSparseAdd {
    pub(crate) fn from_groth_and_aux(
        p2: ark_bn254::G1Affine,
        p3: ark_bn254::G1Affine,
        pub_q2: ark_bn254::G2Affine,
        pub_q3: ark_bn254::G2Affine,
        aux_t2: ark_bn254::G2Affine,
        aux_t3: ark_bn254::G2Affine,
    ) -> Self {
        Self {
            t2: aux_t2,
            t3: aux_t3,
            p2,
            p3,
            q2: pub_q2,
            q3: pub_q3,
        }
    }
}
#[derive(Debug, Clone)]

pub(crate) struct HintOutSparseAdd {
    pub(crate) t2: ark_bn254::G2Affine,
    pub(crate) t3: G2Affine,
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) fhash: HashBytes,
}

impl HintOutSparseAdd {
   pub(crate) fn out(&self) -> HashBytes {
        self.fhash
    }
}


// PREMILLER

pub(crate) struct HintInHashC {
    pub(crate) c: ark_bn254::Fq12,
    pub(crate) hashc: HashBytes,
}

pub(crate) struct HintInHashP { // r (gp3) = t(msm) + q(vk0)
    pub(crate) rx: ark_bn254::Fq,
    pub(crate) ry: ark_bn254::Fq,
    pub(crate) tx: ark_bn254::Fq,
    pub(crate) qx: ark_bn254::Fq,
    pub(crate) ty: ark_bn254::Fq,
    pub(crate) qy: ark_bn254::Fq,
}


impl HintInHashC {
    pub(crate) fn from_hashc(g: HintOutFp12) -> Self {
        HintInHashC {
            c: g.f,
            hashc: g.hash,
        }
    }
    pub(crate) fn from_grothc(g: HintOutFp12) -> Self {
        HintInHashC {
            c: g.f,
            hashc: g.hash,
        }
    }
    pub(crate) fn from_points(gs: Vec<ark_bn254::Fq>) -> Self {
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
            hashc: hash,
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
    pub(crate) p: G1Affine,
}

impl HintInPrecomputePx {
    pub(crate) fn from_points(v: Vec<ark_bn254::Fq>) -> Self {
        // GP3y,GP3x,P3y
        Self {
            p: ark_bn254::G1Affine::new_unchecked(v[1], v[0]),
        }
    }
}


pub(crate) struct HintInInitT4 {
    pub(crate) t4: ark_bn254::G2Affine,
}

impl HintInInitT4 {
    pub(crate) fn from_groth_q4(cs: Vec<ark_bn254::Fq>) -> Self {
        assert_eq!(cs.len(), 4);
        //Q4y1,Q4y0,Q4x1,Q4x0
        Self {
            t4: ark_bn254::G2Affine::new_unchecked(
                ark_bn254::Fq2::new(cs[3], cs[2]),
                ark_bn254::Fq2::new(cs[1], cs[0]),
            ),
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct HintOutInitT4 {
    pub(crate) t4: ark_bn254::G2Affine,
    pub(crate) t4hash: [u8; 64],
    pub(crate) hash_le_aux: HashBytes,
}

impl HintOutInitT4 {
   pub(crate) fn out(&self) -> HashBytes {
        self.t4hash
    }
}

pub(crate) struct HintInFrobFp12 {
    pub(crate) f: ark_bn254::Fq12,
}

impl HintInFrobFp12 {
    pub(crate) fn from_groth_c(g: HintOutFp12) -> Self {
        Self { f: g.f }
    }
    pub(crate) fn from_hash_c(g: HintOutFp12) -> Self {
        Self { f: g.f }
    }
}


pub(crate) struct HintInSparseDenseMul {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) le0: ark_bn254::Fq2,
    pub(crate) le1: ark_bn254::Fq2,
    pub(crate) hash_other_le: HashBytes,
    pub(crate) hash_aux_T: HashBytes,
}

impl HintInSparseDenseMul {
    pub(crate) fn from_double(g: HintOutDouble, sq: HintOutFp12) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        HintInSparseDenseMul {
            a: sq.f,
            le0: g.dbl_le.0,
            le1: g.dbl_le.1,
            hash_other_le: g.hash_add_le_aux,
            hash_aux_T: hash_t,
        }
    }

    pub(crate) fn from_double_add_top(g: HintOutDblAdd, sq: HintOutFp12) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let (add_le0, add_le1) = g.add_le;
        let hash_add_le =
            extern_hash_fps(vec![add_le0.c0, add_le0.c1, add_le1.c0, add_le1.c1], true);
        return HintInSparseDenseMul {
            a: sq.f,
            le0: g.dbl_le.0,
            le1: g.dbl_le.1,
            hash_other_le: hash_add_le,
            hash_aux_T: hash_t,
        };
    }

    pub(crate) fn from_doubl_add_bottom(g: HintOutDblAdd, dmul: HintOutFp12) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        let (dbl_le0, dbl_le1) = g.dbl_le;
        let hash_dbl_le =
            extern_hash_fps(vec![dbl_le0.c0, dbl_le0.c1, dbl_le1.c0, dbl_le1.c1], true);
        return HintInSparseDenseMul {
            a: dmul.f,
            le0: g.add_le.0,
            le1: g.add_le.1,
            hash_other_le: hash_dbl_le,
            hash_aux_T: hash_t,
        };
    }
    pub(crate) fn from_add(g: HintOutAdd, sq: HintOutFp12) -> Self {
        let t = g.t;
        let hash_t = extern_hash_fps(vec![t.x.c0, t.x.c1, t.y.c0, t.y.c1], true);
        HintInSparseDenseMul {
            a: sq.f,
            le0: g.add_le.0,
            le1: g.add_le.1,
            hash_other_le: g.hash_dbl_le_aux,
            hash_aux_T: hash_t,
        }
    }
}


pub(crate) struct HintInDenseMul0 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
}

impl HintInDenseMul0 {
    pub(crate) fn from_groth_hc(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_grothc(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_sparse_dense_dbl(c: HintOutFp12, d: HintOutSparseDbl) -> Self {
        Self { a: c.f, b: d.f.f }
    }
    pub(crate) fn from_sparse_dense_add(c: HintOutFp12, d: HintOutSparseAdd) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_dense_c(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_hash_c(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    // pub(crate) fn from_dense_fixed_acc(c: HintOutDenseMul1, d: HintOutFixedAcc) -> Self {
    //     Self { a: c.c, b: d.f }
    // }
    pub(crate) fn from_dense_frob(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
}

pub(crate) struct HintInDenseMul1 {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) b: ark_bn254::Fq12,
    // hash_aux_c0: HashBytes,
}

impl HintInDenseMul1 {
    pub(crate) fn from_groth_hc(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_grothc(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_sparse_dense_dbl(c: HintOutFp12, d: HintOutSparseDbl) -> Self {
        Self { a: c.f, b: d.f.f }
    }
    pub(crate) fn from_sparse_dense_add(c: HintOutFp12, d: HintOutSparseAdd) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_dense_c(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    // pub(crate) fn from_dense_fixed_acc(c: HintOutDenseMul1, d: HintOutFixedAcc) -> Self {
    //     Self { a: c.c, b: d.f }
    // }
    pub(crate) fn from_dense_frob(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
    pub(crate) fn from_hash_c(c: HintOutFp12, d: HintOutFp12) -> Self {
        Self { a: c.f, b: d.f }
    }
}

pub(crate) struct HintInSquaring {
    pub(crate) a: ark_bn254::Fq12,
    pub(crate) ahash: HashBytes,
}

impl HintInSquaring {
    pub(crate) fn from_hashc(g: HintOutFp12) -> Self {
        HintInSquaring {
            a: g.f,
            ahash: g.hash,
        }
    }
    pub(crate) fn from_dmul1(g: HintOutFp12) -> Self {
        HintInSquaring {
            a: g.f,
            ahash: g.hash,
        }
    }
}


#[derive(Debug, Clone)]
pub(crate) struct HintOutFp12 {
    pub(crate) f: ark_bn254::Fq12,
    pub(crate) hash: HashBytes,
}

impl HintOutFp12 {
    pub(crate) fn out(&self) -> HashBytes {
         self.hash
     }
 }