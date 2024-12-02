
use crate::treepp;

use super::hint_models::HintOut;

#[derive(Debug, Clone)]
pub struct Segment {
    pub id: usize,
    pub input: Vec<Segment>,   
    pub output: (HintOut, treepp::Script, bool),
    pub hints: treepp::Script,
    pub scr_type: ScriptType
}

#[derive(Debug, Clone, Copy)]
enum ScriptType {
    PreMillerInitT4,
    PreMillerPrecomputePy,
    PreMillerPrecomputePx,
    PreMillerHashC,
    PreMillerHashC2,
    PreMillerDenseDenseMulByHash0,
    PreMillerDenseDenseMulByHash1,
    PreMillerHashP,

    MillerSquaring,
    MillerDoubleAdd(u8),
    MillerDouble,
    MillerSparseDense,
    MillerSparseSparseDbl((ark_bn254::G2Affine, ark_bn254::G2Affine)),
    MillerDenseDenseMul0(bool),
    MillerDenseDenseMul1(bool),
    MillerSparseSparseAdd(([ark_bn254::G2Affine;4], i8)),

    PostMillerFrobFp12(u8),
    PostMillerDenseDenseMul0(bool),
    PostMillerDenseDenseMul1(bool),
    PostMillerAddWithFrob(i8),
    PostMillerSparseDenseMul,
    PostMillerSparseAddWithFrob(([ark_bn254::G2Affine;4], i8)),
    PostMillerDenseDenseMulByK0((bool, ark_bn254::Fq12)),
    PostMillerDenseDenseMulByK1((bool, ark_bn254::Fq12)),
}