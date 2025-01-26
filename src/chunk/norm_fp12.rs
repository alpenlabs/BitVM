use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;
use core::ops::Neg;
use std::str::FromStr;
use ark_ec::{bn::BnConfig,  CurveGroup};


// p1 should have been precomputed
pub fn multi_miller_loop_affine_norm(ps: Vec<ark_bn254::G1Affine>, qs: Vec<ark_bn254::G2Affine>, gc: ark_bn254::Fq12, s: ark_bn254::Fq12) -> ark_bn254::fq12::Fq12 {
    let beta_12x = BigUint::from_str(
        "21575463638280843010398324269430826099269044274347216827212613867836435027261",
    )
    .unwrap();
    let beta_12y = BigUint::from_str(
        "10307601595873709700152284273816112264069230130616436755625194854815875713954",
    )
    .unwrap();
    let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_12x.clone()),
        ark_bn254::Fq::from(beta_12y.clone()),
    ])
    .unwrap();
    let beta_13x = BigUint::from_str(
        "2821565182194536844548159561693502659359617185244120367078079554186484126554",
    )
    .unwrap();
    let beta_13y = BigUint::from_str(
        "3505843767911556378687030309984248845540243509899259641013678093033130930403",
    )
    .unwrap();
    let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_13x.clone()),
        ark_bn254::Fq::from(beta_13y.clone()),
    ])
    .unwrap();
    let beta_22x = BigUint::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
        ark_bn254::Fq::from(beta_22x.clone()),
        ark_bn254::Fq::from(beta_22y.clone()),
    ])
    .unwrap();

    let mut cinv = gc.inverse().unwrap();
    cinv = ark_bn254::Fq12::new(cinv.c0/cinv.c1, ark_bn254::Fq6::ONE);
    let mut c =  gc.clone();
    c = ark_bn254::Fq12::new(c.c0/c.c1, ark_bn254::Fq6::ONE);
    
    // let mut f = ark_bn254::Fq12::ONE;
    let mut f = cinv.clone();
    
    let mut ts = qs.clone();
    let ps: Vec<ark_bn254::G1Affine> = ps.iter().map(|p1|ark_bn254::G1Affine::new_unchecked(-p1.x/p1.y, p1.y.inverse().unwrap())).collect();
    let num_pairings = ps.len();
    for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
        // square
        f = f * f;
        if f.c1 != ark_bn254::Fq6::ZERO {
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
        }
        // f = f * f;
        // f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);


        // double and eval
        for i in 0..num_pairings {
            let t = ts[i].clone();
            let p = ps[i].clone();
            let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f = f * le;
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    
            ts[i] = (t + t).into_affine();
        }



        if ate_bit == 1 || ate_bit == -1 {
            let c_or_cinv = if ate_bit == -1 { c.clone() } else { cinv.clone() };
            f = f * c_or_cinv;
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

            for i in 0..num_pairings {
                let t = ts[i].clone();
                let mut q = qs[i].clone();
                let p = ps[i].clone();

                if ate_bit == -1 {
                    q = q.neg();
                };
                let alpha = (t.y - q.y) / (t.x - q.x);
                let neg_bias = alpha * t.x - t.y;
    
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x);
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y);
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;
    
                f = f * le;
                f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

                ts[i] = (t + q).into_affine();
            }
        }

    }
    let cinv_q = cinv.frobenius_map(1);
    let c_q2 = c.frobenius_map(2);
    let cinv_q3 = cinv.frobenius_map(3);

    for mut cq in vec![cinv_q, c_q2, cinv_q3] {
        cq = ark_bn254::Fq12::new(cq.c0/cq.c1, ark_bn254::Fq6::ONE); 
        f = f * cq;
        f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    }

    f = f * s;
    f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);

    for i in 0..num_pairings {
        let mut q = qs[i].clone();
        let t = ts[i].clone();
        let p = ps[i].clone();
        
        q.x.conjugate_in_place();
        q.x = q.x * beta_12;
        q.y.conjugate_in_place();
        q.y = q.y * beta_13;
        let alpha = (t.y - q.y) / (t.x - q.x);
        let neg_bias = alpha * t.x - t.y;
        let mut le0 = alpha;
        le0.mul_assign_by_fp(&p.x);
        let mut le1 = neg_bias;
        le1.mul_assign_by_fp(&p.y);
        let mut le = ark_bn254::Fq12::ZERO;
        le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
        le.c1.c0 = le0;
        le.c1.c1 = le1;
    
        f = f * le;
        f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
    
        ts[i] = (t + q).into_affine();
    }


    // t + q^3
    for i in 0..num_pairings {
        let mut q = qs[i].clone();
        let t = ts[i].clone();
        let p = ps[i].clone();

        q.x = q.x * beta_22;
    
        let alpha = (t.y - q.y) / (t.x - q.x);
        let neg_bias = alpha * t.x - t.y;
        let mut le0 = alpha;
        le0.mul_assign_by_fp(&p.x);
        let mut le1 = neg_bias;
        le1.mul_assign_by_fp(&p.y);
        let mut le = ark_bn254::Fq12::ZERO;
        le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
        le.c1.c0 = le0;
        le.c1.c1 = le1;
    
        f = f * le;
        if f.c1 != ark_bn254::Fq6::ZERO {
            f = ark_bn254::Fq12::new(f.c0/f.c1, ark_bn254::Fq6::ONE);
        }
        ts[i] = (t + q).into_affine();
    }
    f
}
