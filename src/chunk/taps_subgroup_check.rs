use ark_ff::AdditiveGroup;
use bitcoin::opcodes::all::{OP_ELSE, OP_ENDIF};
use bitcoin_script::script;

use crate::{bn254::{curves::G2Affine, fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, g2_subgroup_check, utils::fq2_push_not_montgomery}, chunk::primitves::hash_fp4, treepp};

use super::hint_models::{ElemFq, ElemG2Point};
use crate::chunk::hint_models::ElemTraitExt;

fn tap_g2_subgroup_check_msm(
    ith_index: usize,
    msm_script: treepp::Script,
) -> treepp::Script {

    let ops_scr = script!(
        if ith_index == 0 {
            { fq2_push_not_montgomery(ark_bn254::Fq2::ZERO) }
            { fq2_push_not_montgomery(ark_bn254::Fq2::ZERO) }
            // [t]
            {Fq2::fromaltstack()} {Fq2::fromaltstack()} // bitcommitted q
            // [t, q]
            {msm_script}
            // [nt]
        } else {
            {G2Affine::copy(0)}
            // [t, t]
            {Fq2::fromaltstack()} {Fq2::fromaltstack()} // bitcommitted q
            // [t, t, q]
            {msm_script}
            // [t, nt]
        }

    );

    let hash_scr = if ith_index == 0 {
        script!(
            // [nt] / [nt_hash]
            {hash_fp4()}
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)}
            OP_NOT OP_VERIFY
        )  
    } else {
        script!(
            // [t, nt] / [nt_hash, thash]
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            {hash_fp4()}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            // [thash, nt] / [nt_hash, thash]
            {Fq::roll(4)} {Fq::toaltstack()}
            {hash_fp4()} {Fq::fromaltstack()}
            // [nthash, thash] / [nt_hash, thash]
            {Fq::fromaltstack()}  {Fq::fromaltstack()}
            // [nthash, thash, thash, nthash]
            {Fq::equalverify(2, 1)}
            {Fq::equal(1, 0)}
            OP_NOT OP_VERIFY
        )  
    };

    let scr = script!(
        {ops_scr}
        {hash_scr}
        OP_TRUE
    );

    scr
}


fn tap_g2_subgroup_check_endomorphism(endo_script: treepp::Script) -> treepp::Script {
    let ops_scr = script!(
        // [t]
        {G2Affine::copy(0)}
        // [t, t]
        {endo_script}
        // [t, nt]
    );
    let hash_scr =         
        script!(
            // [t, nt] / [nt_hash, thash]
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            {hash_fp4()}
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}
            // [thash, nt] / [nt_hash, thash]
            {Fq::roll(4)} {Fq::toaltstack()}
            {hash_fp4()} {Fq::fromaltstack()}
            // [nthash, thash] / [nt_hash, thash]
            {Fq::fromaltstack()}  {Fq::fromaltstack()}
            // [nthash, thash, thash, nthash]
            {Fq::equalverify(2, 1)}
            {Fq::equal(1, 0)}
            OP_NOT OP_VERIFY
        );
    let scr = script!(
        {ops_scr}
        {hash_scr}
        OP_TRUE
    );
    scr
}


fn tap_g2_subgroup_check_equality(equality_script: treepp::Script) -> treepp::Script {
    let ops_scr = script!(
        // [t, msm]
        {G2Affine::copy(1)}
        {G2Affine::copy(1)}
        // [t, msm, t, msm]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} // bitcommitted q
        // [t, msm, t, msm, q]
        {equality_script}
        // [t, msm, t, msm, nt]
    );
    let hash_scr =         
        script!(
            // [t, msm, nt] / [nthash, thash, msmhash]
            {G2Affine::toaltstack()} {G2Affine::toaltstack()}
            {hash_fp4()}
            {G2Affine::fromaltstack()} 
            // [thash, msm] / [nthash, thash, msmhash, nt]
            {Fq::roll(4)} {Fq::toaltstack()}
            // [msm] / [thash, msmhash, nt, thash]
            {hash_fp4()} {Fq::fromaltstack()}
            // [msmhash, thash] / [nthash, thash, msmhash, nt]
            {G2Affine::fromaltstack()}
            {Fq::fromaltstack()}  {Fq::fromaltstack()} {Fq::fromaltstack()}
            
            // [msmhash, thash, nt, msmhash, thash, nthash]
            {Fq::equalverify(1, 7)}
            // [msmhash, nt, msmhash, nthash]
            {Fq::equalverify(1, 6)}
            // [nt, nthash]
            {Fq::roll(4)} {Fq::roll(4)} {Fq::roll(4)} {Fq::roll(4)}
            {G2Affine::toaltstack()}  {Fq::toaltstack()} 

            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
            {hash_fp4()}
            {Fq::fromaltstack()}
            // [zerohash, nthash] [t]
            {Fq::equal(1, 0)}
            OP_IF 
                {G2Affine::fromaltstack()} // calc nt
                {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)} // claimed nt
                {fq2_push_not_montgomery(ark_bn254::Fq2::ZERO)}
                // [nt, zero]
                {G2Affine::equal()}
                OP_NOT OP_VERIFY
            OP_ELSE
                {G2Affine::fromaltstack()}
                {G2Affine::drop()}
            OP_ENDIF
        );
    let scr = script!(
        {ops_scr}
        {hash_scr}
        OP_TRUE
    );
    scr
}

fn hint_g2_subgroup_check(
    hint_q4y1: ElemFq,
    hint_q4y0: ElemFq,
    hint_q4x1: ElemFq,
    hint_q4x0: ElemFq,
    window: usize,
) -> Vec<(ElemG2Point, treepp::Script)>  {
    let q4x = ark_bn254::Fq2::new(hint_q4x0, hint_q4x1);
    let q4y = ark_bn254::Fq2::new(hint_q4y0, hint_q4y1);
    let q4 = ark_bn254::G2Affine::new_unchecked(q4x, q4y);

    let chunks = g2_subgroup_check::is_in_g2_subgroup(q4, window);
    let num_msm_chunks = chunks.len() - 2;

    let mut hint_outs = vec![];

    // MSM
    for i in 0..num_msm_chunks {
        let hint_script = script!(
            for hint in &chunks[i].2 {
                {hint.push()}
            }
            // t
            if i != 0 {
                {fq2_push_not_montgomery(chunks[i-1].0.x)}
                {fq2_push_not_montgomery(chunks[i-1].0.y)}
            }
        );
        let hout: ElemG2Point = (chunks[i].0.x, chunks[i].0.y);
        hint_outs.push((hout, hint_script));
    }

    // ENDO
    let hint_script = script!(
        for hint in &chunks[num_msm_chunks].2 {
            {hint.push()}
        }
        {fq2_push_not_montgomery(chunks[num_msm_chunks-1].0.x)}
        {fq2_push_not_montgomery(chunks[num_msm_chunks-1].0.y)}
    );
    let hout: ElemG2Point = (chunks[num_msm_chunks].0.x, chunks[num_msm_chunks].0.y);
    hint_outs.push((hout, hint_script));

    // EQUALITY
    let hint_script = script!(
        for hint in &chunks[num_msm_chunks+1].2 {
            {hint.push()}
        }
        {fq2_push_not_montgomery(chunks[num_msm_chunks].0.x)}
        {fq2_push_not_montgomery(chunks[num_msm_chunks].0.y)}
        {fq2_push_not_montgomery(chunks[num_msm_chunks-1].0.x)}
        {fq2_push_not_montgomery(chunks[num_msm_chunks-1].0.y)}
    );
    let hout: ElemG2Point = (chunks[num_msm_chunks+1].0.x, chunks[num_msm_chunks+1].0.y);
    hint_outs.push((hout, hint_script));

    hint_outs
}

fn tap_g2_subgroup_check(
    window: usize,
) -> Vec<treepp::Script> {
    let (q4x, q4y) = ElemG2Point::mock();
    let chunks = g2_subgroup_check::is_in_g2_subgroup(ark_bn254::G2Affine::new_unchecked(q4x, q4y), window);
    let num_msm_chunks = chunks.len() - 2;
    let mut scrs: Vec<treepp::Script> = vec![];
    for i in 0..num_msm_chunks {
        let scr = tap_g2_subgroup_check_msm(i, chunks[i].1.clone());
        scrs.push(scr);
    }

    let scr = tap_g2_subgroup_check_endomorphism(chunks[num_msm_chunks].1.clone());
    scrs.push(scr);

    let scr = tap_g2_subgroup_check_equality(chunks[num_msm_chunks+1].1.clone());
    scrs.push(scr);
    
    scrs
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, utils::fq_push_not_montgomery}, chunk::{hint_models::{ElemG2Point, ElemTraitExt}, primitves::extern_nibbles_to_limbs}, execute_script, execute_script_without_stack_limit, treepp};

    use super::{hint_g2_subgroup_check, tap_g2_subgroup_check};


    #[test]
    fn test_tap_g2_subgroup_check() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let window = 4;

        let hints = hint_g2_subgroup_check(q.y.c1, q.y.c0, q.x.c1, q.x.c0, window);
        let scripts = tap_g2_subgroup_check(window);

        assert_eq!(hints.len(), scripts.len());

        let num_msm_chunks = hints.len()-2;
        let mut prev_hash:[u8; 64] = [0u8; 64];

        println!("num_msm_chunks {:?}", num_msm_chunks);
        for i in 0..num_msm_chunks {
            let (hout, tmul_hints): (ElemG2Point, treepp::Script) = hints[i].clone();
            let hout_hash = hout.out();
            let bitcom_scr = script!(
                for i in extern_nibbles_to_limbs(hout_hash) {
                    {i}
                }
                {Fq::toaltstack()}
                if i != 0 {
                    for i in extern_nibbles_to_limbs(prev_hash) {
                        {i}
                    }
                    {Fq::toaltstack()}
                }
                {fq_push_not_montgomery(q.y.c1)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q.y.c0)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q.x.c1)}
                {Fq::toaltstack()}
                {fq_push_not_montgomery(q.x.c0)}
                {Fq::toaltstack()}
            );
            prev_hash = hout_hash;

            let tap_len = scripts[i].len();
            let script = script! {
                {tmul_hints}
                {bitcom_scr}
                {scripts[i].clone()}
            };

            let res = execute_script_without_stack_limit(script);
            assert!(!res.success && res.final_stack.len() == 1);
            println!("{} script {} stack {}",i, tap_len, res.stats.max_nb_stack_items);
        }

        // ENDO CHUNK
        let (hout, tmul_hints): (ElemG2Point, treepp::Script) = hints[num_msm_chunks].clone();
        let hout_hash = hout.out();
        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(hout_hash) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(prev_hash) {
                {i}
            }
            {Fq::toaltstack()}
        );

        let tap_len = scripts[num_msm_chunks].len();
        let script = script! {
            {tmul_hints}
            {bitcom_scr}
            {scripts[num_msm_chunks].clone()}
        };

        let res = execute_script_without_stack_limit(script);
        assert!(!res.success && res.final_stack.len() == 1);
        println!("{} script {} stack {}", num_msm_chunks, tap_len, res.stats.max_nb_stack_items);

        // FINAL CHUNK
        let (hout, tmul_hints): (ElemG2Point, treepp::Script) = hints[num_msm_chunks+1].clone();
        let final_hash = hout.out();
        let bitcom_scr = script!(
            for i in extern_nibbles_to_limbs(final_hash) { // final_out
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(hout_hash) { // endo_out
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(prev_hash) { // msm_out
                {i}
            }
            {Fq::toaltstack()}

            {fq_push_not_montgomery(q.y.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.y.c0)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c1)}
            {Fq::toaltstack()}
            {fq_push_not_montgomery(q.x.c0)}
            {Fq::toaltstack()}
        );

        let tap_len = scripts[num_msm_chunks+1].len();
        let script = script! {
            {tmul_hints}
            {bitcom_scr}
            {scripts[num_msm_chunks+1].clone()}
        };

        let res = execute_script_without_stack_limit(script);
        assert!(!res.success && res.final_stack.len() == 1);
        println!("{} script {} stack {}", num_msm_chunks+1, tap_len, res.stats.max_nb_stack_items);
        
    }
}