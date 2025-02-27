use super::fq2::Fq2;
use super::utils::Hint;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::{g1::G1Affine, fr::Fr};
use crate::treepp::*;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField};
use bitcoin::opcodes::all::{OP_DROP, OP_FROMALTSTACK, OP_TOALTSTACK};
use num_bigint::BigUint;

pub fn hinted_msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    println!("use hinted_msm_with_constant_bases_affine");
    assert_eq!(bases.len(), scalars.len());

    let mut hints = Vec::new();

    let mut trivial_bases = vec![];
    let mut msm_bases = vec![];
    let mut msm_scalars = vec![];
    let mut msm_acc = ark_bn254::G1Affine::identity();
    for (itr, s) in scalars.iter().enumerate() {
        if *s == ark_bn254::Fr::ONE {
            trivial_bases.push(bases[itr]);
        } else {
            msm_bases.push(bases[itr]);
            msm_scalars.push(*s);
            msm_acc = (msm_acc + (bases[itr] * *s).into_affine()).into_affine();
        }
    }    

    // parameters
    let mut window = 4;
    if msm_scalars.len() == 1 {
        window = 7;
    } else if msm_scalars.len() == 2 {
        window = 5;
    }

    // MSM
    let mut acc = ark_bn254::G1Affine::zero();
    let msm_chunks = G1Affine::hinted_scalar_mul_by_constant_g1(
        msm_scalars.clone(),
        msm_bases.clone(),
        window,
    );
    let msm_chunk_hints: Vec<Hint> = msm_chunks.iter().flat_map(|f| f.2.clone()).collect();
    let msm_chunk_scripts: Vec<Script> = msm_chunks.iter().map(|f| f.1.clone()).collect();
    let msm_chunk_results: Vec<ark_bn254::G1Affine> = msm_chunks.iter().map(|f| f.0).collect();
    hints.extend_from_slice(&msm_chunk_hints);

    acc = (acc + msm_acc).into_affine();

    // Additions
    let mut add_scripts = Vec::new();
    for i in 0..trivial_bases.len() {
        // check coeffs before using
        let (add_script, hint) =
            G1Affine::hinted_check_add(acc, trivial_bases[i]); // outer_coeffs[i - 1].1
        add_scripts.push(add_script);
        hints.extend(hint);
        acc = (acc + trivial_bases[i]).into_affine();
    }

    // Gather scripts
    let script = script! {
        for i in 0..msm_chunk_scripts.len() {
            // G1Acc preimage
            if i == 0 {
                {G1Affine::push( ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO))}
            } else {
                {G1Affine::push(msm_chunk_results[i-1])}
            }

            // Scalar_i: groth16 public inputs bitcommited input irl
            for msm_scalar in &msm_scalars {
                {Fr::push(*msm_scalar)}
            }
            // [ScalarDecomposition_0, ScalarDecomposition_1,.., ScalarDecomposition_i,    G1Acc, Scalar_0, Scalar_1,..Scalar_i, ]
            {msm_chunk_scripts[i].clone()}

            {G1Affine::push(msm_chunk_results[i])}
            {G1Affine::equalverify()}
        }
        {G1Affine::push(msm_chunk_results[msm_chunk_results.len()-1])}
        // tx, ty
        for i in 0..add_scripts.len() {
            {G1Affine::push(trivial_bases[i])}
            {add_scripts[i].clone()}
        }
    };
    //println!("msm is divided into {} chunks ", msm_scripts.len() + add_scripts.len());

    (script, hints)
    // into_affine involving extreem expensive field inversion, X/Z^2 and Y/Z^3, fortunately there's no need to do into_affine any more here
}



fn generate_lookup_tables(q: ark_bn254::G1Affine, window: usize) -> (Vec<Vec<ark_bn254::G1Affine>>, Vec<Script>) {
    let num_tables = (Fr::N_BITS as usize + window - 1)/window;
    let mut all_tables_scr = vec![];
    let mut all_tables = vec![];
    for i in 0..num_tables {
        let doubling_factor = BigUint::one() << (i * window);
        let doubled_base = (q * ark_bn254::Fr::from(doubling_factor)).into_affine();
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << window) {
            let entry = (*p_mul.last().unwrap() + doubled_base).into_affine();
            p_mul.push(entry);
        }
        let p_mul_scr = {G1Affine::dfs_with_constant_mul(0, window as u32 - 1, 0, &p_mul) };
        all_tables_scr.push(p_mul_scr);
        all_tables.push(p_mul);
    }
    (all_tables, all_tables_scr)
}

// given a scalar, split it into slices each of window bits and return the slice at "index"
// script takes scalar and returns slice
fn get_query_for_table_index(scalar: ark_bn254::Fr, window: usize, index: usize) -> (u32, Script) {

    pub fn fq_to_bits(fq: ark_ff::BigInt<4>, limb_size: usize) -> Vec<u32> {
        let mut bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).collect();
        bits.reverse();
        bits.chunks(limb_size)
            .map(|chunk| {
                let mut factor = 1;
                let res = chunk.iter().fold(0, |acc, &x| {
                    let r = acc + if x { factor } else { 0 };
                    factor *= 2;
                    r
                });
                res
            })
            .collect()
    }

    let chunks = fq_to_bits(scalar.into_bigint(), window);
    let elem = chunks[index];

    let scr = script!{
        {Fr::convert_to_le_bits_toaltstack()}
        {0}
        {0}
        for _ in 0..Fr::N_BITS {
            OP_FROMALTSTACK
        }
        for i in 0..256 {
            if i/window == index {
                OP_TOALTSTACK
            } else {
                OP_DROP
            }
        }
        for _ in 0..window {
            OP_FROMALTSTACK
        }
    };
    (elem, scr)
}


fn query_table(table: (Vec<ark_bn254::G1Affine>, Script), row_index: (usize, Script)) -> (ark_bn254::G1Affine, Script) {
    let row = table.0[row_index.0];
    let scr = script!{
        // [scalar]
        {row_index.1}
        // [scalar_slice[table_index]] = row_index.0
        {table.1}
        // row
    };
    (row, scr)
}

fn accumulate_rows(init_acc: ark_bn254::G1Affine, q: ark_bn254::G1Affine, fq: ark_bn254::Fr, window: usize) ->  Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> {
    let mut all_rows: Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> = vec![];

    let num_tables = (Fr::N_BITS as usize + window - 1)/window;   
    let tables = generate_lookup_tables(q, window);

    let mut prev = init_acc;    
    for table_index in 0..num_tables {
        let (value, slice_scr) = get_query_for_table_index(fq, window as usize, table_index as usize);
        let selected_table  = (tables.0[table_index as usize].clone(), tables.1[table_index as usize].clone());
        let (row, row_scr) = query_table(selected_table, (value as usize, slice_scr));

        let (add_scr, add_hints) = G1Affine::hinted_check_add(prev, row);
        let scr = script!{
            // [hints, t, scalar]
            {Fr::toaltstack()}
            {Fq2::copy(0)}
            {Fr::fromaltstack()}
             // [hints, t, t, scalar]
            {row_scr}
            // [hints, t, t, q]
            {add_scr}
            // [t, t+q]
        };
        prev = (prev + row).into_affine();
        all_rows.push((prev, scr, add_hints));
    }
    all_rows
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::g1::G1Affine;
    use crate::execute_script_without_stack_limit;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;


    #[test]
    fn test_get_query_for_table_index() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..100 {
            let fq = ark_bn254::Fr::rand(&mut prng);
            let window = (u32::rand(&mut prng) % 15)  + 1;
            let num_tables = 256/window;
            let random_index = u32::rand(&mut prng) % num_tables as u32;
            let (value, slice_scr) = get_query_for_table_index(fq, window as usize, random_index as usize);
    
            let scr = script!{
                {Fr::push(fq)}
                {slice_scr}
                for _ in 0..window {
                    OP_TOALTSTACK
                }
                {0}
                for i in 0..window {
                    OP_FROMALTSTACK
                    OP_ADD
                    if i != window-1 {
                        OP_DUP
                        OP_ADD
                    }
                }
                {value}
                OP_EQUAL OP_VERIFY
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert!(res.success);
            assert!(res.final_stack.len() == 1);
        }

    }

    #[test]
    fn test_query_table() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let window = 15;
        let tables = generate_lookup_tables(q, window);
        let num_tables = tables.1.len();
        let table_index = u32::rand(&mut prng) % num_tables as u32;

        let fq = ark_bn254::Fr::rand(&mut prng);
        
        let (value, slice_scr) = get_query_for_table_index(fq, window as usize, table_index as usize);

        let selected_table  = (tables.0[table_index as usize].clone(), tables.1[table_index as usize].clone());
        let (row, row_scr) = query_table(selected_table, (value as usize, slice_scr));

        let tap_len = row_scr.len();
        let scr = script!{
            {Fr::push(fq)}
            {row_scr}
            {G1Affine::push(row)}
            {G1Affine::equalverify()}
            OP_TRUE
        };

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success);
        assert!(res.final_stack.len() == 1);
        println!("tap len {} stack len {}", tap_len, res.stats.max_nb_stack_items);
    }



    #[test]
    fn test_hinted_msm_with_constant_bases_affine_script() {
        let n = 2;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases_affine(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            for hint in hints {
                { hint.push() }
            } 

            { msm.clone() }
            { G1Affine::push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        assert!(exec_result.success);
    }

    #[test]
    fn test_accumulate_rows() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let fq = ark_bn254::Fr::rand(&mut prng);
        let window = 15;
        let mut prev = ark_bn254::G1Affine::identity();
        let all_rows = accumulate_rows(prev, q, fq, window);

        let expected_msm = (q * fq).into_affine();
        let calculated_msm = all_rows[all_rows.len()-1].0;
        assert_eq!(expected_msm, calculated_msm);

        for (row_out, row_scr, row_hints) in all_rows {

            let scr = script!{
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(fq)}
                {row_scr}
                {G1Affine::push(row_out)}
                {G1Affine::equalverify()}
                {G1Affine::push(prev) }
                {G1Affine::equalverify()}
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            prev = row_out;

            assert!(res.success);
        }

    }


    #[test]
    fn test_accumulate_multiple_rows() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q0 = ark_bn254::G1Affine::rand(&mut prng);
        let fq0 = ark_bn254::Fr::rand(&mut prng);

        let q1 = ark_bn254::G1Affine::rand(&mut prng);
        let fq1 = ark_bn254::Fr::rand(&mut prng);

        let window = 15;
        let mut prev = ark_bn254::G1Affine::identity();
        let all_rows0 = accumulate_rows(prev, q0, fq0, window);
        let psm_out = all_rows0[all_rows0.len()-1].0;

        let all_rows1 = accumulate_rows(psm_out, q1, fq1, window);
        let calculated_msm = all_rows1[all_rows1.len()-1].0;
        let expected_msm = (q0 * fq0 + q1 * fq1).into_affine();
        assert_eq!(expected_msm, calculated_msm);

        for (row_out, row_scr, row_hints) in all_rows0 {

            let scr = script!{
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(fq0)}
                {row_scr}
                {G1Affine::push(row_out)}
                {G1Affine::equalverify()}
                {G1Affine::push(prev) }
                {G1Affine::equalverify()}
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            prev = row_out;

            assert!(res.success);
        }

        for (row_out, row_scr, row_hints) in all_rows1 {

            let scr = script!{
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(fq1)}
                {row_scr}
                {G1Affine::push(row_out)}
                {G1Affine::equalverify()}
                {G1Affine::push(prev) }
                {G1Affine::equalverify()}
                OP_TRUE
            };
            let res = execute_script(scr);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            prev = row_out;

            assert!(res.success);
        }

    }
}
