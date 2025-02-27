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

    let all_rows = g1_msm(bases.to_vec(), scalars.to_vec());
    let mut all_hints: Vec<Hint> = vec![];
    let mut prev = ark_bn254::G1Affine::identity();
    let mut scr = script!();

    let all_rows_len = all_rows.len();
    let num_scalars = scalars.len();
    let psm_len = all_rows.len()/num_scalars;

    for (idx, (row_out, row_scr, row_hints)) in all_rows.into_iter().enumerate() {

        all_hints.extend_from_slice(&row_hints);
        
        let temp_scr = script!{
            // [hints, t, scalar]
            {G1Affine::push(prev)}
            {Fr::push(scalars[idx/psm_len] )} // fq0, fq1
            {row_scr}
            if idx == all_rows_len-1 { // save final output
                {Fq2::copy(0)}
                {Fq2::toaltstack()}
            }
            {G1Affine::push(row_out)}
            {G1Affine::equalverify()}
            {G1Affine::push(prev) }
            {G1Affine::equalverify()}
            if idx == all_rows_len-1 {
                {Fq2::fromaltstack()}
            }
        };

        scr = script!{
            {scr}
            {temp_scr}
        };
        prev = row_out;
    }

    (scr, all_hints)
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


fn g1_msm(bases: Vec<ark_bn254::G1Affine>, scalars: Vec<ark_bn254::Fr>)->  Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> {
    assert_eq!(bases.len(), scalars.len());
    let mut prev = ark_bn254::G1Affine::identity();
    let window = 15;
    let mut compile_all_rows = vec![];
    for i in 0..bases.len() {
        let all_rows = accumulate_rows(prev, bases[i], scalars[i], window);
        prev = all_rows[all_rows.len()-1].0;
        compile_all_rows.extend_from_slice(&all_rows);
    }
    compile_all_rows
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
        println!("hints {:?}", hints.len());
        let tap_len = msm.len();
        let script = script! {
            for hint in hints {
                { hint.push() }
            } 
            { msm }

            { G1Affine::push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", tap_len);
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
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

            let tap_len = row_scr.len();
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
            println!("taplen {:?} max_stat {:?}", tap_len, res.stats.max_nb_stack_items);
        }

    }


    #[test]
    fn test_accumulate_multiple_rows() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q0 = ark_bn254::G1Affine::rand(&mut prng);
        let fq0 = ark_bn254::Fr::rand(&mut prng);
        let q1 = ark_bn254::G1Affine::rand(&mut prng);
        let fq1 = ark_bn254::Fr::rand(&mut prng);
        let bases = vec![q0, q1];
        let scalars = vec![fq0, fq1];

        let num_scalars = scalars.len();
        let all_rows = g1_msm(bases, scalars.clone());
        let psm_len = all_rows.len()/num_scalars;

        let expected_msm = (q0 * fq0 + q1 * fq1).into_affine();
        let calculated_msm = all_rows[all_rows.len()-1].0;
        assert_eq!(expected_msm, calculated_msm);

        let mut prev = ark_bn254::G1Affine::identity();
        for (idx, (row_out, row_scr, row_hints)) in all_rows.into_iter().enumerate() {

            let scr = script!{
                // [hints, t, scalar]
                for h in &row_hints {
                    {h.push()}
                }
                {G1Affine::push(prev)}
                {Fr::push(scalars[idx/psm_len] )} // fq0, fq1
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
