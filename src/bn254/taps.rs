
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine};
// utils for push fields into stack
use crate::pseudo::NMUL;
use crate::signatures::winternitz_compact::checksig_verify_fq;
use ark_bn254::{G2Affine};
use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use bitcoin::ScriptBuf;
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::{self, Read};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use num_traits::One;
use num_traits::ToPrimitive;



fn config_gen() {

    #[derive(Clone)]
    struct TableRowTemplate {
        name: &'static str,
        ID_expr: &'static str,
        Deps_expr: &'static str,
    }

    struct TableRow {
        name: String,
        ID: String,
        Deps: String,
    }

    fn evaluate_expression(expr: &str, start_id: i32) -> i32 {
        let expr_replaced = expr.replace("Sx", &start_id.to_string());
        let mut result = 0;
        let mut last_op = '+';
        let mut num = String::new();
        let expr_chars = expr_replaced.chars().chain(" ".chars()); // Add space to trigger parsing of the last number

        for c in expr_chars {
            if c.is_digit(10) {
                num.push(c);
            } else if c == '+' || c == '-' || c.is_whitespace() {
                if !num.is_empty() {
                    let n: i32 = num.parse().unwrap();
                    if last_op == '+' {
                        result += n;
                    } else if last_op == '-' {
                        result -= n;
                    }
                    num.clear();
                }
                if c == '+' || c == '-' {
                    last_op = c;
                }
            }
        }
        result
    }

    fn generate_table(
        structure: &[TableRowTemplate],
        start_id: i32,
        f_value: &str,
        T4_value: &str,
        replace_c: bool,
    ) -> Vec<TableRow> {
        let mut table = Vec::new();
        for row in structure {
            let name = row.name.to_string();
            // Calculate the actual ID
            let ID_expr = row.ID_expr;
            let ID = evaluate_expression(ID_expr, start_id);
            let ID_str = format!("S{}", ID);
            // Update dependencies
            let Deps = row.Deps_expr;
            let mut Deps_updated = String::new();
            for dep in Deps.trim_end_matches(';').split(',') {
                let dep = dep.trim();
                let dep_updated = if dep == "f_value" {
                    f_value.to_string()
                } else if dep == "T4_value" {
                    T4_value.to_string()
                } else if dep.starts_with("Sx") {
                    let dep_ID = evaluate_expression(dep, start_id);
                    format!("S{}", dep_ID)
                } else {
                    if replace_c && dep == "c" {
                        "cinv".to_string()
                    } else {
                        dep.to_string()
                    }
                };
                Deps_updated.push_str(&dep_updated);
                Deps_updated.push(',');
            }
            Deps_updated = Deps_updated.trim_end_matches(',').to_string() + ";";
            // Add the row to the table
            table.push(TableRow {
                name,
                ID: ID_str,
                Deps: Deps_updated,
            });
        }
        table
    }

    fn run() {
        // Array specifying the type of table to generate
        let ATE_LOOP_COUNT: Vec<i8> = vec![
            0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0,
            0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1,
            0, -1, 0, 0, 0, 1, 0, 1, 1,
        ];

        // Initialize the ID counter
        let mut id_counter = 1;

        // Initial values for f and T4
        let mut f_value = String::from("f"); // Starting value of f
        let mut T4_value = String::from("T4"); // Starting value of T4

        // Define the half and full table structures
        let half_table_structure = vec![
            TableRowTemplate {
                name: "Sqr",
                ID_expr: "Sx",
                Deps_expr: "f_value;",
            },
            TableRowTemplate {
                name: "Dbl",
                ID_expr: "Sx+1",
                Deps_expr: "P4,Q4,T4_value;",
            },
            TableRowTemplate {
                name: "SD1",
                ID_expr: "Sx+2",
                Deps_expr: "Sx,Sx+1;",
            },
            TableRowTemplate {
                name: "SS1",
                ID_expr: "Sx+3",
                Deps_expr: "P2,P3;",
            },
            TableRowTemplate {
                name: "DD1",
                ID_expr: "Sx+4",
                Deps_expr: "Sx+2,Sx+3;",
            },
            TableRowTemplate {
                name: "DD2",
                ID_expr: "Sx+5",
                Deps_expr: "Sx+2,Sx+3,Sx+4;",
            },
        ];

        let full_table_structure = {
            let mut v = half_table_structure.clone();
            v.extend(vec![
                TableRowTemplate {
                    name: "DD3",
                    ID_expr: "Sx+6",
                    Deps_expr: "Sx+5,c;",
                },
                TableRowTemplate {
                    name: "DD4",
                    ID_expr: "Sx+7",
                    Deps_expr: "Sx+5,c,Sx+6;",
                },
                TableRowTemplate {
                    name: "SD2",
                    ID_expr: "Sx+8",
                    Deps_expr: "Sx+7,Sx+1;",
                },
                TableRowTemplate {
                    name: "SS2",
                    ID_expr: "Sx+9",
                    Deps_expr: "P2,P3;",
                },
                TableRowTemplate {
                    name: "DD5",
                    ID_expr: "Sx+10",
                    Deps_expr: "Sx+8,Sx+9;",
                },
                TableRowTemplate {
                    name: "DD6",
                    ID_expr: "Sx+11",
                    Deps_expr: "Sx+8,Sx+9,Sx+10;",
                },
            ]);
            v
        };

        // Generate and print the sequence of tables
        let mut table_number = 1;
        for i in ATE_LOOP_COUNT.iter().rev().skip(1) {
            let table;
            if *i == 0 {
                // Generate a half table
                table = generate_table(
                    &half_table_structure,
                    id_counter,
                    &f_value,
                    &T4_value,
                    false,
                );
                // Update f_value and T4_value based on the half table
                f_value = format!("S{}", id_counter + 5); // ID of DD2
                T4_value = format!("S{}", id_counter + 1); // ID of Dbl
                id_counter += 6; // Half table uses 6 IDs
            } else if *i == 1 {
                // Generate a full table
                table = generate_table(
                    &full_table_structure,
                    id_counter,
                    &f_value,
                    &T4_value,
                    false,
                );
                // Update f_value and T4_value based on the full table
                f_value = format!("S{}", id_counter + 11); // ID of DD6
                T4_value = format!("S{}", id_counter + 1); // ID of Dbl
                id_counter += 12; // Full table uses 12 IDs
            } else if *i == -1 {
                // Generate a full table with c replaced by cinv
                table = generate_table(
                    &full_table_structure,
                    id_counter,
                    &f_value,
                    &T4_value,
                    true,
                );
                // Update f_value and T4_value based on the full table
                f_value = format!("S{}", id_counter + 11); // ID of DD6
                T4_value = format!("S{}", id_counter + 1); // ID of Dbl
                id_counter += 12; // Full table uses 12 IDs
            } else {
                continue;
            }
            // Print the table
            println!(
                "\n---\nTable {} ({})",
                table_number,
                if table.len() == 6 {
                    "Half Table"
                } else {
                    "Full Table"
                }
            );
            println!("{:<5} | {:<5} | Deps", "name", "ID");
            println!("{}", "-".repeat(40));
            for row in &table {
                println!("{:<5} | {:<5} | {}", row.name, row.ID, row.Deps);
            }
            table_number += 1;
        }
    }

    run();
}

fn split_digit(window: u32, index: u32) -> Script {
    script! {
        // {v}
        0                           // {v} {A}
        OP_SWAP
        for i in 0..index {
            OP_TUCK                 // {v} {A} {v}
            { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
            OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
            OP_TUCK                 // {v} {1/0} {A} {1/0}
            OP_ADD                  // {v} {1/0} {A+1/0}
            if i < index - 1 { { NMUL(2) } }
            OP_ROT OP_ROT
            OP_IF
                { 1 << (window - i - 1) }
                OP_SUB
            OP_ENDIF
        }
        // OP_SWAP
    }
}

pub fn unpack_u32_to_u4() -> Script {

    script!{
        {8}
        OP_ROLL
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-1 + 6}
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}
  
        {NMUL(8)}
        {8-2 + 6+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-3 + 6+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-4 + 6+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

        {8-5 + 6+8+7+7+7} //
        OP_ROLL
        {split_digit(29, 4)}
        {split_digit(25, 4)}
        {split_digit(21, 4)}
        {split_digit(17, 4)}
        {split_digit(13, 4)}
        {split_digit(9, 4)}
        {split_digit(5, 4)}

        {NMUL(8)}
        {8-6 + 6+8+7+7+7+8} //
        OP_ROLL
        {split_digit(29, 3)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(26, 4)}
        {split_digit(22, 4)}
        {split_digit(18, 4)}
        {split_digit(14, 4)}
        {split_digit(10, 4)}
        {split_digit(6, 4)}

        {NMUL(4)}
        {8-7 + 6+8+7+7+7+8+7} //
        OP_ROLL
        {split_digit(29, 2)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(27, 4)}
        {split_digit(23, 4)}
        {split_digit(19, 4)}
        {split_digit(15, 4)}
        {split_digit(11, 4)}
        {split_digit(7, 4)}

        {NMUL(2)}
        {8-8 + 6+8+7+7+7+8+7+7} //
        OP_ROLL
        {split_digit(29, 1)}
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        {split_digit(28, 4)}
        {split_digit(24, 4)}
        {split_digit(20, 4)}
        {split_digit(16, 4)}
        {split_digit(12, 4)}
        {split_digit(8, 4)}

    }
}

pub fn pack_u4_to_u32() -> Script {
    let n_limbs = 9;
    script!{
        {58} OP_ROLL
        {59} OP_ROLL
        {60} OP_ROLL
        {61} OP_ROLL
        {62} OP_ROLL
        {63} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        OP_TOALTSTACK

        {50} OP_ROLL
        {51} OP_ROLL
        {52} OP_ROLL
        {53} OP_ROLL
        {54} OP_ROLL
        {55} OP_ROLL
        {56} OP_ROLL
        {57} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(2)}
        OP_SWAP
        {split_digit(4, 1)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {43} OP_ROLL
        {44} OP_ROLL
        {45} OP_ROLL
        {46} OP_ROLL
        {47} OP_ROLL
        {48} OP_ROLL
        {49} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(4)}
        OP_SWAP
        {split_digit(4, 2)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {36} OP_ROLL
        {37} OP_ROLL
        {38} OP_ROLL
        {39} OP_ROLL
        {40} OP_ROLL
        {41} OP_ROLL
        {42} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(8)}
        OP_SWAP
        {split_digit(4, 3)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {29} OP_ROLL
        {30} OP_ROLL
        {31} OP_ROLL
        {32} OP_ROLL
        {33} OP_ROLL
        {34} OP_ROLL
        {35} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        OP_TOALTSTACK

        {21} OP_ROLL
        {22} OP_ROLL
        {23} OP_ROLL
        {24} OP_ROLL
        {25} OP_ROLL
        {26} OP_ROLL
        {27} OP_ROLL
        {28} OP_ROLL
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(2)}
        OP_SWAP
        {split_digit(4, 1)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {14} OP_ROLL
        {15} OP_ROLL
        {16} OP_ROLL
        {17} OP_ROLL
        {18} OP_ROLL
        {19} OP_ROLL
        {20} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(4)}
        OP_SWAP
        {split_digit(4, 2)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {7} OP_ROLL
        {8} OP_ROLL
        {9} OP_ROLL
        {10} OP_ROLL
        {11} OP_ROLL
        {12} OP_ROLL
        {13} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(8)}
        OP_SWAP
        {split_digit(4, 3)}
        OP_ROT OP_ROT OP_ADD
        OP_TOALTSTACK

        OP_TOALTSTACK
        {1} OP_ROLL
        {2} OP_ROLL
        {3} OP_ROLL
        {4} OP_ROLL
        {5} OP_ROLL
        {6} OP_ROLL
        OP_FROMALTSTACK
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD
        {NMUL(16)} OP_ADD

        for i in 1..n_limbs {
            OP_FROMALTSTACK
        }
        for i in 1..n_limbs {
            {i} OP_ROLL
        }
    }

}



pub fn read_script_from_file(file_path: &str) -> Script {
    fn read_file_to_bytes(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut all_script_bytes = Vec::new();
        file.read_to_end(&mut all_script_bytes)?;
        Ok(all_script_bytes)
    }
    //let file_path = "blake3_bin/blake3_192b_252k.bin"; // Replace with your file path
    let all_script_bytes = read_file_to_bytes(file_path).unwrap();
    let scb = ScriptBuf::from_bytes(all_script_bytes);
    let sc = script!();
    let sc = sc.push_script(scb);
    sc
}

// [a0, a1, a2, a3, a4, a5]
// [H(a0,a1), H(a2,a3,a4,a5)]
// [Hb0, Hb1]
// [Hb1, Hb0]
// Hash(Hb1, Hb0)
// Hb
pub fn hash_fp6() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }
        { unpack_u32_to_u4() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u4() }
        {hash_64b_75k.clone()}
        { pack_u4_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { hash_128b_168k.clone() }

            for _ in 0..9 {
                {64 + 8} OP_ROLL
            }
            {unpack_u32_to_u4()}
        { hash_64b_75k }
        {pack_u4_to_u32()}
    } 
}

pub fn emulate_extern_hash_fp6(msgs: [ark_bn254::Fq; 6]) -> [u32;9] {
    let scr = script!{
        for i in 0..msgs.len() {
            {fq_push_not_montgomery(msgs[i])}
        }
        {hash_fp6()}
    };
    let exec_result = execute_script(scr);

    assert_eq!(exec_result.final_stack.len(), 9);
    let mut us: [u32;9] = [0u32;9];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        let mut w = [0u8; 4];
        for i in 0..v.len() {
            w[i] = v[i];
        }
        println!("v {:?}", v);
        let u = u32::from_le_bytes(w);
        us[i] = u;
    }
    us
}

// msg to nibbles
pub fn emulate_extern_hash_fp12(a: ark_bn254::Fq12) -> [u8; 64] {
    let msgs = [a.c0.c0.c0,a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0,a.c0.c2.c1, a.c1.c0.c0,a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0,a.c1.c2.c1,];
    let scr = script!{
        for i in 0..msgs.len() {
            {fq_push_not_montgomery(msgs[i])}
        }
        {hash_fp12()}
        {unpack_u32_to_u4()}
    };
    let exec_result = execute_script(scr);
    let mut arr = [0u8; 64];
    for i in 0..exec_result.final_stack.len() {
        let v = exec_result.final_stack.get(i);
        if v.is_empty() {
            arr[i] = 0;
        } else {
            arr[i] = v[0];
        }
    }
    arr
}


pub fn hash_fp12() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }

        // first part
        { unpack_u32_to_u4() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u4() }
        {hash_64b_75k.clone()}
        { pack_u4_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        {pack_u4_to_u32()}

        // second part

        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        { pack_u4_to_u32() }
        

        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { hash_128b_168k.clone() }

        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        {pack_u4_to_u32()}

    } 
}

pub fn hash_fp12_192() -> Script {
    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_192b_252k = read_script_from_file("blake3_bin/blake3_192b_252k.bin");
    script! {
        for _ in 0..=10 {
            {Fq::toaltstack()}
        }
        {unpack_u32_to_u4() }
        for _ in 0..5 {
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
        }
        {hash_192b_252k.clone()}
        {pack_u4_to_u32()}

        for _ in 0..6 {
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
        }
        {hash_192b_252k}
        for _ in 0..9 {
            {64+8} OP_ROLL
        }
        { unpack_u32_to_u4() }
        {hash_64b_75k}
        {pack_u4_to_u32()}
    }
}


// 6Fp_hash
// fp6
pub fn hash_fp12_with_hints() -> Script {

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    script!{
        for _ in 0..=4 {
            {Fq::toaltstack()}
        }

        { unpack_u32_to_u4() }
        { Fq::fromaltstack() }
        { unpack_u32_to_u4() }
        {hash_64b_75k.clone()}
        { pack_u4_to_u32() }

        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { Fq::fromaltstack() }
        {unpack_u32_to_u4()}
        { hash_128b_168k.clone() }


        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}

        // wrap up
        for _ in 0..9 {
            {64 + 8} OP_ROLL
        }
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        {pack_u4_to_u32()}

    } 
}



// Taps
fn tap_squaring(sec_key: &str)-> Script {

    let (sq_script, _) = Fq12::hinted_square(ark_bn254::Fq12::ONE);
    let bitcomms_sc = script!{
        {checksig_verify_fq(sec_key)}
        {Fq::toaltstack()}
        {checksig_verify_fq(sec_key)}
        {Fq::fromaltstack()}
        {Fq::roll(1)}
    };
    let hash_sc  = script!{
        { hash_fp12() }
        { Fq::drop() }
        { hash_fp12() }
        {Fq::drop()}
        {Fq::drop()}
        {Fq::drop()}
    };
    let sc = script!{
        {bitcomms_sc.clone()}
        {sq_script}
        {hash_sc}
        OP_TRUE
    };
    bitcomms_sc
}


fn tap_point_ops() -> Script {

    let (hinted_double_line, hints_double_line) = new_hinted_affine_double_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_tangent, hints_check_tangent) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_check_chord_t, hints_check_chord_t) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_check_chord_q, hints_check_chord_q) = new_hinted_check_line_through_point(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_add_line, hints_add_line) = new_hinted_affine_add_line(ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let (hinted_ell_tangent, hints_ell_tangent) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());
    let (hinted_ell_chord, hints_ell_chord) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::one(), ark_bn254::Fq::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

    let bcsize = 6+3;
    let script = script! {
        // hints
        // for hint in hints_check_tangent { 
        //     { hint.push() }
        // }
        // for hint in hints_ell_tangent { 
        //     { hint.push() }
        // }
        // for hint in hints_double_line { 
        //     { hint.push() }
        // }
        // for hint in hints_check_chord_q { 
        //     { hint.push() }
        // }
        // for hint in hints_check_chord_t { 
        //     { hint.push() }
        // }
        // for hint in hints_ell_chord { 
        //     { hint.push() }
        // }
        // for hint in hints_add_line { 
        //     { hint.push() }
        // }

        // aux
        // { fq2_push_not_montgomery(alpha_chord)}
        // { fq2_push_not_montgomery(bias_minus_chord)}
        // { fq2_push_not_montgomery(alpha_tangent)}
        // { fq2_push_not_montgomery(bias_minus_tangent)}
        // { fq2_push_not_montgomery(t.x) }
        // { fq2_push_not_montgomery(t.y) }

        // bit commits
        // { fq_push_not_montgomery(p_dash_x) }
        // { fq_push_not_montgomery(p_dash_y) }
        // { fq2_push_not_montgomery(q.x) }
        // { fq2_push_not_montgomery(q.y) }
        // { Fq::push_zero() } // hash
        // { Fq::push_zero() } // hash
        // { Fq::push_zero() } // hash
        

        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::copy(bcsize+6)} // t.x
        { Fq2::copy(bcsize+6)} // t.y
        { hinted_check_tangent }

        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(4 + 7) } // p_dash
        { hinted_ell_tangent }
        { Fq2::toaltstack() } // le.0
        { Fq2::toaltstack() } // le.1


        { Fq2::copy(bcsize+4)} // bias
        { Fq2::copy(bcsize+8)} // alpha
        { Fq2::copy(bcsize+6)} // t.x
        { hinted_double_line }
        { Fq2::toaltstack() }
        { Fq2::toaltstack()}
        // { fq2_push_not_montgomery(tt.y) }
        // { Fq2::equalverify() }
        // { fq2_push_not_montgomery(tt.x) }
        // { Fq2::equalverify() }

        { Fq2::roll(bcsize+6) } // alpha tangent drop
        { Fq2::drop() }
        { Fq2::roll(bcsize+4) } // bias tangent drop
        { Fq2::drop() }

        // hinted check chord // t.x, t.y
        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::copy(8+1) } // q.x
        { Fq2::copy(8+1) } // q.y
        { hinted_check_chord_q }
        { Fq2::copy(bcsize+6)} // alpha
        { Fq2::copy(bcsize+6)} // bias
        { Fq2::fromaltstack() }
        { Fq2::fromaltstack() }
        { Fq2::copy(2)} // t.x
        { Fq2::toaltstack() }
        { hinted_check_chord_t }


        { Fq2::copy(bcsize+6) } // alpha
        { Fq2::copy(bcsize+6) } // bias
        { Fq2::copy(10+1) } // p_dash
        { hinted_ell_chord }

        { Fq2::roll(4+bcsize+4) } // bias
        { Fq2::roll(6+bcsize+4) } // alpha
        { Fq2::copy(4+4+4+1) } //q.x
        { Fq2::fromaltstack() }
        { hinted_add_line }

        { Fq2::toaltstack() }//R
        { Fq2::toaltstack() }
        
        { Fq2::toaltstack() } //le_add
        { Fq2::toaltstack() } 


        { Fq::toaltstack() } //hashes
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq2::drop() }
        { Fq2::drop() }
        { Fq2::drop() }

        //T
        {Fq::roll(1)}
        {Fq::roll(2)}
        {Fq::roll(3)}
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_u32_to_u4()} // 0
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        {hash_128b_168k.clone()}

        // fetch 1 hash
        { Fq::fromaltstack()} // aux_hash
        {unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        {pack_u4_to_u32()}
        { Fq::fromaltstack()} //input_hash
        {Fq2::drop()} //{Fq::equalverify(1, 0)}

        for i in 0..13 {
            {Fq::fromaltstack()}
        }

        // Hash le
        {Fq::roll(1)}
        {Fq::roll(2)}
        {Fq::roll(3)}
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_u32_to_u4()} // 0
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        {hash_128b_168k.clone()}
        {pack_u4_to_u32()}
        {Fq::toaltstack()}
        
        {Fq::roll(1)}
        {Fq::roll(2)}
        {Fq::roll(3)}
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_u32_to_u4()} // 0
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        {hash_128b_168k.clone()}
        {pack_u4_to_u32()}
        {Fq::toaltstack()}

        {Fq::roll(1)}
        {Fq::roll(2)}
        {Fq::roll(3)}
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_u32_to_u4()} // 0
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        {hash_128b_168k.clone()}
        //{nibbles_to_fq()}

        // bring back hash
        { Fq::fromaltstack()}
        { unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        { Fq::fromaltstack()}
        { unpack_u32_to_u4()}
        {hash_64b_75k.clone()}
        {pack_u4_to_u32()}

        {Fq2::drop()} //{Fq::equalverify(1, 0)}
        OP_TRUE
    };
    script
}


fn tap_sparse_muls() -> Vec<Script> {
    // take fixed Qs as input vkY and vk_del
    let mut prng = ChaCha20Rng::seed_from_u64(0);
    let q_vk_g = ark_bn254::G2Affine::rand(&mut prng);
    let q_vk_del = ark_bn254::G2Affine::rand(&mut prng);
    // take T4 as auxiliary input
    let t2 = q_vk_g; // initial assignment
    let t3 = q_vk_del;

    fn sparse_mul_for_doubling(t2: G2Affine, t3: G2Affine) -> (Script, (G2Affine, G2Affine)) {
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_t2 = t2.x.square();
        alpha_t2 /= t2.y;
        alpha_t2.mul_assign_by_fp(&three_div_two);
        let bias_t2 = alpha_t2 * t2.x - t2.y;
        let x2 = alpha_t2.square() - t2.x.double();
        let y2 = bias_t2 - alpha_t2 * x2;
        let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);
        
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_t3 = t3.x.square();
        alpha_t3 /= t3.y;
        alpha_t3.mul_assign_by_fp(&three_div_two);
        let bias_t3 = alpha_t3 * t3.x - t3.y;
        let x3 = alpha_t3.square() - t3.x.double();
        let y3 = bias_t3 - alpha_t3 * x3;
        let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);
        
        let (sparse_dense_mul, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::ONE, ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);
        
        let sc = script!{
            // P2 
            // P3
            {fq2_push_not_montgomery(alpha_t2)} // baked
            {fq2_push_not_montgomery(bias_t2)}
            {fq2_push_not_montgomery(alpha_t3)}
            {fq2_push_not_montgomery(bias_t3)}
            { Fq2::roll(6) } // P3
            { hinted_ell_t3 }
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}
            { Fq2::roll(4) }
            { hinted_ell_t2 }
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}

            // sparse fq12
            {Fq2::push_one()} // 0
            {Fq2::push_zero()}
            {Fq2::push_zero()}
            {Fq2::fromaltstack()} // 3
            {Fq2::fromaltstack()} // 4
            {Fq2::push_zero()}
            // sparse fp12
            {Fq2::fromaltstack()}
            {Fq2::fromaltstack()}
            {sparse_dense_mul}
        };
        (sc, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)))
    }

    fn sparse_mul_for_addition(t2: G2Affine, t3: G2Affine, q2: G2Affine, q3: G2Affine) -> (Script, (G2Affine, G2Affine)) {
        let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x);
        let bias_t2 = alpha_t2 * t2.x - t2.y;
        let x2 = alpha_t2.square() - t2.x - q2.x;
        let y2 = bias_t2 - alpha_t2 * x2;
        let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);

        let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x);
        let bias_t3 = alpha_t3 * t3.x - t3.y;
        let x3 = alpha_t3.square() - t3.x - q3.x;
        let y3 = bias_t3 - alpha_t3 * x3;
        let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t3, bias_t3);
        
        let (sparse_dense_mul, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::ONE, ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);
        
        let sc = script!{
            // P2 
            // P3
            {fq2_push_not_montgomery(alpha_t2)}
            {fq2_push_not_montgomery(bias_t2)}
            {fq2_push_not_montgomery(alpha_t3)}
            {fq2_push_not_montgomery(bias_t3)}
            { Fq2::roll(6) } // P3
            { hinted_ell_t3 }
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}
            { Fq2::roll(4) }
            { hinted_ell_t2 }
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}

            // sparse fq12
            {Fq2::push_one()} // 0
            {Fq2::push_zero()}
            {Fq2::push_zero()}
            {Fq2::fromaltstack()} // 3
            {Fq2::fromaltstack()} // 4
            {Fq2::push_zero()}
            // sparse fp12
            {Fq2::fromaltstack()}
            {Fq2::fromaltstack()}
            {sparse_dense_mul}
        };
        (sc, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)))
    }

    let ate_loop_count: Vec<i8> = vec![
        0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0,
        0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1,
        0, -1, 0, 0, 0, 1, 0, 1, 1,
    ];

    let mut nt2 = t2.clone();
    let mut nt3 = t3.clone();
    let mut scripts = vec![];
    let mut scr: Script = script!();
    for bit in ate_loop_count.iter().rev().skip(1) {
        (scr, (nt2, nt3)) = sparse_mul_for_doubling(nt2, nt3);
        scripts.push(scr);
        if *bit == 1 {
            (scr, (nt2, nt3)) = sparse_mul_for_addition(nt2, nt3, q_vk_g, q_vk_del);
            scripts.push(scr);
        } else if *bit == -1 {
            (scr, (nt2, nt3)) = sparse_mul_for_addition(nt2, nt3, -q_vk_g, -q_vk_del);
            scripts.push(scr);
        }
    }
    scripts
}


fn tap_sparse_dense_mul() -> Script {
    let (hinted_script, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::one(), ark_bn254::Fq2::one(), ark_bn254::Fq2::one());

    let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");


    let script = script! {
        // for hint in hints { 
        //     { hint.push() }
        // }

        // { fq12_push_not_montgomery(f) }
        // { fq2_push_not_montgomery(c1new) }
        // { fq2_push_not_montgomery(c2new) }
        // { fq12_push_not_montgomery(f) }
        // { fq2_push_not_montgomery(c1new) }
        // { fq2_push_not_montgomery(c2new) }

        { hinted_script.clone() }

        for _ in 0..12 { // save claim
            {Fq::toaltstack()}
        }

        // hash c1new and c2new
        {Fq::roll(1)}
        {Fq::roll(2)}
        {Fq::roll(3)}
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        { Fq::toaltstack() }
        {unpack_u32_to_u4()} // 0
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        { Fq::fromaltstack()}
        {unpack_u32_to_u4()}
        {hash_128b_168k.clone()}
        {pack_u4_to_u32()}

        {hash_fp12() }

        for _ in 0..12 { // save claim
            {Fq::fromaltstack()}
        }
        { hash_fp12_192() }

        OP_TRUE
    };
    script
}


fn tap_dense_dense_mul0() -> Script {
    let (hinted_mul, _) = Fq12::hinted_mul_first(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let script = script! {
        // mul hints
        // Hash_b
        // Hash_a
        // Hash_c

        // aux a
        // aux b
        { hinted_mul }
        { Fq6::toaltstack() } // c0
        
        { hash_fp12()}
        //bring Hashb to top
        for _ in 0..9 {
            OP_DEPTH OP_1SUB OP_ROLL
        }
        { Fq::equalverify(0, 1)}

        // hash_a
        { hash_fp12_192() }
        for _ in 0..9 {
            OP_DEPTH OP_1SUB OP_ROLL
        }
        { Fq::equalverify(0, 1)}

        {Fq::fromaltstack()} // Fq_claimed from altstack
        {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
        OP_TRUE
    };
    script
}


fn tap_dense_dense_mul1() -> Script {
    let (hinted_mul, _) = Fq12::hinted_mul_second(12, ark_bn254::Fq12::one(), 0, ark_bn254::Fq12::one());

    let script = script! {
        // hints
        // Hash_b

        // Hash_c0

        // Hash_a
        
        // Hash_c

        // aux a
        // aux b
        { hinted_mul }
        { Fq6::toaltstack() }
        
        { hash_fp12()}
        // bring Hashb to top
        for i in 0..9 {
            OP_DEPTH OP_1SUB OP_ROLL
        }
        { Fq::equalverify(0, 1)}

        // bring Hash_c0 to top
        for i in 0..9 {
            OP_DEPTH OP_1SUB OP_ROLL
        }
        { Fq6::fromaltstack() }
        { hash_fp12_with_hints() }
        { Fq::toaltstack() } // Fq_claimed to altstack

        // hash_a
        { hash_fp12_192() }
        for i in 0..9 {
            OP_DEPTH OP_1SUB OP_ROLL
        }
        { Fq::equalverify(0, 1)}

        {Fq::fromaltstack()} // Fq_claimed from altstack
        {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
        OP_TRUE
    };
    script  
}




#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::G2Affine;
    use ark_ff::AdditiveGroup;
    use ark_std::UniformRand;
    use num_traits::{FromPrimitive, One};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq6::Fq6;
    use crate::bn254::utils::{fq12_push_not_montgomery, fq2_push_not_montgomery, fq_push_not_montgomery, new_hinted_affine_add_line, new_hinted_affine_double_line, new_hinted_check_line_through_point, new_hinted_ell_by_constant_affine};
    use crate::signatures::winternitz_compact;
    use ark_ff::Field;
    use core::ops::Mul;
    use crate::bn254::{fq12::Fq12, fq2::Fq2};


    #[test]
    fn test_fp6_hasher() {
        let res = emulate_extern_hash_fp6([ark_bn254::Fq::one(); 6]);
        println!("res {:?}", res);
    }

    #[test]
    fn test_hinited_sparse_dense_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let _q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let f = ark_bn254::Fq12::rand(&mut prng);
        
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_tangent = t.x.square();
        alpha_tangent /= t.y;
        alpha_tangent.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus_tangent = alpha_tangent * t.x - t.y;

        let mut f1 = f;
        let mut c1new = alpha_tangent;
        c1new.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new = bias_minus_tangent;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        f1.mul_by_034(&ark_bn254::Fq2::ONE, &c1new, &c2new);
        let (hinted_script, hints) = Fq12::hinted_mul_by_34(f, c1new, c2new);

        let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");


        let script = script! {
            for hint in hints { 
                { hint.push() }
            }

            { fq12_push_not_montgomery(f) }
            { fq2_push_not_montgomery(c1new) }
            { fq2_push_not_montgomery(c2new) }
            { fq12_push_not_montgomery(f) }
            { fq2_push_not_montgomery(c1new) }
            { fq2_push_not_montgomery(c2new) }
            { hinted_script.clone() }

            for _ in 0..12 { // save claim
                {Fq::toaltstack()}
            }

            // hash c1new and c2new
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u4()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            {hash_128b_168k.clone()}
            {pack_u4_to_u32()}

            {hash_fp12() }

            for _ in 0..12 { // save claim
                {Fq::fromaltstack()}
            }
            { hash_fp12_192() }

            OP_TRUE
        };
        let len = script.len();
        let res = execute_script(script);
        assert!(res.success);
        let mut max_stack = 0;
        max_stack = max_stack.max(res.stats.max_nb_stack_items);
        println!("Fq6::window_mul: {} @ {} stack", len, max_stack);
    }

    #[test]
    fn test_bn254_fq12_hinted_mul_split0() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul_first(12, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                // Hash_b
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_a
                {u32::from_le_bytes([131, 116, 114, 0])}
                {u32::from_le_bytes([245, 129, 139, 3])}
                {u32::from_le_bytes([132, 171, 199, 7])}
                {u32::from_le_bytes([97, 185, 93, 16])}
                {u32::from_le_bytes([161, 222, 150, 25])}
                {u32::from_le_bytes([44, 144, 71, 23])}
                {u32::from_le_bytes([139, 185, 38, 22])}
                {u32::from_le_bytes([233, 138, 103, 22])}
                {u32::from_le_bytes([9, 213, 155, 19])}
                
                // Hash_c
                {u32::from_le_bytes([82, 143, 25,0])}
                {u32::from_le_bytes([106, 69, 151, 13])}
                {u32::from_le_bytes([154, 120, 131, 27])}
                {u32::from_le_bytes([140, 55, 239, 25])}
                {u32::from_le_bytes([92, 201, 47, 28])}
                {u32::from_le_bytes([44, 174, 74, 16])}
                {u32::from_le_bytes([57, 190, 31, 19])}
                {u32::from_le_bytes([31, 231, 126, 1])}
                {u32::from_le_bytes([158, 11, 210, 2])}

                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(b) } // fp12_one
                { hinted_mul.clone() }
                { Fq6::toaltstack() }
                
                { hash_fp12()}
                //bring Hashb to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                // hash_a
                { hash_fp12_192() }
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                {Fq::fromaltstack()} // Fq_claimed from altstack
                {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
                OP_TRUE
            };

            println!("script len {}", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            for i in 0..exec_result.final_stack.len() {
                println!("{i:3} {:?}", exec_result.final_stack.get(i));
            }
            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq12::mul {} stack", max_stack);
            
        }

    }

    #[test]
    fn test_bn254_fq12_hinted_mul_split1() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul_second(12, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                // Hash_b
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_c0
                {u32::from_le_bytes([17, 50, 164, 0])}
                {u32::from_le_bytes([235, 77, 217, 15])}
                {u32::from_le_bytes([1, 4, 86, 10])}
                {u32::from_le_bytes([23, 225, 110, 26])}
                {u32::from_le_bytes([71, 105, 236, 11])}
                {u32::from_le_bytes([75, 29, 151, 8])}
                {u32::from_le_bytes([130, 190, 188, 3])}
                {u32::from_le_bytes([246, 67, 44, 19])}
                {u32::from_le_bytes([105, 194, 20, 27])}

                // Hash_a
                {u32::from_le_bytes([131, 116, 114, 0])}
                {u32::from_le_bytes([245, 129, 139, 3])}
                {u32::from_le_bytes([132, 171, 199, 7])}
                {u32::from_le_bytes([97, 185, 93, 16])}
                {u32::from_le_bytes([161, 222, 150, 25])}
                {u32::from_le_bytes([44, 144, 71, 23])}
                {u32::from_le_bytes([139, 185, 38, 22])}
                {u32::from_le_bytes([233, 138, 103, 22])}
                {u32::from_le_bytes([9, 213, 155, 19])}
                
                // Hash_c
                {u32::from_le_bytes([66, 234, 4, 0])}
                {u32::from_le_bytes([156, 104, 70, 7])}
                {u32::from_le_bytes([5, 60, 102, 10])}
                {u32::from_le_bytes([171, 108, 80, 11])}
                {u32::from_le_bytes([30, 94, 254, 19])}
                {u32::from_le_bytes([34, 232, 58, 11])}
                {u32::from_le_bytes([191, 101, 160, 16])}
                {u32::from_le_bytes([53, 186, 189, 25])}
                {u32::from_le_bytes([83, 33, 154, 8])}

                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(b) } // fp12_one
                { hinted_mul.clone() }
                { Fq6::toaltstack() }
                
                { hash_fp12()}
                // bring Hashb to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                // bring Hash_c0 to top
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq6::fromaltstack() }
                { hash_fp12_with_hints() }
                { Fq::toaltstack() } // Fq_claimed to altstack

                // hash_a
                { hash_fp12_192() }
                for i in 0..9 {
                    OP_DEPTH OP_1SUB OP_ROLL
                }
                { Fq::equalverify(0, 1)}

                {Fq::fromaltstack()} // Fq_claimed from altstack
                {Fq::equalverify(0, 1)} // SHOULD BE UNEQUAL VERIFY
                OP_TRUE
            };

            println!("script len {}", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            for i in 0..exec_result.final_stack.len() {
                println!("{i:3} {:?}", exec_result.final_stack.get(i));
            }
            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq12::mul {} stack", max_stack);
            
        }

    }


    #[test]
    fn test_bn254_fq12_hinted_square() {

        let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let hinted_square = tap_squaring(&sec_key_for_bitcomms);

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = a.square();
        let a_hash = emulate_extern_hash_fp12(a);
        let b_hash = emulate_extern_hash_fp12(b);

        let simulate_stack_input = script!{
            // for hint in hints { 
            //     { hint.push() }
            // }
            // aux_b
            {fq12_push_not_montgomery(b)}
            // aux_a
            {fq12_push_not_montgomery(b)}
            // hash_a
            { winternitz_compact::sign(sec_key_for_bitcomms, a_hash)}
            // hash_b
            { winternitz_compact::sign(sec_key_for_bitcomms, b_hash)}
        };
        let script = script! {
            {simulate_stack_input}
            { hinted_square }
        };

        let exec_result = execute_script(script);

        // assert!(exec_result.success);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:3}x {:?}", exec_result.final_stack.get(i));
        }
        // println!("stack len {:?} final len {:?}", exec_result.stats.max_nb_stack_items, exec_result.final_stack.len());
        // max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
        // println!("Fq12::hinted_square: {} @ {} stack final stack {}", hinted_square.len(), max_stack,exec_result.final_stack.len());
    }


    #[test]
    fn test_hinted_sparse_mul() {
        // take fixed Qs as input vkY and vk_del
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q_vk_g = ark_bn254::G2Affine::rand(&mut prng);
        let q_vk_del = ark_bn254::G2Affine::rand(&mut prng);
        // take var Ps as input: MSM, Groth
        let p2 = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::g1::G1Affine::rand(&mut prng);
        // take T4 as auxiliary input
        let t2 = q_vk_g; // initial assignment
        let t3 = q_vk_del;

        fn sparse_mul_for_doubling(t2: G2Affine, t3: G2Affine) -> (Script, (G2Affine, G2Affine)) {
            let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
            let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
            let mut alpha_t2 = t2.x.square();
            alpha_t2 /= t2.y;
            alpha_t2.mul_assign_by_fp(&three_div_two);
            let bias_t2 = alpha_t2 * t2.x - t2.y;
            let x2 = alpha_t2.square() - t2.x.double();
            let y2 = bias_t2 - alpha_t2 * x2;
            let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);
            
            let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
            let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
            let mut alpha_t3 = t3.x.square();
            alpha_t3 /= t3.y;
            alpha_t3.mul_assign_by_fp(&three_div_two);
            let bias_t3 = alpha_t3 * t3.x - t3.y;
            let x3 = alpha_t3.square() - t3.x.double();
            let y3 = bias_t3 - alpha_t3 * x3;
            let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);
            
            let (sparse_dense_mul, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::ONE, ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);
            
            let sc = script!{
                // P2 
                // P3
                {fq2_push_not_montgomery(alpha_t2)} // baked
                {fq2_push_not_montgomery(bias_t2)}
                {fq2_push_not_montgomery(alpha_t3)}
                {fq2_push_not_montgomery(bias_t3)}
                { Fq2::roll(6) } // P3
                { hinted_ell_t3 }
                {Fq2::toaltstack()}
                {Fq2::toaltstack()}
                { Fq2::roll(4) }
                { hinted_ell_t2 }
                {Fq2::toaltstack()}
                {Fq2::toaltstack()}

                // sparse fq12
                {Fq2::push_one()} // 0
                {Fq2::push_zero()}
                {Fq2::push_zero()}
                {Fq2::fromaltstack()} // 3
                {Fq2::fromaltstack()} // 4
                {Fq2::push_zero()}
                // sparse fp12
                {Fq2::fromaltstack()}
                {Fq2::fromaltstack()}
                {sparse_dense_mul}
            };
            (sc, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)))
        }


        fn sparse_mul_for_addition(t2: G2Affine, t3: G2Affine, q2: G2Affine, q3: G2Affine) -> (Script, (G2Affine, G2Affine)) {
            let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x);
            let bias_t2 = alpha_t2 * t2.x - t2.y;
            let x2 = alpha_t2.square() - t2.x - q2.x;
            let y2 = bias_t2 - alpha_t2 * x2;
            let (hinted_ell_t2, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t2, bias_t2);

            let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x);
            let bias_t3 = alpha_t3 * t3.x - t3.y;
            let x3 = alpha_t3.square() - t3.x - q3.x;
            let y3 = bias_t3 - alpha_t3 * x3;
            let (hinted_ell_t3, _) = new_hinted_ell_by_constant_affine(ark_bn254::Fq::ONE,ark_bn254::Fq::ONE, alpha_t3, bias_t3);
            
            let (sparse_dense_mul, _) = Fq12::hinted_mul_by_34(ark_bn254::Fq12::ONE, ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);
            
            let sc = script!{
                // P2 
                // P3
                {fq2_push_not_montgomery(alpha_t2)}
                {fq2_push_not_montgomery(bias_t2)}
                {fq2_push_not_montgomery(alpha_t3)}
                {fq2_push_not_montgomery(bias_t3)}
                { Fq2::roll(6) } // P3
                { hinted_ell_t3 }
                {Fq2::toaltstack()}
                {Fq2::toaltstack()}
                { Fq2::roll(4) }
                { hinted_ell_t2 }
                {Fq2::toaltstack()}
                {Fq2::toaltstack()}

                // sparse fq12
                {Fq2::push_one()} // 0
                {Fq2::push_zero()}
                {Fq2::push_zero()}
                {Fq2::fromaltstack()} // 3
                {Fq2::fromaltstack()} // 4
                {Fq2::push_zero()}
                // sparse fp12
                {Fq2::fromaltstack()}
                {Fq2::fromaltstack()}
                {sparse_dense_mul}
            };
            (sc, (G2Affine::new(x2, y2), G2Affine::new(x3, y3)))
        }

        let (scd, (nt2, nt3)) = sparse_mul_for_doubling(t2, t3);

        let (sca, (nt2, nt3)) = sparse_mul_for_addition(nt2, nt3, q_vk_g, q_vk_del);
    }


    #[test]
    fn test_hinted_affine_double_add_eval() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha_tangent = t.x.square();
        alpha_tangent /= t.y;
        alpha_tangent.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus_tangent = alpha_tangent * t.x - t.y;

        let x = alpha_tangent.square() - t.x.double();
        let y = bias_minus_tangent - alpha_tangent * x;
        let (hinted_double_line, hints_double_line) = new_hinted_affine_double_line(t.x, alpha_tangent, bias_minus_tangent);
        let (hinted_check_tangent, hints_check_tangent) = new_hinted_check_line_through_point(t.x, alpha_tangent, bias_minus_tangent);

        let tt = G2Affine::new(x, y);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha_chord = (tt.y - q.y) / (tt.x - q.x);
        // -bias
        let bias_minus_chord = alpha_chord * tt.x - tt.y;
        assert_eq!(alpha_chord * tt.x - tt.y, bias_minus_chord);

        let x = alpha_chord.square() - tt.x - q.x;
        let y = bias_minus_chord - alpha_chord * x;
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);
        let p_dash_x = -p.x/p.y;
        let p_dash_y = p.y.inverse().unwrap();

        let (hinted_check_chord_t, hints_check_chord_t) = new_hinted_check_line_through_point( tt.x, alpha_chord, bias_minus_chord);
        let (hinted_check_chord_q, hints_check_chord_q) = new_hinted_check_line_through_point( q.x, alpha_chord, bias_minus_chord);
        let (hinted_add_line, hints_add_line) = new_hinted_affine_add_line(tt.x, q.x, alpha_chord, bias_minus_chord);

        // affine mode as well
        let mut c1new = alpha_tangent;
        c1new.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new = bias_minus_tangent;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        let mut c1new_2 = alpha_chord;
        c1new_2.mul_assign_by_fp(&(-p.x / p.y));

        let mut c2new_2 = bias_minus_chord;
        c2new_2.mul_assign_by_fp(&(p.y.inverse().unwrap()));

        let (hinted_ell_tangent, hints_ell_tangent) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_tangent, bias_minus_tangent);
        let (hinted_ell_chord, hints_ell_chord) = new_hinted_ell_by_constant_affine(p_dash_x, p_dash_y, alpha_chord, bias_minus_chord);

        let hash_64b_75k = read_script_from_file("blake3_bin/blake3_64b_75k.bin");
        let hash_128b_168k = read_script_from_file("blake3_bin/blake3_128b_168k.bin");

        let bcsize = 6+3;
        let script = script! {
            // hints
            for hint in hints_check_tangent { 
                { hint.push() }
            }
            for hint in hints_ell_tangent { 
                { hint.push() }
            }
            for hint in hints_double_line { 
                { hint.push() }
            }
            for hint in hints_check_chord_q { 
                { hint.push() }
            }
            for hint in hints_check_chord_t { 
                { hint.push() }
            }
            for hint in hints_ell_chord { 
                { hint.push() }
            }
            for hint in hints_add_line { 
                { hint.push() }
            }

            // aux
            { fq2_push_not_montgomery(alpha_chord)}
            { fq2_push_not_montgomery(bias_minus_chord)}
            { fq2_push_not_montgomery(alpha_tangent)}
            { fq2_push_not_montgomery(bias_minus_tangent)}
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }

            // bit commits
            { fq_push_not_montgomery(p_dash_x) }
            { fq_push_not_montgomery(p_dash_y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { Fq::push_zero() } // hash
            { Fq::push_zero() } // hash
            { Fq::push_zero() } // hash
            

            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::copy(bcsize+6)} // t.x
            { Fq2::copy(bcsize+6)} // t.y
            { hinted_check_tangent }

            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(4 + 7) } // p_dash
            { hinted_ell_tangent }
            { Fq2::toaltstack() } // le.0
            { Fq2::toaltstack() } // le.1


            { Fq2::copy(bcsize+4)} // bias
            { Fq2::copy(bcsize+8)} // alpha
            { Fq2::copy(bcsize+6)} // t.x
            { hinted_double_line }
            { Fq2::toaltstack() }
            { Fq2::toaltstack()}
            // { fq2_push_not_montgomery(tt.y) }
            // { Fq2::equalverify() }
            // { fq2_push_not_montgomery(tt.x) }
            // { Fq2::equalverify() }

            { Fq2::roll(bcsize+6) } // alpha tangent drop
            { Fq2::drop() }
            { Fq2::roll(bcsize+4) } // bias tangent drop
            { Fq2::drop() }

            // hinted check chord // t.x, t.y
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::copy(8+1) } // q.x
            { Fq2::copy(8+1) } // q.y
            { hinted_check_chord_q }
            { Fq2::copy(bcsize+6)} // alpha
            { Fq2::copy(bcsize+6)} // bias
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
            { Fq2::copy(2)} // t.x
            { Fq2::toaltstack() }
            { hinted_check_chord_t }


            { Fq2::copy(bcsize+6) } // alpha
            { Fq2::copy(bcsize+6) } // bias
            { Fq2::copy(10+1) } // p_dash
            { hinted_ell_chord }

            { Fq2::roll(4+bcsize+4) } // bias
            { Fq2::roll(6+bcsize+4) } // alpha
            { Fq2::copy(4+4+4+1) } //q.x
            { Fq2::fromaltstack() }
            { hinted_add_line }

            { Fq2::toaltstack() }//R
            { Fq2::toaltstack() }
            
            { Fq2::toaltstack() } //le_add
            { Fq2::toaltstack() } 

  
            { Fq::toaltstack() } //hashes
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }

            //T
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u4()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            {hash_128b_168k.clone()}

            // fetch 1 hash
            { Fq::fromaltstack()} // aux_hash
            {unpack_u32_to_u4()}
            {hash_64b_75k.clone()}
            {pack_u4_to_u32()}
            { Fq::fromaltstack()} //input_hash
            {Fq2::drop()} //{Fq::equalverify(1, 0)}

            for i in 0..13 {
                {Fq::fromaltstack()}
            }

            // Hash le
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u4()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            {hash_128b_168k.clone()}
            {pack_u4_to_u32()}
            {Fq::toaltstack()}
            
            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u4()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            {hash_128b_168k.clone()}
            {pack_u4_to_u32()}
            {Fq::toaltstack()}

            {Fq::roll(1)}
            {Fq::roll(2)}
            {Fq::roll(3)}
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            {unpack_u32_to_u4()} // 0
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            { Fq::fromaltstack()}
            {unpack_u32_to_u4()}
            {hash_128b_168k.clone()}
            //{nibbles_to_fq()}

            // bring back hash
            { Fq::fromaltstack()}
            { unpack_u32_to_u4()}
            {hash_64b_75k.clone()}
            { Fq::fromaltstack()}
            { unpack_u32_to_u4()}
            {hash_64b_75k.clone()}
            {pack_u4_to_u32()}

            {Fq2::drop()} //{Fq::equalverify(1, 0)}
            OP_TRUE
        };

        let len = script.len();
        let res = execute_script(script);
        assert!(res.success);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        println!("script {} stack {}", len, res.stats.max_nb_stack_items);
    }


}