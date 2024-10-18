use ark_bn254::{G1Affine, G2Affine};

use crate::bn254::chunk_primitves;


#[derive(Debug)]
struct TableRow {
    name: String,
    ID: String,
    Deps: String,
}

fn config_gen()->Vec<Vec<TableRow>> {

    #[derive(Clone)]
    struct TableRowTemplate {
        name: &'static str,
        ID_expr: &'static str,
        Deps_expr: &'static str,
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

    fn run()-> Vec<Vec<TableRow>> {
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
        let mut tables = vec![];
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
            // println!(
            //     "\n---\nTable {} ({})",
            //     table_number,
            //     if table.len() == 6 {
            //         "Half Table"
            //     } else {
            //         "Full Table"
            //     }
            // );
            // println!("{:<5} | {:<5} | Deps", "name", "ID");
            // println!("{}", "-".repeat(40));
            // for row in &table {
            //     println!("{:<5} | {:<5} | {}", row.name, row.ID, row.Deps);
            // }
            table_number += 1;
            tables.push(table);
        }
        return tables;
    }

    run()
}

// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile(vk: (G1Affine, G2Affine, G2Affine, G2Affine)) {
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    let (P1, Q1, Q2, Q3) = vk;

    const ATE_LOOP_COUNT: &'static [i8] = &[
         0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
         0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
         -1, 0, 0, 0, 1, 0, 1, 1,
     ];
    let blocks = config_gen();

    let mut itr = 0;
    let max_id = blocks.last().unwrap().last().unwrap().ID.as_str()[1..].parse::<u32>().ok().unwrap();
    // println!("max id {:?}", max_id);
    let sec_key_for_bitcomms = "b138982ce17ac813d505b5b40b665d404e9528e7";


    fn get_index(blk_name: &str, max_id: u32)-> u32 {
        if blk_name.starts_with("S") {
            return blk_name[1..].parse::<u32>().ok().unwrap();
        } else if blk_name == "P2" {
            return max_id+1;
        } else if blk_name == "P3" {
            return max_id+2;
        } else if blk_name == "P4" {
            return max_id+3;
        } else if blk_name == "Q4" {
            return max_id+4;
        } else if blk_name == "c" {
            return max_id+5;
        } else if blk_name == "cinv" {
            return max_id+6;
        } else {
            println!("unknown blk_name {:?}", blk_name);
            panic!();
        }
    }
    // p2, p3, p4, q4, c, cinv

    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        let blocks_of_a_loop = &blocks[itr];
        for block in blocks_of_a_loop {
            if block.name == "Sqr" {
                // chunk_primitves::tap_squaring(&sec_key_for_bitcomms);
            } else if block.name == "Dbl" {

            } else if block.name == "SD1" {

            } else if block.name == "SS1" {

            } else if block.name == "DD1" {
                
            } else if block.name == "DD2" {
                
            } else if block.name == "DD3" {
                
            } else if block.name == "DD4" {
                
            } else if block.name == "SD2" {
                
            } else if block.name == "SS2" {

            } else if block.name == "DD5" {
                
            } else if block.name == "DD6" {
                
            } else {
                println!("unhandled {:?}", block.name);
                panic!();
            }
        }
        println!("{itr} {:?}", blocks[itr]);
        // squaring
        // point_ops
        // sparse_dense
        // sparse_sparse
        // dense_dense
        itr += 1;
    }   

}

// name;ID;Deps
// Sqr;S1;f;
// Dbl;S2;P4,Q4,T4;
// SD1;S3;S1,S2;
// SS1;S4;P2,P3;
// DD1;S5;S3,S4;
// DD2;S6;S3,S4,S5;
// DD3;S7;S6,c;
// DD4;S8;S6,c,S7;
// SD2;S9;S8,S2;
// SS2;S10;P2,P3;
// DD5;S11;S9,S10;
// DD6;S12;S9,S10,S11;

#[test]
fn compile_test() {
   config_gen();
}