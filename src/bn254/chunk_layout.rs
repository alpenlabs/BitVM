
use crate::bn254::chunk_primitves;
use crate::{
    treepp::*,
};

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
            Deps_updated = Deps_updated.trim_end_matches(',').to_string();
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
        let mut f_value = String::from("cinv"); // Starting value of f
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
                Deps_expr: "T4_value,P4y,P4x;",
            },
            TableRowTemplate {
                name: "SD1",
                ID_expr: "Sx+2",
                Deps_expr: "Sx,Sx+1;",
            },
            TableRowTemplate {
                name: "SS1",
                ID_expr: "Sx+3",
                Deps_expr: "P3y,P3x,P2y,P2x;",
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
            let v = vec![
                TableRowTemplate {
                    name: "Sqr",
                    ID_expr: "Sx",
                    Deps_expr: "f_value;",
                },
                TableRowTemplate {
                    name: "DblAdd",
                    ID_expr: "Sx+1",
                    Deps_expr: "T4_value,Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x;",
                },
                TableRowTemplate {
                    name: "SD1",
                    ID_expr: "Sx+2",
                    Deps_expr: "Sx,Sx+1;",
                },
                TableRowTemplate {
                    name: "SS1",
                    ID_expr: "Sx+3",
                    Deps_expr: "P3y,P3x,P2y,P2x;",
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
                    Deps_expr: "P3y,P3x,P2y,P2x;",
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
            ];
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
            tables.push(table);
        }
        return tables;
    }

    run()
}

// given a groth16 verification key, generate all of the tapscripts in compile mode
fn compile() {
    // vk: (G1Affine, G2Affine, G2Affine, G2Affine)
    // groth16 is 1 G2 and 2 G1, P4, Q4, 
    // e(A,B)⋅e(vkα ,vkβ)=e(C,vkδ)⋅e(vkγ_ABC,vkγ)
    // e(P4,Q4).e(P1,Q1) = e(P2,Q2).e(P3,Q3)
    // P3 = vk_0 + msm(vk_i, k_i)

    // Verification key is P1, Q1, Q2, Q3
    // let (P1, Q1, Q2, Q3) = vk;

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


    fn get_index(blk_name: &str, max_id: u32)-> Vec<u32> {
        if blk_name.starts_with("S") {
            return vec![blk_name[1..].parse::<u32>().ok().unwrap()];
        } else if blk_name == "P2" {
            return vec![max_id+1, max_id+2];
        } else if blk_name == "P3" {
            return vec![max_id+3, max_id+4]; 
        } else if blk_name == "P4" {
            return vec![max_id+5, max_id+6]; // y,x
        } else if blk_name == "Q4" {
            return vec![max_id+7, max_id+8, max_id+9, max_id+10]; // y1,y0,x1,x0
        } else if blk_name == "c" {
            return vec![max_id+11];
        } else if blk_name == "cinv" {
            return vec![max_id+12];
        } else if blk_name == "T4" {
            return vec![max_id+13];
        } else {
            println!("unknown blk_name {:?}", blk_name);
            panic!();
        }
    }
    fn get_deps(deps: &str, max_id: u32) -> Vec<u32> {
        let splits: Vec<Vec<u32>>= deps.split(",").into_iter().map(|s| get_index(s, max_id)).collect();
        splits.into_iter().flatten().collect()
    }

    fn get_script(blk_name: &str, sec_key_for_bitcomms: &str, self_index: u32, deps_indices: Vec<u32>) -> Script {
        if blk_name == "Sqr" {
            chunk_primitves::tap_squaring(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "Dbl" {
            chunk_primitves::tap_point_ops(sec_key_for_bitcomms, self_index, deps_indices, 0);
        } else if blk_name == "SD1" {
            chunk_primitves::tap_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, true);
        } else if blk_name == "SS1" {
            //chunk_primitves::tap_double_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "DD1" {
            chunk_primitves::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "DD2" {
            chunk_primitves::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "DD3" {
            chunk_primitves::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "DD4" {
            chunk_primitves::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "SD2" {
            chunk_primitves::tap_sparse_dense_mul(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "SS2" {
            //chunk_primitves::tap_add_eval_mul_for_fixed_Qs(sec_key_for_bitcomms, self_index, deps_indices);
        } else if blk_name == "DD5" {
            chunk_primitves::tap_dense_dense_mul0(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else if blk_name == "DD6" {
            chunk_primitves::tap_dense_dense_mul1(sec_key_for_bitcomms, self_index, deps_indices, false);
        } else {
            println!("unhandled {:?}", blk_name);
            panic!();
        }
        script!{}
    }

    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        let blocks_of_a_loop = &blocks[itr];
        for block in blocks_of_a_loop {
            let self_index = get_index(&block.ID, max_id);
            assert_eq!(self_index.len(), 1);
            let deps_indices = get_deps(&block.Deps, max_id);
            let tap = get_script(&block.name, sec_key_for_bitcomms, self_index[0], deps_indices);
            let selfid = get_index(&block.ID, max_id);
            let depsid = get_deps(&block.Deps, max_id);
            println!("{itr} {} ID {:?} deps {:?}", block.name, selfid, depsid);
        }
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
// SS1;S4;P3,P2;
// DD1;S5;S3,S4;
// DD2;S6;S3,S4,S5;
// DD3;S7;S6,c;
// DD4;S8;S6,c,S7;
// SD2;S9;S8,S2;
// SS2;S10;P3,P2;
// DD5;S11;S9,S10;
// DD6;S12;S9,S10,S11;

#[test]
fn compile_test() {
   config_gen();
}