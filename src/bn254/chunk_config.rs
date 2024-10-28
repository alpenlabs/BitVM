use std::collections::HashMap;

use ark_ec::bn::BnConfig;

use crate::signatures::{winternitz_compact::{self, get_pub_key, WOTSPubKey}, winterntiz_compact_hash};

pub const ATE_LOOP_COUNT: &'static [i8] = ark_bn254::Config::ATE_LOOP_COUNT;


#[derive(Debug)]
pub(crate) struct ScriptItem {
    pub(crate) category: String, // script category
    pub(crate) link_id: String,  // link identifier
    pub(crate) dependencies: String, 
    pub(crate) is_type_field: bool, // output type
}

// these values are agreed during compile time
pub(crate) fn public_params_config_gen() -> Vec<ScriptItem> {
    let mut r = vec![];
    let r1 = vec![
        String::from("identity")
    ]; // hash of Fp12::one()
    for item in r1 {
        r.push(ScriptItem {category:String::from("PubHashIden"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    let r2 = vec![String::from("Q3y1"), // vk
        String::from("Q3y0"),
        String::from("Q3x1"),
        String::from("Q3x0"),
        String::from("Q2y1"), // vk
        String::from("Q2y0"),
        String::from("Q2x1"),
        String::from("Q2x0")];
    for item in r2 {
        r.push(ScriptItem {category:String::from("PubVK"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    let r3 = vec![
            String::from("f_fixed"), // hash of output of miller loop for fixed P,Q
        ];
    for item in r3 {
        r.push(ScriptItem {category:String::from("PubHashFixedAcc"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    r
}

pub(crate) fn groth16_config_gen() -> Vec<ScriptItem> {
    let mut r = vec![];
    let r1 = vec![
        "GP4y","GP4x",
        "GP3y","GP3x",
        "GP2y","GP2x"];
    for item in r1 {
        r.push(ScriptItem {category:String::from("GrothG1"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    let r2 = vec!["Gc11","Gc10","Gc9","Gc8","Gc7","Gc6","Gc5","Gc4","Gc3","Gc2","Gc1","Gc0"];
    for item in r2 {
        r.push(ScriptItem {category:String::from("GrothAuxC"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    let r3 = vec!["c","c2"];
    for item in r3 {
        r.push(ScriptItem {category:String::from("GrothAuxHash"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    let r4 = vec!["Gs11","Gs10","Gs9","Gs8","Gs7","Gs6","Gs5","Gs4","Gs3","Gs2","Gs1","Gs0"];
    for item in r4 {
        r.push(ScriptItem {category:String::from("GrothAuxS"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    let r5 = vec!["s","cinv","cinv2"];
    for item in r5 {
        r.push(ScriptItem {category:String::from("GrothAuxHash"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    let r6 = vec!["Q4y1","Q4y0","Q4x1","Q4x0"];
    for item in r6 {
        r.push(ScriptItem {category:String::from("GrothG2"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    r
}

pub(crate) fn premiller_config_gen() -> Vec<ScriptItem> {
    let mut r = vec![];
    let r1 = vec!["T4"];
    for item in r1 {
        r.push(ScriptItem {category:String::from("PreMiller"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    let r2 = vec!["P4y","P4x","P3y","P3x","P2y","P2x"];
    for item in r2 {
        r.push(ScriptItem {category:String::from("PreMiller"), link_id: String::from(item), dependencies:String::new(), is_type_field: true})
    }
    let r3 = vec!["cinv0"];
    for item in r3 {
        r.push(ScriptItem {category:String::from("PreMiller"), link_id: String::from(item), dependencies:String::new(), is_type_field: false})
    }
    r
}

pub(crate) fn pre_miller_config_gen() -> Vec<ScriptItem> {
    let tables: Vec<ScriptItem> = vec![
        ScriptItem {category: String::from("T4Init"), link_id: String::from("T4"), dependencies: String::from("Q4y1,Q4y0,Q4x1,Q4x0"), is_type_field: false},
        ScriptItem {category: String::from("PrePy"), link_id: String::from("P4y"), dependencies: String::from("GP4y"), is_type_field: true},
        ScriptItem {category: String::from("PrePx"), link_id: String::from("P4x"), dependencies: String::from("GP4y,GP4x,P4y"), is_type_field: true},
        ScriptItem {category: String::from("PrePy"), link_id: String::from("P3y"), dependencies: String::from("GP3y"), is_type_field: true},
        ScriptItem {category: String::from("PrePx"), link_id: String::from("P3x"), dependencies: String::from("GP3y,GP3x,P3y"), is_type_field: true},
        ScriptItem {category: String::from("PrePy"), link_id: String::from("P2y"), dependencies: String::from("GP2y"), is_type_field: true},
        ScriptItem {category: String::from("PrePx"), link_id: String::from("P2x"), dependencies: String::from("GP2y,GP2x,P2y"), is_type_field: true},
        ScriptItem {category: String::from("HashC"), link_id: String::from("c"), dependencies: String::from("Gc11,Gc10,Gc9,Gc8,Gc7,Gc6,Gc5,Gc4,Gc3,Gc2,Gc1,Gc0"), is_type_field: false},
        ScriptItem {category: String::from("HashC2"), link_id: String::from("c2"), dependencies: String::from("c"), is_type_field: false},
        ScriptItem {category: String::from("HashC2"), link_id: String::from("cinv2"), dependencies: String::from("cinv"), is_type_field: false},
        ScriptItem {category: String::from("HashC"), link_id: String::from("s"), dependencies: String::from("Gs11,Gs10,Gs9,Gs8,Gs7,Gs6,Gs5,Gs4,Gs3,Gs2,Gs1,Gs0"), is_type_field: false},
        ScriptItem {category: String::from("DD1"), link_id: String::from("cinv0"), dependencies: String::from("c2,cinv"), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("identity"), dependencies: String::from("c2,cinv,cinv0"), is_type_field: false},
    ];
    tables
}

pub(crate) fn post_miller_config_gen(f_acc: String, t4_acc: String) -> Vec<ScriptItem> {
    let tables: Vec<ScriptItem> = vec![
        ScriptItem {category: String::from("Frob1"), link_id: String::from("U0"), dependencies: String::from("cinv"), is_type_field: false},
        ScriptItem {category: String::from("Frob2"), link_id: String::from("U1"), dependencies: String::from("c"), is_type_field: false},
        ScriptItem {category: String::from("Frob3"), link_id: String::from("U2"), dependencies: String::from("cinv"), is_type_field: false},

        ScriptItem {category: String::from("DD1"), link_id: String::from("U3"), dependencies: String::from(format!("{f_acc},s")), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("U4"), dependencies: String::from(format!("{f_acc},s,U3")), is_type_field: false},
        ScriptItem {category: String::from("DD1"), link_id: String::from("U5"), dependencies: String::from("U4,U0"), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("U6"), dependencies: String::from("U4,U0,U5"), is_type_field: false},
        ScriptItem {category: String::from("DD1"), link_id: String::from("U7"), dependencies: String::from("U6,U1"), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("U8"), dependencies: String::from("U6,U1,U7"), is_type_field: false},
        ScriptItem {category: String::from("DD1"), link_id: String::from("U9"), dependencies: String::from("U8,U2"), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("U10"), dependencies: String::from("U8,U2,U9"), is_type_field: false},

        ScriptItem {category: String::from("Add1"), link_id: String::from("U11"), dependencies: String::from(format!("{t4_acc},Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x")), is_type_field: false},
        ScriptItem {category: String::from("SD"), link_id: String::from("U12"), dependencies: String::from("U10,U11"), is_type_field: false},
        ScriptItem {category: String::from("SS1"), link_id: String::from("U13"), dependencies: String::from("P3y,P3x,P2y,P2x"), is_type_field: false},
        ScriptItem {category: String::from("DD3"), link_id: String::from("U14"), dependencies: String::from("U12,U13"), is_type_field: false},
        ScriptItem {category: String::from("DD4"), link_id: String::from("U15"), dependencies: String::from("U12,U13,U14"), is_type_field: false},

        ScriptItem {category: String::from("Add2"), link_id: String::from("U16"), dependencies: String::from("U11,Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x"), is_type_field: false},
        ScriptItem {category: String::from("SD"), link_id: String::from("U17"), dependencies: String::from("U15,U16"), is_type_field: false},
        ScriptItem {category: String::from("SS2"), link_id: String::from("U18"), dependencies: String::from("P3y,P3x,P2y,P2x"), is_type_field: false},
        ScriptItem {category: String::from("DD3"), link_id: String::from("U19"), dependencies: String::from("U17,U18"), is_type_field: false},
        ScriptItem {category: String::from("DD4"), link_id: String::from("U20"), dependencies: String::from("U17,U18,U19"), is_type_field: false},

        ScriptItem {category: String::from("DD1"), link_id: String::from("U21"), dependencies: String::from("U20,f_fixed"), is_type_field: false},
        ScriptItem {category: String::from("DD2"), link_id: String::from("fin"), dependencies: String::from("U20,f_fixed,U21"), is_type_field: false},
    //// SS1;S4;P3,P2;
    ];
    tables
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
pub(crate) fn miller_config_gen()->Vec<Vec<ScriptItem>> {


    #[derive(Clone)]
    struct ScriptRowTemplate {
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
        structure: &[ScriptRowTemplate],
        start_id: i32,
        f_value: &str,
        T4_value: &str,
        replace_c: bool,
    ) -> Vec<ScriptItem> {
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
            table.push(ScriptItem {
                category: name,
                link_id: ID_str,
                dependencies: Deps_updated,
                is_type_field: false,
            });
        }
        table
    }

    fn run()-> Vec<Vec<ScriptItem>> {
        // Array specifying the type of table to generate

        // Initialize the ID counter
        let mut id_counter = 1;

        // Initial values for f and T4
        let mut f_value = String::from("cinv2"); // Starting value of f
        let mut T4_value = String::from("T4"); // Starting value of T4

        // Define the half and full table structures
        let half_table_structure = vec![
            ScriptRowTemplate {
                name: "Sqr",
                ID_expr: "Sx",
                Deps_expr: "f_value;",
            },
            ScriptRowTemplate {
                name: "Dbl",
                ID_expr: "Sx+1",
                Deps_expr: "T4_value,P4y,P4x;",
            },
            ScriptRowTemplate {
                name: "SD1",
                ID_expr: "Sx+2",
                Deps_expr: "Sx,Sx+1;",
            },
            ScriptRowTemplate {
                name: "SS1",
                ID_expr: "Sx+3",
                Deps_expr: "P3y,P3x,P2y,P2x;",
            },
            ScriptRowTemplate {
                name: "DD1",
                ID_expr: "Sx+4",
                Deps_expr: "Sx+2,Sx+3;",
            },
            ScriptRowTemplate {
                name: "DD2",
                ID_expr: "Sx+5",
                Deps_expr: "Sx+2,Sx+3,Sx+4;",
            },
        ];

        let full_table_structure = {
            let v = vec![
                ScriptRowTemplate {
                    name: "Sqr",
                    ID_expr: "Sx",
                    Deps_expr: "f_value;",
                },
                ScriptRowTemplate {
                    name: "DblAdd",
                    ID_expr: "Sx+1",
                    Deps_expr: "T4_value,Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x;",
                },
                ScriptRowTemplate {
                    name: "SD1",
                    ID_expr: "Sx+2",
                    Deps_expr: "Sx,Sx+1;",
                },
                ScriptRowTemplate {
                    name: "SS1",
                    ID_expr: "Sx+3",
                    Deps_expr: "P3y,P3x,P2y,P2x;",
                },
                ScriptRowTemplate {
                    name: "DD1",
                    ID_expr: "Sx+4",
                    Deps_expr: "Sx+2,Sx+3;",
                },
                ScriptRowTemplate {
                    name: "DD2",
                    ID_expr: "Sx+5",
                    Deps_expr: "Sx+2,Sx+3,Sx+4;",
                },
                ScriptRowTemplate {
                    name: "DD3",
                    ID_expr: "Sx+6",
                    Deps_expr: "Sx+5,c;",
                },
                ScriptRowTemplate {
                    name: "DD4",
                    ID_expr: "Sx+7",
                    Deps_expr: "Sx+5,c,Sx+6;",
                },
                ScriptRowTemplate {
                    name: "SD2",
                    ID_expr: "Sx+8",
                    Deps_expr: "Sx+7,Sx+1;",
                },
                ScriptRowTemplate {
                    name: "SS2",
                    ID_expr: "Sx+9",
                    Deps_expr: "P3y,P3x,P2y,P2x;",
                },
                ScriptRowTemplate {
                    name: "DD5",
                    ID_expr: "Sx+10",
                    Deps_expr: "Sx+8,Sx+9;",
                },
                ScriptRowTemplate {
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
        for j in (1..ATE_LOOP_COUNT.len()).rev() {
            let i = ATE_LOOP_COUNT[j-1];
            let table;
            if i == 0 {
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
            } else if i == 1 {
                // Generate a full table
                table = generate_table(
                    &full_table_structure,
                    id_counter,
                    &f_value,
                    &T4_value,
                    true, // 1 => cinv
                );
                // Update f_value and T4_value based on the full table
                f_value = format!("S{}", id_counter + 11); // ID of DD6
                T4_value = format!("S{}", id_counter + 1); // ID of Dbl
                id_counter += 12; // Full table uses 12 IDs
            } else if i == -1 {
                // Generate a full table with c replaced by cinv
                table = generate_table(
                    &full_table_structure,
                    id_counter,
                    &f_value,
                    &T4_value,
                    false, // -1 => c
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


fn assign_ids_to_public_params(start_identifier: u32) -> HashMap<String, (u32, bool)> {
    let pub_params = public_params_config_gen();
    let mut name_to_id: HashMap<String, (u32, bool)> = HashMap::new();
    for i in 0..pub_params.len() {
        name_to_id.insert( pub_params[i].link_id.clone(), (start_identifier + i as u32, pub_params[i].is_type_field));
    }
    name_to_id
}


fn assign_ids_to_groth16_params(start_identifier: u32) -> HashMap<String, (u32, bool)> {
    let g_params = groth16_config_gen();
    let mut name_to_id: HashMap<String, (u32, bool)> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].link_id.clone(), (start_identifier + i as u32, g_params[i].is_type_field));
    }
    name_to_id
}

fn assign_ids_to_premiller_params(start_identifier: u32) -> HashMap<String, (u32, bool)> {
    let g_params = premiller_config_gen();
    let mut name_to_id: HashMap<String, (u32, bool)> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].link_id.clone(), (start_identifier + i as u32, g_params[i].is_type_field));
    }
    name_to_id
}

fn assign_ids_to_miller_blocks(start_identifier: u32)-> (HashMap<String, (u32, bool)>, String, String) {
    let g_params = miller_config_gen();
    let mut name_to_id: HashMap<String, (u32, bool)> = HashMap::new();
    let mut counter = 0;
    let mut last_f_block_id = String::new();
    let mut last_t4_block_id = String::new();
    for t in g_params {
        for r in t {
            name_to_id.insert(r.link_id.clone(), (start_identifier + counter as u32, r.is_type_field));
            counter += 1;
            if r.category.starts_with("DD") {
                last_f_block_id = r.link_id;
            } else if r.category.starts_with("Dbl") {
                last_t4_block_id = r.link_id;
            }
        }
    }
    (name_to_id, last_f_block_id, last_t4_block_id)
}

fn assign_ids_to_postmiller_params(start_identifier: u32) -> HashMap<String, (u32, bool)> {
    let g_params = post_miller_config_gen(String::new(), String::new());
    let mut name_to_id: HashMap<String, (u32, bool)> = HashMap::new();
    for i in 0..g_params.len() {
        name_to_id.insert( g_params[i].link_id.clone(), (start_identifier + i as u32, g_params[i].is_type_field));
    }
    name_to_id
}

pub(crate) fn assign_link_ids() -> (HashMap<String, (u32, bool)>, String, String) {
    let mut all_ids: HashMap<String, (u32, bool)> = HashMap::new();
    let mut total_len = 0;
    let pubp = assign_ids_to_public_params(0);
    total_len += pubp.len();
    let grothp = assign_ids_to_groth16_params(total_len as u32);
    total_len += grothp.len();
    let premillp = assign_ids_to_premiller_params(total_len as u32);
    total_len += premillp.len();
    let (millp, f_blk, t4_blk) = assign_ids_to_miller_blocks(total_len as u32);
    total_len += millp.len();
    let postmillp = assign_ids_to_postmiller_params(total_len as u32);
    total_len += postmillp.len();

    all_ids.extend(pubp.clone());
    all_ids.extend(grothp.clone());
    all_ids.extend(premillp.clone());
    all_ids.extend(millp.clone());
    all_ids.extend(postmillp.clone());
    assert_eq!(pubp.len() + grothp.len() + premillp.len() + millp.len() + postmillp.len(), all_ids.len());
    (all_ids, f_blk, t4_blk)
}

pub fn keygen(msk: &str) -> HashMap<u32, WOTSPubKey> {
    // given master secret key and number of links, generate pub keys
    let (links, _,_) = assign_link_ids();
    let mut scripts = HashMap::new();
    for (_, link) in links {
        let link_id = link.0;
        let mut pub_key = vec![];
        if link.1 {
            pub_key = winternitz_compact::get_pub_key(&format!("{}{:04X}", msk, link.0));
        } else {
            pub_key = winterntiz_compact_hash::get_pub_key(&format!("{}{:04X}", msk, link.0));
        }
        //let s = checksig_verify_fq(pub_key);
        scripts.insert(link_id as u32, pub_key);
    }
    scripts
}
