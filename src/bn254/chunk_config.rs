
#[derive(Debug)]
pub(crate) struct TableRow {
    pub(crate) name: String,
    pub(crate) ID: String,
    pub(crate) Deps: String,
}

// these values are agreed during compile time
pub(crate) fn public_params() -> Vec<String> {
    vec![
        String::from("identity"), // hash of Fp12::one()
        String::from("Q3y1"), // vk
        String::from("Q3y0"),
        String::from("Q3x1"),
        String::from("Q3x0"),
        String::from("Q2y1"), // vk
        String::from("Q2y0"),
        String::from("Q2x1"),
        String::from("Q2x0"),
        String::from("f_fixed"), // hash of output of miller loop for fixed P,Q
    ]
}

pub(crate) fn groth16_params() -> Vec<String> {
    let r = vec![
        "GP4y","GP4x",
        "GP3y","GP3x",
        "GP2y","GP2x",
        "Gc11","Gc10","Gc9","Gc8","Gc7","Gc6","Gc5","Gc4","Gc3","Gc2","Gc1","Gc0",
        "c",
        "Gs11","Gs10","Gs9","Gs8","Gs7","Gs6","Gs5","Gs4","Gs3","Gs2","Gs1","Gs0",
        "s",
        "cinv",
        "Q4y1","Q4y0","Q4x1","Q4x0",
        ];
    r.into_iter().map(|f|f.to_string()).collect()
}

pub(crate) fn groth16_derivatives() -> Vec<String> {
    let r = vec![
        "T4",
        "P4y","P4x",
        "P3y","P3x",
        "P2y","P2x",
        "cinv0",
        ];
    r.into_iter().map(|f|f.to_string()).collect()
}

pub(crate) fn post_miller_params() -> Vec<String> {
    let num_params = 22;
    let mut arr = vec![String::from("U"); num_params];
    for i in 0..num_params {
        arr[i] = format!("{}{}", arr[i], i);
    }
    arr
}

pub(crate) fn pre_miller_config_gen() -> Vec<TableRow> {
    let tables: Vec<TableRow> = vec![
        TableRow {name: String::from("T4Init"), ID: String::from("T4"), Deps: String::from("Q4y1,Q4y0,Q4x1,Q4x0")},
        TableRow {name: String::from("PrePy"), ID: String::from("P4y"), Deps: String::from("GP4y")},
        TableRow {name: String::from("PrePx"), ID: String::from("P4x"), Deps: String::from("GP4y,GP4x,P4y")},
        TableRow {name: String::from("PrePy"), ID: String::from("P3y"), Deps: String::from("GP3y")},
        TableRow {name: String::from("PrePx"), ID: String::from("P3x"), Deps: String::from("GP3y,GP3x,P3y")},
        TableRow {name: String::from("PrePy"), ID: String::from("P2y"), Deps: String::from("GP2y")},
        TableRow {name: String::from("PrePx"), ID: String::from("P2x"), Deps: String::from("GP2y,GP2x,P2y")},
        TableRow {name: String::from("HashC"), ID: String::from("c"), Deps: String::from("Gc11,Gc10,Gc9,Gc8,Gc7,Gc6,Gc5,Gc4,Gc3,Gc2,Gc1,Gc0")},
        TableRow {name: String::from("HashC"), ID: String::from("s"), Deps: String::from("Gs11,Gs10,Gs9,Gs8,Gs7,Gs6,Gs5,Gs4,Gs3,Gs2,Gs1,Gs0")},
        TableRow {name: String::from("DD1"), ID: String::from("cinv0"), Deps: String::from("c,cinv")},
        TableRow {name: String::from("DD2"), ID: String::from("identity"), Deps: String::from("c,cinv,cinv0")},
    ];
    tables
}

pub(crate) fn post_miller_config_gen(f_acc: String, t4_acc: String) -> Vec<TableRow> {
    let tables: Vec<TableRow> = vec![
        TableRow {name: String::from("Frob1"), ID: String::from("U0"), Deps: String::from("cinv")},
        TableRow {name: String::from("Frob2"), ID: String::from("U1"), Deps: String::from("c")},
        TableRow {name: String::from("Frob3"), ID: String::from("U2"), Deps: String::from("cinv")},

        TableRow {name: String::from("DD1"), ID: String::from("U3"), Deps: String::from(format!("{f_acc},s"))},
        TableRow {name: String::from("DD2"), ID: String::from("U4"), Deps: String::from(format!("{f_acc},s,U3"))},
        TableRow {name: String::from("DD1"), ID: String::from("U5"), Deps: String::from("U4,U0")},
        TableRow {name: String::from("DD2"), ID: String::from("U6"), Deps: String::from("U4,U0,U5")},
        TableRow {name: String::from("DD1"), ID: String::from("U7"), Deps: String::from("U6,U1")},
        TableRow {name: String::from("DD2"), ID: String::from("U8"), Deps: String::from("U6,U1,U7")},
        TableRow {name: String::from("DD1"), ID: String::from("U9"), Deps: String::from("U8,U2")},
        TableRow {name: String::from("DD2"), ID: String::from("U10"), Deps: String::from("U8,U2,U9")},

        TableRow {name: String::from("Add1"), ID: String::from("U11"), Deps: String::from(format!("{t4_acc},Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x"))},
        TableRow {name: String::from("SD"), ID: String::from("U12"), Deps: String::from("U10,U11")},
        TableRow {name: String::from("SS"), ID: String::from("U13"), Deps: String::from("P3y,P3x,P2y,P2x")},
        TableRow {name: String::from("DD1"), ID: String::from("U14"), Deps: String::from("U12,U13")},
        TableRow {name: String::from("DD2"), ID: String::from("U15"), Deps: String::from("U12,U13,U14")},

        TableRow {name: String::from("Add2"), ID: String::from("U16"), Deps: String::from("U11,Q4y1,Q4y0,Q4x1,Q4x0,P4y,P4x")},
        TableRow {name: String::from("SD"), ID: String::from("U17"), Deps: String::from("U15,U16")},
        TableRow {name: String::from("SS"), ID: String::from("U18"), Deps: String::from("P3y,P3x,P2y,P2x")},
        TableRow {name: String::from("DD1"), ID: String::from("U19"), Deps: String::from("U17,U18")},
        TableRow {name: String::from("DD2"), ID: String::from("U20"), Deps: String::from("U17,U18,U19")},

        TableRow {name: String::from("DD3"), ID: String::from("U21"), Deps: String::from("U20,f_fixed")},
        TableRow {name: String::from("DD4"), ID: String::from("identity"), Deps: String::from("U20,f_fixed,U21")},
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
pub(crate) fn miller_config_gen()->Vec<Vec<TableRow>> {


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

