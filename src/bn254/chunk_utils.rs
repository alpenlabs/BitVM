use bitcoin::ScriptBuf;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::io::BufReader;
use crate::{
    treepp::*,
};

fn write_map_to_file(map: &HashMap<u32, Vec<Vec<u8>>>, filename: &str) -> Result<(), Box<dyn Error>> {
    // Serialize the map to a JSON string
    let json = serde_json::to_string(map)?;

    // Write the JSON string to a file
    let mut file = File::create(filename)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn read_map_from_file(filename: &str) -> Result<HashMap<u32, Vec<Vec<u8>>>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader)?;
    Ok(map)
}

pub fn dump_assertions_to_a_file(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
    let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    for (k, v) in sig_cache {
        let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
        buf.insert(k, vs);
    }
    // let file = "assertion.json";
    write_map_to_file(&buf, file).unwrap();
}

pub fn read_assertions_from_a_file(file: &str) -> HashMap<u32, Vec<Script>> {
    let mut scr: HashMap<u32, Vec<Script>> = HashMap::new();
    let f = read_map_from_file(file).unwrap();
    for (k, v) in f {
        let vs: Vec<Script> = v.into_iter().map(|x| {
            let sc = script!{};
            let bf = ScriptBuf::from_bytes(x);
            let sc = sc.push_script(bf);
            sc
        }).collect();
        scr.insert(k, vs);
    }
    scr
}