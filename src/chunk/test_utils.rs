use crate::treepp::*;
use bitcoin::ScriptBuf;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;

use super::wots::WOTSPubKey;


pub(crate) fn serialize_pubkey(pubkey: WOTSPubKey) -> Vec<Vec<u8>> {
    match pubkey {
        WOTSPubKey::P160(p) => {
            let mut v = Vec::new();
            for i in p {
                v.push(i.to_vec());
            }
            v
        },
        WOTSPubKey::P256(p) => {
            let mut v = Vec::new();
            for i in p {
                v.push(i.to_vec());
            }
            v
        }
    }
}

// hardcoded values shouldn't be used, 
// but will make do for now, until wots::PublicKey support SerDe trait
// besides this entire module is for testing purpose only
pub(crate) fn deserialize_pubkey(ser: Vec<Vec<u8>>) -> Option<WOTSPubKey> {
    if ser.len() == 67 {
        let mut ps: [[u8;20]; 67] = [[0u8;20];67];
        for pi in 0..ser.len() {
            let en:[u8;20] = ser[pi].clone().try_into().unwrap();
            ps[pi] = en;
        }
        return Some(WOTSPubKey::P256(ps));
    } else if ser.len() == 43 {
        let mut ps: [[u8;20]; 43] = [[0u8;20];43];
        for pi in 0..ser.len() {
            let en:[u8;20] = ser[pi].clone().try_into().unwrap();
            ps[pi] = en;
        }
        return Some(WOTSPubKey::P160(ps));
    } 
    None
}

pub(crate) fn write_pubkey_to_file(
    map: &HashMap<u32, WOTSPubKey>,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    // Serialize the map to a JSON string
    let mut serializable_map: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    for (k, v) in map {
        let vs = serialize_pubkey(v.clone());
        serializable_map.insert(*k, vs);
    }
    write_map_to_file(&serializable_map, filename)
}

pub(crate) fn read_pubkey_from_file(filename: &str) -> Result<HashMap<u32, WOTSPubKey>, Box<dyn Error>> {
    let serialized_map = read_map_from_file(filename)?;
    let mut map = HashMap::new();
    for (k, v) in serialized_map {
        let vs = deserialize_pubkey(v).unwrap();
        map.insert(k, vs);
    }
    Ok(map)
}

pub(crate) fn write_map_to_file(
    map: &HashMap<u32, Vec<Vec<u8>>>,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    // Serialize the map to a JSON string
    let json = serde_json::to_string(map)?;

    // Write the JSON string to a file
    let mut file = File::create(filename)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(crate) fn read_map_from_file(
    filename: &str,
) -> Result<HashMap<u32, Vec<Vec<u8>>>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader)?;
    Ok(map)
}

pub fn write_scripts_to_file(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
    let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    for (k, v) in sig_cache {
        let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
        buf.insert(k, vs);
    }
    write_map_to_file(&buf, file).unwrap();
}

pub fn write_scripts_to_separate_files(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
    let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
    for (k, v) in sig_cache {
        let file = format!("chunker_data/{file}_{k}.json");
        let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
        buf.insert(k, vs);
        write_map_to_file(&buf, &file).unwrap();
        buf.clear();
    }
}

pub fn read_scripts_from_file(file: &str) -> HashMap<u32, Vec<Script>> {
    let mut scr: HashMap<u32, Vec<Script>> = HashMap::new();
    let f = read_map_from_file(file).unwrap();
    for (k, v) in f {
        let vs: Vec<Script> = v
            .into_iter()
            .map(|x| {
                let sc = script! {};
                let bf = ScriptBuf::from_bytes(x);
                let sc = sc.push_script(bf);
                sc
            })
            .collect();
        scr.insert(k, vs);
    }
    scr
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, io, ops::Neg};

    use ark_ec::{AffineRepr, CurveGroup};
    use bitcoin_script::script;

    use crate::{
        chunk::{
            config::keygen,
            taps::{bitcom_precompute_Py, tap_precompute_Py},
        },
        groth16::offchain_checker::compute_c_wi,
    };

    use super::{read_scripts_from_file, write_scripts_to_file};

    #[test]
    fn test_read_write_script() {
        let sec_out = (56, true);
        let sec_in = vec![(14, true)];
        let master_secret = "b138982ce17ac813d505b5b40b665d404e9528e7";

        let pub_scripts_per_link_id = &keygen(master_secret);
        let tap = tap_precompute_Py();
        let bc = bitcom_precompute_Py(pub_scripts_per_link_id, sec_out, sec_in);
        let script = script! {
            {bc}
            {tap}
        };

        let mut cache = HashMap::new();
        cache.insert(sec_out.0, vec![script.clone()]);
        write_scripts_to_file(cache, "/tmp/tmp.json");
        let read = read_scripts_from_file("/tmp/tmp.json");
        let read = read.get(&sec_out.0).unwrap().first().unwrap();
        assert_eq!(read.len(), script.len());
        assert_eq!(
            read.clone().compile().to_bytes(),
            script.compile().to_bytes()
        );
    }
}
