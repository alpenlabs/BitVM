
#[cfg(test)]
mod test {
    use bitvm::{bn254::chunk_compile::keygen, signatures::winternitz_compact::checksig_verify_fq};


    #[test]
    fn test_keygen() {
        let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pub_keys_per_index = keygen(sec_key);
        let mut pub_key_indices: Vec<u32> = pub_keys_per_index.keys().cloned().collect();
        pub_key_indices.sort();
         
        for pub_key_index in pub_key_indices {
            if let Some(pub_key) = pub_keys_per_index.get(&pub_key_index) {
                let locking_script = checksig_verify_fq(pub_key.clone());
                println!("lsindex {} ls {} bytes", pub_key_index, locking_script.len());
            }
        }
    }
}