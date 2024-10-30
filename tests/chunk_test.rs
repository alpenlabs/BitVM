
#[cfg(test)]
mod test {
    use bitvm::{chunk::{config::keygen, wots::{generate_assertion_script_public_keys, generate_assertion_spending_key_lengths, generate_verifier_public_keys}}, signatures::winternitz_compact::checksig_verify_with_pubkey};



    #[test]
    fn test_keygen() {
        let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let pub_keys_per_index = keygen(sec_key);
        let mut pub_key_indices: Vec<u32> = pub_keys_per_index.keys().cloned().collect();
        pub_key_indices.sort();
         
        for pub_key_index in pub_key_indices {
            if let Some(pub_key) = pub_keys_per_index.get(&pub_key_index) {
                let locking_script = checksig_verify_with_pubkey(pub_key.clone());
                println!("lsindex {} ls {} bytes", pub_key_index, locking_script.len());
            }
        }
    }

    #[test]
    fn test_keygen_new() {
        let sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let apks = &generate_verifier_public_keys(sec_key);
        let aspks = generate_assertion_script_public_keys(apks);
        let aspk_lengths = generate_assertion_spending_key_lengths(apks);

        println!("apks.len(): {}", apks.p160.len() + apks.p256.len());
        let aspk_lens = aspks.iter().map(|spk| spk.len()).collect::<Vec<_>>();

        println!("aspk.lens: {:?}", aspk_lens);
        println!("aspk_lengths: {:?}", aspk_lengths);
    }
}