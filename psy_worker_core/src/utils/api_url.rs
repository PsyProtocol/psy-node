use parth_crypto::hash::sha256::CoreSha256Hasher;

pub fn hash_api_url_to_32_bytes(api_url: &str) -> [u8; 32] {
    let api_url_bytes = api_url.as_bytes();
    if api_url_bytes.len() <= 32 {
        let mut padded_bytes = [0u8; 32];
        padded_bytes[..api_url_bytes.len()].copy_from_slice(api_url_bytes);

        padded_bytes
    }else{
        CoreSha256Hasher::hash_bytes(api_url.as_bytes()).0
    }
}