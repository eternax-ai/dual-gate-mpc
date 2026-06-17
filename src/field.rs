use ark_ff::PrimeField;
use ark_secp256k1::Fr;
use sha2::{Digest, Sha256};

/// Domain-separated hash to field element: H(domain || data) -> Fr.
pub fn hash_to_field(domain: &[u8], data: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(data);
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

/// Serialize a field element to 32 bytes (big-endian).
pub fn field_to_bytes(x: &Fr) -> [u8; 32] {
    let bigint = x.into_bigint();
    let limbs = bigint.0;
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    bytes.reverse();
    bytes
}
