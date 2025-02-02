use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub fn sha256sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&result);
    output
}

pub fn keccak256sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&result);
    output
}
