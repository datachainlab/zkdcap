use crate::Result;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

// verify_p256_signature_bytes verifies a P256 ECDSA signature
// using the provided data, signature, and public key.
// The data is the message that was signed as a byte slice.
// The signature is the signature (in raw form [r][s]) of the data as a byte slice. (64 bytes)
// The public_key is the public key (in uncompressed form [4][x][y]) of the entity that signed the data. (65 bytes)
// Returns true if the signature is valid, false otherwise.
pub fn verify_p256_signature_bytes(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
    let signature = Signature::from_bytes(signature.into())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)?;
    Ok(verifying_key.verify(data, &signature)?)
}

pub fn verify_p256_signature_der(
    data: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
) -> Result<()> {
    let signature = Signature::from_der(signature_der)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)?;
    Ok(verifying_key.verify(data, &signature)?)
}

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
