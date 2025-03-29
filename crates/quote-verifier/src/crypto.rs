use crate::Result;
use anyhow::bail;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// verify_p256_signature_bytes verifies a P256 ECDSA signature
/// using the provided data, signature, and public key.
///
/// # Arguments
/// * `data` - The data that was signed.
/// * `signature` - The signature is the signature (in raw form \[r\]\[s\]) of the data as a byte slice. (64 bytes)
/// * `public_key` - The public key (in uncompressed form \[4\]\[\x\]\[y\]) of the entity that signed the data. (65 bytes)
/// # Returns
/// * Returns Ok(()) if the signature is valid.
pub fn verify_p256_signature_bytes(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
    validate_uncompressed_ec_pubkey(public_key)?;
    let signature = Signature::from_bytes(signature.into())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)?;
    Ok(verifying_key.verify(data, &signature)?)
}

/// verify_p256_signature_der verifies a P256 ECDSA signature
/// using the provided data, signature, and public key.
///
/// # Arguments
/// * `data` - The data that was signed.
/// * `signature_der` - The der encoded signature of the data as a byte slice.
/// * `public_key` - The public key (in uncompressed form \[4\]\[\x\]\[y\]) of the entity that signed the data. (65 bytes)
/// # Returns
/// * Returns Ok(()) if the signature is valid.
pub fn verify_p256_signature_der(
    data: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
) -> Result<()> {
    validate_uncompressed_ec_pubkey(public_key)?;
    let signature = Signature::from_der(signature_der)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)?;
    Ok(verifying_key.verify(data, &signature)?)
}

/// sha256sum returns the SHA-256 hash of the input data.
pub fn sha256sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&result);
    output
}

/// keccak256sum returns the Keccak-256 hash of the input data.
pub fn keccak256sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&result);
    output
}

fn validate_uncompressed_ec_pubkey(public_key: &[u8]) -> Result<()> {
    if public_key.len() != 65 {
        bail!("Public key must be 65 bytes: got {}", public_key.len());
    } else if public_key[0] != 0x04 {
        bail!(
            "Public key must be uncompressed: got 0x{:02x}",
            public_key[0]
        );
    }
    Ok(())
}
