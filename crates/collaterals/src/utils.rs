use chrono::{TimeZone, Utc};
use der::{asn1::Uint, Decode, Sequence};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
    sign::Signer,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer, x509::SubjectPublicKeyInfo};

pub fn gen_key() -> PKey<Private> {
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    PKey::from_ec_key(ec_key).unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EcdsaSignature {
    pub r: Uint,
    pub s: Uint,
}

pub fn sign(pkey: &PKeyRef<Private>, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)?;
    signer.update(msg)?;
    EcdsaSignature::from_der(signer.sign_to_vec()?.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to decode ASN.1 signature: {}", e))
        .map(|asn_sig| {
            let mut sig = vec![];
            let r = asn_sig.r.as_bytes();
            let s = asn_sig.s.as_bytes();
            sig.extend_from_slice(&vec![0; 32 - r.len()]);
            sig.extend_from_slice(r);
            sig.extend_from_slice(&vec![0; 32 - s.len()]);
            sig.extend_from_slice(s);
            sig
        })
}

pub fn p256_prvkey_to_pubkey_bytes(pkey: &PKeyRef<Private>) -> Result<[u8; 64], anyhow::Error> {
    let der = pkey
        .public_key_to_der()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {}", e))?;
    let bz = SubjectPublicKeyInfo::from_der(der.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse SubjectPublicKeyInfo: {}", e))
        .map(|(_, spki)| spki.subject_public_key.data)?;
    let mut pubkey = [0; 64];
    // The first byte is 0x04, which is the tag for an uncompressed point.
    pubkey.copy_from_slice(&bz[1..]);
    Ok(pubkey)
}

pub fn parse_cert_der(cert_der: &[u8]) -> Result<X509Certificate<'_>, anyhow::Error> {
    let (_, c) = X509Certificate::from_der(cert_der)?;
    Ok(c)
}

pub fn unix_timestamp_to_rfc3339(timestamp_secs: i64) -> String {
    Utc.timestamp_opt(timestamp_secs, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "Invalid timestamp".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::{gen_sgx_intel_root_ca, Validity};

    #[test]
    fn test_parse_cert_der() {
        let pkey = gen_key();
        let cert = gen_sgx_intel_root_ca(&pkey, Validity::new(1524607999, 2524607999)).unwrap();
        println!("{}", String::from_utf8(cert.to_pem().unwrap()).unwrap());
        let bz = cert.to_der().unwrap();
        let cert2 = parse_cert_der(bz.as_ref()).unwrap();
        assert_eq!(
            cert2.serial.to_bytes_be(),
            cert.serial_number().to_bn().unwrap().to_vec()
        );
    }
}
