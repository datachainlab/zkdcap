use x509_parser::oid_registry::asn1_rs::FromDer;
use x509_parser::prelude::*;

pub fn pem_to_der(pem_bytes: &[u8]) -> Result<Vec<u8>, PEMError> {
    // convert from raw pem bytes to pem objects
    let pems = parse_pem(pem_bytes)?;
    // convert from pem objects to der bytes
    // to make it more optimize, we'll read get all the lengths of the der bytes
    // and then allocate the buffer once
    let der_bytes_len: usize = pems.iter().map(|pem| pem.contents.len()).sum();
    let mut der_bytes = Vec::with_capacity(der_bytes_len);
    for pem in pems {
        der_bytes.extend_from_slice(&pem.contents);
    }
    Ok(der_bytes)
}

pub fn parse_pem(raw_bytes: &[u8]) -> Result<Vec<Pem>, PEMError> {
    Pem::iter_from_buffer(raw_bytes).collect()
}

pub fn parse_crl_der(raw_bytes: &[u8]) -> crate::Result<CertificateRevocationList> {
    let (_, crl) = CertificateRevocationList::from_der(raw_bytes)?;
    Ok(crl)
}

pub fn parse_x509_der(raw_bytes: &[u8]) -> crate::Result<X509Certificate> {
    let (_, cert) = X509Certificate::from_der(raw_bytes)?;
    Ok(cert)
}

pub fn parse_x509_der_multi(raw_bytes: &[u8]) -> crate::Result<Vec<X509Certificate>> {
    let mut certs = Vec::new();
    let mut i = raw_bytes;
    while !i.is_empty() {
        let (j, cert) = X509Certificate::from_der(i)?;
        certs.push(cert);
        i = j;
    }
    Ok(certs)
}
