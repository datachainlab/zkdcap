use crate::{
    sgx_extensions::{sgx_extensions_to_bytes, SgxExtensionsBuilder},
    utils::gen_key,
};
use anyhow::bail;
use dcap_types::cert::{
    SgxExtensions, SGX_PCK_CERT_CN, SGX_PCK_PLATFORM_CA_CN, SGX_PCK_PROCESSOR_CA_CN,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time},
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage},
        X509Builder, X509Crl, X509Extension, X509Name, X509Ref, X509,
    },
};

pub struct RootCa {
    pub cert: X509,
    pub key: PKey<Private>,
    pub crl: X509Crl,
}

impl RootCa {
    pub fn with_new_crl(&self, revoked_certs: Vec<X509>) -> Result<RootCa, anyhow::Error> {
        let crl = gen_crl(&self.cert, &self.key, revoked_certs, None)?;
        Ok(RootCa {
            cert: self.cert.clone(),
            key: self.key.clone(),
            crl,
        })
    }
}

pub fn gen_sgx_intel_root_ca(
    root_pkey: &PKey<Private>,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let name = build_x509_name("Intel SGX Root CA")?;
    let mut builder = X509Builder::new()?;
    builder.set_version(0x2)?;
    builder.set_issuer_name(&name)?;
    builder.set_serial_number(
        Asn1Integer::from_bn(BigNum::from_slice(calc_skid(root_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(&name)?;
    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.set_pubkey(root_pkey)?;

    builder.append_extension(gen_skid(root_pkey))?;

    builder.append_extension(gen_crl_distribution_points(
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
    ))?;

    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(1).build()?)?;

    let ctx = builder.x509v3_context(None, None);
    builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(false)
            .build(&ctx)
            .unwrap(),
    )?;

    builder.sign(root_pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

pub fn gen_root_ca(
    root_cert_validity: Option<Validity>,
    crl_validity: Option<Validity>,
) -> Result<RootCa, anyhow::Error> {
    let root_key = gen_key();
    let root_cert = gen_sgx_intel_root_ca(
        &root_key,
        root_cert_validity.unwrap_or_else(Validity::long_duration),
    )?;
    let crl = gen_crl(&root_cert, &root_key, vec![], crl_validity)?;
    Ok(RootCa {
        cert: root_cert,
        key: root_key,
        crl,
    })
}

pub fn gen_crl(
    issuer_cert: &X509Ref,
    issuer_pkey: &PKeyRef<Private>,
    revoked_certs: Vec<X509>,
    crl_validity: Option<Validity>,
) -> Result<X509Crl, anyhow::Error> {
    let mut crl = X509Crl::new(issuer_cert, None)?;
    let validity = crl_validity.unwrap_or_else(Validity::long_duration);
    crl.set_last_update(&validity.not_before())?;
    crl.set_next_update(&validity.not_after())?;
    crl.increment_crl_number()?;
    for cert in revoked_certs {
        crl.revoke(&cert)?;
    }
    crl.sign(issuer_pkey, MessageDigest::sha256())?;
    Ok(crl)
}

pub fn gen_crl_der(
    issuer_cert: &X509Ref,
    issuer_pkey: &PKeyRef<Private>,
    revoked_certs: Vec<X509>,
    crl_validity: Option<Validity>,
) -> Result<Vec<u8>, anyhow::Error> {
    Ok(gen_crl(issuer_cert, issuer_pkey, revoked_certs, crl_validity)?.to_der()?)
}

pub fn gen_tcb_signing_ca(
    root_cert: &X509Ref,
    root_pkey: &PKeyRef<Private>,
    tcb_signing_pkey: &PKeyRef<Private>,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let mut builder = X509Builder::new()?;
    builder.set_version(0x2)?;
    builder.set_issuer_name(root_cert.subject_name())?;
    builder.set_serial_number(
        Asn1Integer::from_bn(BigNum::from_slice(calc_skid(tcb_signing_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name("Intel SGX TCB Signing")?.as_ref())?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.set_pubkey(tcb_signing_pkey)?;

    builder.append_extension(gen_skid(tcb_signing_pkey))?;
    builder.append_extension(gen_crl_distribution_points(
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
    ))?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .build()?,
    )?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    let ctx = builder.x509v3_context(Some(root_cert), None);
    builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(false)
            .build(&ctx)?,
    )?;

    builder.sign(root_pkey, MessageDigest::sha256())?;

    Ok(builder.build())
}

pub struct TcbCertchain {
    pub cert: X509,
    pub key: PKey<Private>,
}

pub fn gen_tcb_certchain(
    root_ca: &RootCa,
    tcb_signing_ca_cert_validity: Option<Validity>,
) -> Result<TcbCertchain, anyhow::Error> {
    let tcb_signing_key = gen_key();
    let tcb_signing_cert = gen_tcb_signing_ca(
        &root_ca.cert,
        &root_ca.key,
        &tcb_signing_key,
        tcb_signing_ca_cert_validity.unwrap_or_else(Validity::long_duration),
    )?;
    Ok(TcbCertchain {
        cert: tcb_signing_cert,
        key: tcb_signing_key,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PckCa {
    Processor,
    Platform,
}

impl PckCa {
    /// Create a PckCa from the CN of the certificate
    pub fn from_cn(cn: &str) -> Result<Self, anyhow::Error> {
        if cn == SGX_PCK_PROCESSOR_CA_CN {
            Ok(PckCa::Processor)
        } else if cn == SGX_PCK_PLATFORM_CA_CN {
            Ok(PckCa::Platform)
        } else {
            bail!("Invalid PCK CA CN: {}", cn)
        }
    }

    /// Get the CN of the PckCa
    pub fn cn(&self) -> &'static str {
        match self {
            PckCa::Processor => SGX_PCK_PROCESSOR_CA_CN,
            PckCa::Platform => SGX_PCK_PLATFORM_CA_CN,
        }
    }

    /// Get the type of the PckCa
    pub fn ca_type(&self) -> &'static str {
        match self {
            PckCa::Processor => "processor",
            PckCa::Platform => "platform",
        }
    }
}

pub fn gen_pck_cert_ca(
    pck_ca: PckCa,
    root_cert: &X509Ref,
    root_pkey: &PKeyRef<Private>,
    pck_cert_ca_pkey: &PKeyRef<Private>,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let mut builder = X509Builder::new()?;
    builder.set_version(0x2)?;
    builder.set_issuer_name(root_cert.subject_name())?;
    builder.set_serial_number(
        Asn1Integer::from_bn(BigNum::from_slice(calc_skid(pck_cert_ca_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name(pck_ca.cn())?.as_ref())?;
    builder.set_pubkey(pck_cert_ca_pkey)?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.append_extension(gen_skid(pck_cert_ca_pkey))?;
    builder.append_extension(gen_crl_distribution_points(
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
    ))?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;

    let ctx = builder.x509v3_context(Some(root_cert), None);
    builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(false)
            .build(&ctx)?,
    )?;

    builder.sign(root_pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

pub fn gen_pck_cert(
    pck_ca_cert: &X509Ref,
    pck_ca_key: &PKeyRef<Private>,
    pck_cert_pkey: &PKeyRef<Private>,
    sgx_extensions: &SgxExtensions,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let pck_ca = PckCa::from_cn(
        pck_ca_cert
            .subject_name()
            .entries()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No subject name"))?
            .data()
            .as_utf8()?
            .as_ref(),
    )?;

    let mut builder = X509Builder::new()?;
    builder.set_version(0x2)?;
    builder.set_issuer_name(pck_ca_cert.subject_name())?;
    builder.set_serial_number(
        Asn1Integer::from_bn(BigNum::from_slice(calc_skid(pck_cert_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name(SGX_PCK_CERT_CN)?.as_ref())?;
    builder.set_pubkey(pck_cert_pkey)?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.append_extension(gen_skid(pck_cert_pkey))?;
    builder.append_extension(gen_crl_distribution_points(
        format!(
            "https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca={}&encoding=der",
            pck_ca.ca_type()
        )
        .as_str(),
    ))?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .build()?,
    )?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;

    let ctx = builder.x509v3_context(Some(pck_ca_cert), None);
    builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(false)
            .build(&ctx)?,
    )?;

    set_sgx_extension(
        &mut builder,
        sgx_extensions_to_bytes(sgx_extensions)?.as_ref(),
    )?;

    builder.sign(pck_ca_key, MessageDigest::sha256())?;

    Ok(builder.build())
}

pub struct PckCertchain {
    pub pck_cert_ca: X509,
    pub pck_cert_ca_key: PKey<Private>,
    pub pck_cert: X509,
    pub pck_cert_key: PKey<Private>,
    pub pck_cert_crl: X509Crl,
}

impl PckCertchain {
    /// Generate a new PCK certificate and CRL
    /// If `revoked` is true, the `self.pck_cert`` will be revoked in the CRL
    pub fn gen_new_pck_cert(&self, revoked: bool) -> PckCertchain {
        let pck_cert_key = gen_key();
        let pck_cert = gen_pck_cert(
            &self.pck_cert_ca,
            &self.pck_cert_ca_key,
            &pck_cert_key,
            &SgxExtensionsBuilder::new().build(),
            Validity::new_with_duration(1, 60 * 60 * 24 * 365),
        )
        .unwrap();
        let pck_cert_crl = gen_crl(
            &self.pck_cert_ca,
            &self.pck_cert_ca_key,
            if revoked {
                vec![self.pck_cert.clone()]
            } else {
                vec![]
            },
            None,
        )
        .unwrap();
        PckCertchain {
            pck_cert_ca: self.pck_cert_ca.clone(),
            pck_cert_ca_key: self.pck_cert_ca_key.clone(),
            pck_cert,
            pck_cert_key,
            pck_cert_crl,
        }
    }
}

/// Generate Intel SGX Root CA and PCK Processor/Platform CA and PCK certificates and private keys and CRLs for testing
pub fn gen_pck_certchain(
    root_ca: &RootCa,
    ca_type: PckCa,
    sgx_extensions: &SgxExtensions,
    pck_cert_ca_validity: Option<Validity>,
    pck_cert_validity: Option<Validity>,
    pck_cert_ca_crl_validity: Option<Validity>,
) -> Result<PckCertchain, anyhow::Error> {
    let pck_cert_ca_key = gen_key();
    let pck_cert_ca = gen_pck_cert_ca(
        ca_type,
        &root_ca.cert,
        &root_ca.key,
        &pck_cert_ca_key,
        pck_cert_ca_validity.unwrap_or_else(Validity::long_duration),
    )?;
    let pck_cert_key = gen_key();
    let pck_cert = gen_pck_cert(
        &pck_cert_ca,
        &pck_cert_ca_key,
        &pck_cert_key,
        sgx_extensions,
        pck_cert_validity.unwrap_or_else(Validity::long_duration),
    )?;
    let pck_cert_crl = gen_crl(
        &pck_cert_ca,
        &pck_cert_ca_key,
        vec![],
        pck_cert_ca_crl_validity,
    )?;
    Ok(PckCertchain {
        pck_cert_ca,
        pck_cert_ca_key,
        pck_cert,
        pck_cert_key,
        pck_cert_crl,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Validity {
    /// not_before in unix timestamp (seconds)
    pub not_before: i64,
    /// not_after in unix timestamp (seconds)
    pub not_after: i64,
}

impl Validity {
    pub fn new(not_before: i64, not_after: i64) -> Self {
        assert!(
            not_before < not_after,
            "not_before must be less than not_after"
        );
        Self {
            not_before,
            not_after,
        }
    }

    pub fn new_with_duration(not_before: i64, duration: i64) -> Self {
        Self::new(not_before, not_before + duration)
    }

    pub fn long_duration() -> Self {
        Self::new(1, u32::MAX as i64)
    }

    pub fn not_before(&self) -> Asn1Time {
        let t = chrono::DateTime::from_timestamp(self.not_before, 0).unwrap();
        Asn1Time::from_str_x509(t.format("%Y%m%d%H%M%SZ").to_string().as_str()).unwrap()
    }

    pub fn not_after(&self) -> Asn1Time {
        let t = chrono::DateTime::from_timestamp(self.not_after, 0).unwrap();
        Asn1Time::from_str_x509(t.format("%Y%m%d%H%M%SZ").to_string().as_str()).unwrap()
    }
}

pub fn build_x509_name(cn: &str) -> Result<X509Name, ErrorStack> {
    let mut builder = X509Name::builder()?;
    builder.append_entry_by_text("CN", cn)?;
    builder.append_entry_by_text("O", "Intel Corporation")?;
    builder.append_entry_by_text("L", "Santa Clara")?;
    builder.append_entry_by_text("ST", "CA")?;
    builder.append_entry_by_text("C", "US")?;
    Ok(builder.build())
}

fn calc_skid(pubkey: &PKeyRef<Private>) -> Vec<u8> {
    let der = pubkey.public_key_to_der().unwrap();
    let digest = openssl::sha::sha1(&der);
    digest.to_vec()
}

#[allow(deprecated)]
pub fn gen_skid(pubkey: &PKeyRef<Private>) -> X509Extension {
    let skid = calc_skid(pubkey);
    X509Extension::new(
        None,
        None,
        "subjectKeyIdentifier",
        // hex string to "AA:BB:CC:DD:EE:FF..."
        &hex::encode(skid)
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<&str>>()
            .join(":"),
    )
    .unwrap()
}

#[allow(deprecated)]
fn gen_crl_distribution_points(uri: &str) -> X509Extension {
    X509Extension::new(
        None,
        None,
        "crlDistributionPoints",
        format!("URI:{}", uri).as_str(),
    )
    .unwrap()
}

fn set_sgx_extension(builder: &mut X509Builder, extension_bytes: &[u8]) -> Result<(), ErrorStack> {
    let oid = Asn1Object::from_str("1.2.840.113741.1.13.1")?;
    let der_contents = Asn1OctetString::new_from_bytes(extension_bytes)?;
    builder.append_extension(X509Extension::new_from_der(&oid, false, &der_contents)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sgx_extensions::SgxExtensionsBuilder;

    #[test]
    fn test_gen_sgx_intel_root_ca() {
        let root_ca = gen_root_ca(None, None).unwrap();
        let tcb_certchain = gen_tcb_certchain(&root_ca, None).unwrap();
        let pck_certchain = gen_pck_certchain(
            &root_ca,
            PckCa::Processor,
            &SgxExtensionsBuilder::new().build(),
            None,
            None,
            None,
        )
        .unwrap();

        assert!(
            tcb_certchain.cert.verify(&root_ca.key).unwrap(),
            "verify tcb_signing_cert"
        );
        assert!(
            pck_certchain.pck_cert_ca.verify(&root_ca.key).unwrap(),
            "verify pck_cert_ca"
        );
        assert!(
            pck_certchain
                .pck_cert
                .verify(&pck_certchain.pck_cert_ca_key)
                .unwrap(),
            "verify pck_cert"
        );
    }
}
