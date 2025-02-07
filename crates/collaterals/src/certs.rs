use anyhow::bail;
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

pub fn gen_sgx_intel_root_ca(
    root_pkey: &PKey<Private>,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let name = build_x509_name("Intel SGX Root CA")?;
    let mut builder = X509Builder::new()?;
    builder.set_version(0x2)?;
    builder.set_issuer_name(&name)?;
    builder.set_serial_number(
        Asn1Integer::from_bn(BigNum::from_slice(&calc_skid(root_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(&name)?;
    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.set_pubkey(root_pkey)?;

    builder.append_extension(gen_skid(&root_pkey))?;

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

pub fn gen_crl(
    issuer_cert: &X509Ref,
    issuer_pkey: &PKeyRef<Private>,
    revoked_certs: &[X509],
) -> Result<X509Crl, anyhow::Error> {
    let mut crl = X509Crl::new(issuer_cert, None)?;
    crl.set_next_update_from_now(60 * 60 * 24 * 30)?;
    crl.increment_crl_number()?;
    for cert in revoked_certs {
        crl.revoke(cert)?;
    }
    crl.sign(issuer_pkey, MessageDigest::sha256())?;
    Ok(crl)
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
        Asn1Integer::from_bn(
            BigNum::from_slice(&calc_skid(tcb_signing_pkey).as_slice())?.as_ref(),
        )?
        .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name("Intel SGX TCB Signing")?.as_ref())?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.set_pubkey(tcb_signing_pkey)?;

    builder.append_extension(gen_skid(&tcb_signing_pkey))?;
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

#[derive(Debug, Clone, Copy)]
pub enum PckCa {
    Processor,
    Platform,
}

impl PckCa {
    pub fn from_cn(cn: &str) -> Result<Self, anyhow::Error> {
        match cn {
            "Intel SGX PCK Processor CA" => Ok(PckCa::Processor),
            "Intel SGX PCK Platform CA" => Ok(PckCa::Platform),
            _ => bail!("Invalid PCK CA CN: {}", cn),
        }
    }

    pub fn cn(&self) -> &'static str {
        match self {
            PckCa::Processor => "Intel SGX PCK Processor CA",
            PckCa::Platform => "Intel SGX PCK Platform CA",
        }
    }

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
        Asn1Integer::from_bn(
            BigNum::from_slice(&calc_skid(pck_cert_ca_pkey).as_slice())?.as_ref(),
        )?
        .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name(pck_ca.cn())?.as_ref())?;
    builder.set_pubkey(pck_cert_ca_pkey)?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.append_extension(gen_skid(&pck_cert_ca_pkey))?;
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

pub fn gen_pck_cert(
    pck_ca_cert: &X509Ref,
    pck_ca_key: &PKeyRef<Private>,
    pck_cert_pkey: &PKeyRef<Private>,
    validity: Validity,
) -> Result<X509, anyhow::Error> {
    let pck_ca = PckCa::from_cn(
        pck_ca_cert
            .subject_name()
            .entries()
            .into_iter()
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
        Asn1Integer::from_bn(BigNum::from_slice(&calc_skid(pck_cert_pkey).as_slice())?.as_ref())?
            .as_ref(),
    )?;
    builder.set_subject_name(build_x509_name("Intel SGX PCK Certificate")?.as_ref())?;
    builder.set_pubkey(pck_cert_pkey)?;

    builder.set_not_before(&validity.not_before())?;
    builder.set_not_after(&validity.not_after())?;

    builder.append_extension(gen_skid(&pck_cert_pkey))?;
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
    set_sgx_extension(&mut builder)?;

    builder.sign(pck_ca_key, MessageDigest::sha256())?;

    Ok(builder.build())
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
        Self {
            not_before,
            not_after,
        }
    }

    pub fn new_with_duration(not_before: i64, duration: i64) -> Self {
        Self {
            not_before,
            not_after: not_before + duration,
        }
    }

    pub fn not_before(&self) -> Asn1Time {
        Asn1Time::from_unix(self.not_before).unwrap()
    }

    pub fn not_after(&self) -> Asn1Time {
        Asn1Time::from_unix(self.not_after).unwrap()
    }
}

fn build_x509_name(cn: &str) -> Result<X509Name, ErrorStack> {
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
fn gen_skid(pubkey: &PKeyRef<Private>) -> X509Extension {
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

fn set_sgx_extension(builder: &mut X509Builder) -> Result<(), ErrorStack> {
    let oid = Asn1Object::from_str("1.2.840.113741.1.13.1")?;
    let der_contents = Asn1OctetString::new_from_bytes(&get_sgx_extension_data())?;
    builder.append_extension(X509Extension::new_from_der(&oid, false, &der_contents)?)
}

fn get_sgx_extension_data() -> Vec<u8> {
    let bz = hex::decode("30820228301E060A2A864886F84D010D0101041025F8E1DA4FE822D04F0FF15025931F4930820165060A2A864886F84D010D0102308201553010060B2A864886F84D010D01020102010C3010060B2A864886F84D010D01020202010C3010060B2A864886F84D010D0102030201033010060B2A864886F84D010D0102040201033011060B2A864886F84D010D010205020200FF3011060B2A864886F84D010D010206020200FF3010060B2A864886F84D010D0102070201013010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D01021102010D301F060B2A864886F84D010D01021204100C0C0303FFFF010000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600606A000000300F060A2A864886F84D010D01050A0101301E060A2A864886F84D010D010604101135C40890AEDF44EB6E02D58424229E3044060A2A864886F84D010D010730363010060B2A864886F84D010D0107010101FF3010060B2A864886F84D010D0107020101003010060B2A864886F84D010D010703010100").unwrap();
    bz
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::gen_key;
    use openssl::sha::sha1;

    #[test]
    fn test_gen_sgx_intel_root_ca() {
        {
            let x509 = parse_x509(include_str!(
                "../../../data/Intel_SGX_Provisioning_Certification_RootCA.pem"
            ));
            println!("x509: {:?}", x509);
            let pubkey = x509.public_key().unwrap();
            let h = sha1(pubkey.public_key_to_der().unwrap().as_slice());
            println!("sha1: {}", hex::encode(h));
        }

        let root_key = gen_key();
        let tcb_signing_key = gen_key();

        let root_cert =
            gen_sgx_intel_root_ca(&root_key, Validity::new(1524607999, 2524607999)).unwrap();
        let s = String::from_utf8(root_cert.to_pem().unwrap()).unwrap();
        println!("x509: {}", s);

        let crl = gen_crl(&root_cert, &root_key, &[root_cert.clone()]).unwrap();
        // let crl = gen_crl(&x509, &pkey, &[]);
        let s = String::from_utf8(crl.to_pem().unwrap()).unwrap();
        println!("crl: {}", s);

        let tcb_signing_cert = gen_tcb_signing_ca(
            &root_cert,
            &root_key,
            &tcb_signing_key,
            Validity::new(1524607999, 2524607999),
        )
        .unwrap();
        let s = String::from_utf8(tcb_signing_cert.to_pem().unwrap()).unwrap();
        println!("tcb_signing_cert: {}", s);

        let pck_cert_processor_key = gen_key();
        let pck_cert_processor_cert = gen_pck_cert_ca(
            PckCa::Platform,
            &root_cert,
            &root_key,
            &pck_cert_processor_key,
            Validity::new(1524607999, 2524607999),
        )
        .unwrap();

        let s = String::from_utf8(pck_cert_processor_cert.to_pem().unwrap()).unwrap();
        println!("pck_cert_processor_cert: {}", s);

        let pck_cert_key = gen_key();
        let pck_cert = gen_pck_cert(
            &pck_cert_processor_cert,
            &pck_cert_processor_key,
            &pck_cert_key,
            Validity::new(1524607999, 2524607999),
        )
        .unwrap();

        let s = String::from_utf8(pck_cert.to_pem().unwrap()).unwrap();
        println!("pck_cert: {}", s);

        assert!(
            tcb_signing_cert.verify(&root_key).unwrap(),
            "verify tcb_signing_cert"
        );
    }

    fn parse_x509(cer: &str) -> X509 {
        X509::from_pem(cer.as_bytes()).unwrap()
    }
}
