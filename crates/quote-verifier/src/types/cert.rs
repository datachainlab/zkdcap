use crate::utils::cert::{parse_x509_der_multi, pem_to_der};
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;

type Result<T> = core::result::Result<T, anyhow::Error>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxExtensionTcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
    pub cpusvn: [u8; 16],
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Certificates {
    pub certs_der: Vec<u8>,
}

impl Certificates {
    pub fn from_der(certs_der: &[u8]) -> Self {
        Self {
            certs_der: certs_der.to_vec(),
        }
    }

    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self> {
        let certs_der = pem_to_der(pem_bytes)?;
        Ok(Self::from_der(&certs_der))
    }

    pub fn get_certs(&self) -> Result<Vec<X509Certificate>> {
        parse_x509_der_multi(&self.certs_der)
    }
}
