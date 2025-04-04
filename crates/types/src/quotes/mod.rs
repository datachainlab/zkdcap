use crate::{
    utils::{parse_x509_der_multi, pem_to_der},
    Result, QUOTE_HEADER_LEN,
};

pub mod body;
pub mod version_3;
pub mod version_4;

use anyhow::bail;
use body::EnclaveReport;
use version_3::QuoteV3;
use version_4::QuoteV4;
use x509_parser::prelude::X509Certificate;

/// Quote is a structure that represents a quote from the DCAP library.
/// It can be of version 3 or 4.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quote {
    V3(QuoteV3),
    V4(QuoteV4),
}

impl Quote {
    /// Parse a byte slice into a `Quote` structure.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < QUOTE_HEADER_LEN {
            bail!("Invalid quote length");
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        match version {
            3 => Ok(QuoteV3::from_bytes(bytes).map(|(quote, consumed)| (quote.into(), consumed))?),
            4 => Ok(QuoteV4::from_bytes(bytes).map(|(quote, consumed)| (quote.into(), consumed))?),
            _ => bail!("Unsupported quote version: {}", version),
        }
    }

    /// Convert the `Quote` structure into a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Quote::V3(quote) => quote.to_bytes(),
            Quote::V4(quote) => quote.to_bytes(),
        }
    }
}

impl From<QuoteV3> for Quote {
    fn from(quote: QuoteV3) -> Self {
        Quote::V3(quote)
    }
}

impl From<QuoteV4> for Quote {
    fn from(quote: QuoteV4) -> Self {
        Quote::V4(quote)
    }
}

/// QuoteHeader is the header of the quote data structure.
///
/// This structure is common to all versions of the quote data structure.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct QuoteHeader {
    /// Version of the quote data structure - 3, 4, or 5
    pub version: u16,
    /// Type of the Attestation Key used by the Quoting Enclave - 2 (ECDSA-256-with-P-256 curve)
    pub att_key_type: u16,
    /// TEE for this Attestation - 0x00000000: SGX, 0x00000081: TDX
    pub tee_type: u32,
    /// Security Version of the Quoting Enclave - 1 (only applicable for SGX Quotes)
    pub qe_svn: [u8; 2],
    /// Security Version of the PCE - 0 (only applicable for SGX Quotes)
    pub pce_svn: [u8; 2],
    /// Unique identifier of the QE Vendor.
    pub qe_vendor_id: [u8; 16],
    /// Custom user-defined data.
    pub user_data: [u8; 20],
}

impl QuoteHeader {
    /// Parse a QuoteHeader from a byte slice.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        if raw_bytes.len() != QUOTE_HEADER_LEN {
            return Err(anyhow::anyhow!("Invalid QuoteHeader length"));
        }
        let version = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let att_key_type = u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]);
        let tee_type = u32::from_le_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);
        let mut qe_svn = [0; 2];
        qe_svn.copy_from_slice(&raw_bytes[8..10]);
        let mut pce_svn = [0; 2];
        pce_svn.copy_from_slice(&raw_bytes[10..12]);
        let mut qe_vendor_id = [0; 16];
        qe_vendor_id.copy_from_slice(&raw_bytes[12..28]);
        let mut user_data = [0; 20];
        user_data.copy_from_slice(&raw_bytes[28..48]);

        Ok(QuoteHeader {
            version,
            att_key_type,
            tee_type,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        })
    }

    /// Serialize a QuoteHeader to a byte array.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut raw_bytes = [0; 48];
        raw_bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        raw_bytes[2..4].copy_from_slice(&self.att_key_type.to_le_bytes());
        raw_bytes[4..8].copy_from_slice(&self.tee_type.to_le_bytes());
        raw_bytes[8..10].copy_from_slice(&self.qe_svn);
        raw_bytes[10..12].copy_from_slice(&self.pce_svn);
        raw_bytes[12..28].copy_from_slice(&self.qe_vendor_id);
        raw_bytes[28..48].copy_from_slice(&self.user_data);

        raw_bytes
    }
}

/// QeAuthData is Data that to be additionally 'signed' by the certification key.
///
/// Variable-length data chosen by the Quoting Enclave and signed by the Provisioning Certification Key (as a part of the Report Data in the QE Report).
/// It can be used by the QE to add additional context to the ECDSA Attestation Key utilized by the QE. For example, this may indicate the customer, geography, network, or anything pertinent to the identity of the Quoting Enclave.
/// Size should be set to 0 if there is no additional data.
/// ref. p.71 <https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QeAuthData {
    pub size: u16,
    pub data: Vec<u8>,
}

impl QeAuthData {
    /// Parse a QeAuthData from a byte slice.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<QeAuthData> {
        let len = raw_bytes.len();
        if len < 2 {
            return Err(anyhow::anyhow!("QeAuthData is too short"));
        }
        let size = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        if len < 2 + size as usize {
            return Err(anyhow::anyhow!("QeAuthData is too short"));
        }
        let data = raw_bytes[2..2 + size as usize].to_vec();
        Ok(QeAuthData { size, data })
    }

    /// Serialize a QeAuthData to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.extend_from_slice(&self.size.to_le_bytes());
        raw_bytes.extend_from_slice(&self.data);
        raw_bytes
    }
}

/// CertData is Data required to verify the QE Report Signature depending on the value of the Certification Data Type
///
/// ref. p.72 <https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertData {
    /// Determines type of data required to verify the QE Report Signature in the Quote Signature Data structure.
    /// 1 - (PCK identifier: PPID in plain text, CPUSVN, and PCESVN)
    /// 2 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, and PCESVN)
    /// 3 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN, and QEID)
    /// 4 - (PCK Leaf Certificate in plain text; currently not supported)
    /// 5 - (Concatenated PCK Cert Chain)
    /// 6 - (QE Report Certification Data)
    /// 7 - (PLATFORM_MANIFEST; currently not supported)
    pub cert_data_type: u16,
    /// Size of Certification Data field.
    pub cert_data_size: u32,
    /// Data required to verify the QE Report Signature depending on the value of the Certification Data Type.
    /// 1: Byte array that contains concatenation of PPID, CPUSVN, PCESVN (LE), PCEID (LE).
    /// 2: Byte array that contains concatenation of PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
    /// 3: Byte array that contains concatenation of PPID encrypted using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
    /// 4: PCK Leaf Certificate
    /// 5: Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert
    /// 6: QE Report Certification Data
    /// 7: PLATFORM_MANIFEST
    pub cert_data: Vec<u8>,
}

impl CertData {
    /// Create a new CertData instance.
    pub fn new(cert_data_type: u16, cert_data: Vec<u8>) -> Result<Self> {
        let cert_data_size = cert_data
            .len()
            .try_into()
            .map_err(|_| anyhow::anyhow!("CertData size is too large"))?;
        Ok(CertData {
            cert_data_type,
            cert_data_size,
            cert_data,
        })
    }

    /// Parse a CertData from a byte slice.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        let len = raw_bytes.len();
        if len < 6 {
            return Err(anyhow::anyhow!("CertData is too short"));
        }
        let cert_data_type = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let cert_data_size =
            u32::from_le_bytes([raw_bytes[2], raw_bytes[3], raw_bytes[4], raw_bytes[5]]);
        if len < 6 + cert_data_size as usize {
            return Err(anyhow::anyhow!("CertData is too short"));
        }
        let cert_data = raw_bytes[6..6 + cert_data_size as usize].to_vec();
        Ok(CertData {
            cert_data_type,
            cert_data_size,
            cert_data,
        })
    }

    /// Serialize a CertData to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.extend_from_slice(&self.cert_data_type.to_le_bytes());
        raw_bytes.extend_from_slice(&self.cert_data_size.to_le_bytes());
        raw_bytes.extend_from_slice(&self.cert_data);

        raw_bytes
    }

    /// Get the CertDataType from the CertData.
    pub fn get_cert_data(&self) -> Result<CertDataType> {
        let t = match self.cert_data_type {
            1 => CertDataType::Type1(self.cert_data.clone()),
            2 => CertDataType::Type2(self.cert_data.clone()),
            3 => CertDataType::Type3(self.cert_data.clone()),
            4 => CertDataType::Type4(self.cert_data.clone()),
            5 => CertDataType::CertChain(Certificates::from_pem(&self.cert_data)?),
            6 => CertDataType::QeReportCertData(QeReportCertData::from_bytes(&self.cert_data)?),
            7 => CertDataType::Type7(self.cert_data.clone()),
            _ => CertDataType::Unused,
        };
        Ok(t)
    }
}

/// CertDataType is a type that represents the different types of certification data.
/// Please refer to the doc of `CertData.cert_data_type` field for more information.
#[allow(clippy::large_enum_variant)]
pub enum CertDataType {
    Unused,
    Type1(Vec<u8>),
    Type2(Vec<u8>),
    Type3(Vec<u8>),
    Type4(Vec<u8>),
    CertChain(Certificates),
    QeReportCertData(QeReportCertData),
    Type7(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QeReportCertData {
    pub qe_report: EnclaveReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

impl QeReportCertData {
    /// Parse a QeReportCertData from a byte slice.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        if raw_bytes.len() < 448 {
            bail!("QeReportCertData input too short");
        }
        // 384 bytes for qe_report
        let qe_report = EnclaveReport::from_bytes(&raw_bytes[0..384])?;
        // 64 bytes for qe_report_signature
        let mut qe_report_signature = [0; 64];
        qe_report_signature.copy_from_slice(&raw_bytes[384..448]);
        // qe auth data is variable length, we'll pass remaining bytes to the from_bytes method
        let qe_auth_data = QeAuthData::from_bytes(&raw_bytes[448..])?;
        // get the length of qe_auth_data
        let qe_auth_data_size = 2 + qe_auth_data.size as usize;
        // finish off with the parsing of qe_cert_data
        let qe_cert_data_start = 448 + qe_auth_data_size;
        let qe_cert_data = CertData::from_bytes(&raw_bytes[qe_cert_data_start..])?;

        Ok(QeReportCertData {
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        })
    }

    /// Serialize a QeReportCertData to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.extend_from_slice(&self.qe_report.to_bytes());
        raw_bytes.extend_from_slice(&self.qe_report_signature);
        raw_bytes.extend_from_slice(&self.qe_auth_data.to_bytes());
        raw_bytes.extend_from_slice(&self.qe_cert_data.to_bytes());

        raw_bytes
    }
}

#[derive(Debug, Clone)]
pub struct Certificates {
    certs_der: Vec<u8>,
}

impl Certificates {
    /// Create a new Certificates instance from a DER encoded byte slice.
    pub fn from_der(certs_der: &[u8]) -> Self {
        Self {
            certs_der: certs_der.to_vec(),
        }
    }

    /// Create a new Certificates instance from a PEM encoded byte slice.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self> {
        let certs_der = pem_to_der(pem_bytes)?;
        Ok(Self::from_der(&certs_der))
    }

    /// Get the certificates as a vector of X509Certificate.
    pub fn get_certs(&self) -> Result<Vec<X509Certificate>> {
        parse_x509_der_multi(&self.certs_der)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{body::tests::enclave_report_strategy, *};
    use proptest::{collection::vec, prelude::*};

    proptest! {
        #[test]
        fn test_quote_header_roundtrip(quote_header in quote_header_strategy(None, None)) {
            let raw_bytes = quote_header.to_bytes();
            let parsed_quote_header = QuoteHeader::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(quote_header, parsed_quote_header, "raw_bytes: {:?}", raw_bytes);
        }

        #[test]
        fn test_qe_report_cert_data_roundtrip(qe_report_cert_data in qe_report_cert_data_strategy()) {
            let raw_bytes = qe_report_cert_data.to_bytes();
            let parsed_qe_report_cert_data = QeReportCertData::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(qe_report_cert_data, parsed_qe_report_cert_data, "raw_bytes: {:?}", raw_bytes);
        }

        #[test]
        fn test_qe_auth_data_roundtrip(qe_auth_data in qe_auth_data_strategy(65535)) {
            let raw_bytes = qe_auth_data.to_bytes();
            let parsed_qe_auth_data = QeAuthData::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(qe_auth_data, parsed_qe_auth_data, "raw_bytes: {:?}", raw_bytes);
        }

        #[test]
        fn test_cert_data_roundtrip(cert_data in cert_data_strategy(65535)) {
            let raw_bytes = cert_data.to_bytes();
            let parsed_cert_data = CertData::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(cert_data, parsed_cert_data);
        }
    }

    pub(crate) fn quote_header_strategy(
        version: Option<u16>,
        tee_type: Option<u32>,
    ) -> impl Strategy<Value = QuoteHeader> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u32>(),
            any::<[u8; 2]>(),
            any::<[u8; 2]>(),
            any::<[u8; 16]>(),
            any::<[u8; 20]>(),
        )
            .prop_map(
                move |(
                    version_,
                    att_key_type,
                    tee_type_,
                    qe_svn,
                    pce_svn,
                    qe_vendor_id,
                    user_data,
                )| {
                    QuoteHeader {
                        version: version.unwrap_or(version_),
                        att_key_type,
                        tee_type: tee_type.unwrap_or(tee_type_),
                        qe_svn,
                        pce_svn,
                        qe_vendor_id,
                        user_data,
                    }
                },
            )
    }

    pub(crate) fn qe_auth_data_strategy(limit_size: u16) -> impl Strategy<Value = QeAuthData> {
        vec(any::<u8>(), 0..=limit_size as usize).prop_map(|data| {
            let size = data.len() as u16;
            QeAuthData { size, data }
        })
    }

    pub(crate) fn cert_data_strategy(limit_size: u32) -> impl Strategy<Value = CertData> {
        (0..=u16::MAX, vec(any::<u8>(), 0..=limit_size as usize)).prop_map(
            |(cert_data_type, cert_data)| {
                let cert_data_size = cert_data.len() as u32;
                CertData {
                    cert_data_type,
                    cert_data_size,
                    cert_data,
                }
            },
        )
    }

    pub(crate) fn qe_report_cert_data_strategy() -> impl Strategy<Value = QeReportCertData> {
        (
            enclave_report_strategy(),
            any::<[u8; 64]>(),
            qe_auth_data_strategy(65535),
            cert_data_strategy(65535),
        )
            .prop_map(
                |(qe_report, qe_report_signature, qe_auth_data, qe_cert_data)| QeReportCertData {
                    qe_report,
                    qe_report_signature,
                    qe_auth_data,
                    qe_cert_data,
                },
            )
    }
}
