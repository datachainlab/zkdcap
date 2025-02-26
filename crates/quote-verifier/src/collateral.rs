use anyhow::bail;
use dcap_types::enclave_identity::EnclaveIdentityV2;
use dcap_types::tcb_info::TcbInfoV3;
use dcap_types::utils::{parse_crl_der, parse_x509_der};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::Result;

/// QvCollateral is a struct that holds the collateral data that is required to verify the
/// authenticity of the quote. This includes the TCBInfo, QEIdentity, certificates and CRLs.
#[derive(Clone, Debug, Default)]
pub struct QvCollateral {
    /// TCBInfo in JSON format
    /// ref. <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-model-v3>
    pub tcb_info_json: String,
    /// QEIdentity in JSON format
    /// ref. <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-enclave-identity-model-v2>
    pub qe_identity_json: String,
    /// SGX Intel Root CA certificate in DER format
    /// ref. <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem>
    pub sgx_intel_root_ca_der: Vec<u8>,
    /// SGX TCB Signing certificate in DER format
    /// You can get this from the response header of the TCBInfo API
    /// ref. <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-v4>
    pub sgx_tcb_signing_der: Vec<u8>,
    /// SGX Intel Root CA CRL in DER format
    /// ref. <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
    pub sgx_intel_root_ca_crl_der: Vec<u8>,
    /// SGX PCK Platform/Processor CA CRL in DER format
    /// NOTE: This CRL issuer must be matched with the quote's PCK cert issuer
    /// ref. <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-revocation-v4>
    pub sgx_pck_crl_der: Vec<u8>,
}

impl QvCollateral {
    /// Serializes the QvCollateral struct into a `Vec<u8>`
    pub fn to_bytes(&self) -> Vec<u8> {
        // serialization scheme is simple: the bytestream is made of 2 parts
        // the first contains a u32 length for each of the members
        // the second contains the actual data
        // [lengths of each of the member][data segment]

        // get the total length
        let total_length = 4 * 6
            + self.tcb_info_json.len()
            + self.qe_identity_json.len()
            + self.sgx_intel_root_ca_der.len()
            + self.sgx_tcb_signing_der.len()
            + self.sgx_intel_root_ca_crl_der.len()
            + self.sgx_pck_crl_der.len();

        // create the vec and copy the data
        let mut data = Vec::with_capacity(total_length);
        data.extend_from_slice(&(self.tcb_info_json.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.qe_identity_json.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_intel_root_ca_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_tcb_signing_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_intel_root_ca_crl_der.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.sgx_pck_crl_der.len() as u32).to_le_bytes());

        data.extend_from_slice(self.tcb_info_json.as_bytes());
        data.extend_from_slice(self.qe_identity_json.as_bytes());
        data.extend_from_slice(&self.sgx_intel_root_ca_der);
        data.extend_from_slice(&self.sgx_tcb_signing_der);
        data.extend_from_slice(&self.sgx_intel_root_ca_crl_der);
        data.extend_from_slice(&self.sgx_pck_crl_der);

        data
    }

    /// Deserializes the QvCollateral struct from a byte slice
    #[allow(unused_assignments)]
    pub fn from_bytes(slice: &[u8]) -> Result<Self> {
        if slice.len() < 4 * 6 {
            bail!("Invalid QvCollateral length");
        }

        // reverse the serialization process
        // each length is 4 bytes long, we have a total of 6 members
        let tcb_info_json_len = u32::from_le_bytes(slice[0..4].try_into()?) as usize;
        let qe_identity_json_len = u32::from_le_bytes(slice[4..8].try_into()?) as usize;
        let sgx_intel_root_ca_der_len = u32::from_le_bytes(slice[8..12].try_into()?) as usize;
        let sgx_tcb_signing_der_len = u32::from_le_bytes(slice[12..16].try_into()?) as usize;
        let sgx_intel_root_ca_crl_der_len = u32::from_le_bytes(slice[16..20].try_into()?) as usize;
        let sgx_pck_crl_der_len = u32::from_le_bytes(slice[20..24].try_into()?) as usize;

        let mut offset = 4 * 6usize;

        if slice.len()
            < offset
                + tcb_info_json_len
                + qe_identity_json_len
                + sgx_intel_root_ca_der_len
                + sgx_tcb_signing_der_len
                + sgx_intel_root_ca_crl_der_len
                + sgx_pck_crl_der_len
        {
            bail!("Invalid QvCollateral length");
        }

        let tcb_info_json = String::from_utf8(slice[offset..offset + tcb_info_json_len].to_vec())?;
        offset += tcb_info_json_len;
        let qe_identity_json =
            String::from_utf8(slice[offset..offset + qe_identity_json_len].to_vec())?;
        offset += qe_identity_json_len;
        let sgx_intel_root_ca_der = slice[offset..offset + sgx_intel_root_ca_der_len].to_vec();
        offset += sgx_intel_root_ca_der_len;
        let sgx_tcb_signing_der = slice[offset..offset + sgx_tcb_signing_der_len].to_vec();
        offset += sgx_tcb_signing_der_len;
        let sgx_intel_root_ca_crl_der =
            slice[offset..offset + sgx_intel_root_ca_crl_der_len].to_vec();
        offset += sgx_intel_root_ca_crl_der_len;
        let sgx_pck_crl_der = slice[offset..offset + sgx_pck_crl_der_len].to_vec();
        offset += sgx_pck_crl_der_len;

        Ok(QvCollateral {
            tcb_info_json,
            qe_identity_json,
            sgx_intel_root_ca_der,
            sgx_tcb_signing_der,
            sgx_intel_root_ca_crl_der,
            sgx_pck_crl_der,
        })
    }

    /// Returns the TCBInfoV3 struct from the TCBInfo JSON bytes
    pub fn get_tcb_info_v3(&self) -> Result<TcbInfoV3> {
        let tcb_info_v3: TcbInfoV3 = serde_json::from_str(&self.tcb_info_json)?;
        if tcb_info_v3.tcb_info.version != 3 {
            bail!("Invalid TCB Info version: {}", tcb_info_v3.tcb_info.version);
        }
        Ok(tcb_info_v3)
    }

    /// Returns the EnclaveIdentityV2 struct from the QEIdentity JSON bytes
    pub fn get_qe_identity_v2(&self) -> Result<EnclaveIdentityV2> {
        let qe: EnclaveIdentityV2 = serde_json::from_str(&self.qe_identity_json)?;
        if qe.enclave_identity.version != 2 {
            bail!(
                "Invalid QE Identity version: {}",
                qe.enclave_identity.version
            );
        }
        Ok(qe)
    }

    /// Returns the SGX Intel Root CA certificate
    pub fn get_sgx_intel_root_ca(&self) -> Result<X509Certificate> {
        parse_x509_der(&self.sgx_intel_root_ca_der)
    }

    /// Returns the SGX TCB Signing certificate
    pub fn get_sgx_tcb_signing(&self) -> Result<X509Certificate> {
        parse_x509_der(&self.sgx_tcb_signing_der)
    }

    /// Returns the SGX Intel Root CA CRL
    pub fn get_sgx_intel_root_ca_crl(&self) -> Result<CertificateRevocationList> {
        parse_crl_der(&self.sgx_intel_root_ca_crl_der)
    }

    /// Returns the SGX PCK Platform/Processor CA CRL
    pub fn get_sgx_pck_crl(&self) -> Result<CertificateRevocationList> {
        parse_crl_der(&self.sgx_pck_crl_der)
    }
}
