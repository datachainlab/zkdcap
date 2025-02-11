use crate::{
    enclave_report::build_qe_auth_data,
    utils::{p256_prvkey_to_pubkey_bytes, sign},
};
use anyhow::Result;
use dcap_types::{
    quotes::{
        body::{EnclaveReport, QuoteBody},
        version_3::{QuoteSignatureDataV3, QuoteV3},
        CertData, QuoteHeader,
    },
    ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID, SGX_TEE_TYPE, TDX_TEE_TYPE,
};
use openssl::{
    pkey::{PKeyRef, Private},
    x509::X509Ref,
};

pub fn gen_quote_v3(
    attestation_key: &PKeyRef<Private>,
    quote_header: &QuoteHeader,
    isv_enclave_report: EnclaveReport,
    qe_cert_data: CertData,
    qe_report: EnclaveReport,
    qe_report_signature: [u8; 64],
) -> Result<QuoteV3> {
    let isv_enclave_report_signature = sign_isv_enclave_report(
        attestation_key,
        quote_header,
        &QuoteBody::SGXQuoteBody(isv_enclave_report),
    )?;
    let sig_data = QuoteSignatureDataV3 {
        isv_enclave_report_signature,
        ecdsa_attestation_key: p256_prvkey_to_pubkey_bytes(attestation_key)?,
        qe_auth_data: build_qe_auth_data(0),
        qe_cert_data,
        qe_report,
        qe_report_signature,
    };
    Ok(QuoteV3 {
        header: quote_header.clone(),
        isv_enclave_report,
        signature_len: sig_data.len(),
        signature: sig_data,
    })
}

pub fn sign_isv_enclave_report(
    attestation_key: &PKeyRef<Private>,
    header: &QuoteHeader,
    body: &QuoteBody,
) -> Result<[u8; 64]> {
    let mut data = Vec::new();
    data.extend_from_slice(&header.to_bytes());
    match body {
        QuoteBody::SGXQuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
        QuoteBody::TD10QuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
    };
    let mut signature = [0u8; 64];
    let sig = sign(attestation_key, &data)?;
    signature.copy_from_slice(&sig);
    Ok(signature)
}

pub fn build_qe_cert_data(
    pck_cert: &X509Ref,
    pck_ca_cert: &X509Ref,
    root_ca_cert: &X509Ref,
) -> CertData {
    let mut data = Vec::new();
    data.extend_from_slice(&pck_cert.to_pem().unwrap());
    data.extend_from_slice(&pck_ca_cert.to_pem().unwrap());
    data.extend_from_slice(&root_ca_cert.to_pem().unwrap());
    CertData {
        cert_data_type: 5,
        cert_data_size: data.len() as u32,
        cert_data: data,
    }
}

pub fn sign_qe_report(pck: &PKeyRef<Private>, qe_report: &EnclaveReport) -> [u8; 64] {
    let mut signature = [0u8; 64];
    let sig = sign(pck, &qe_report.to_bytes()).unwrap();
    signature.copy_from_slice(&sig);
    signature
}

pub struct QuoteHeaderBuilder {
    obj: QuoteHeader,
}

impl QuoteHeaderBuilder {
    pub fn new() -> Self {
        Self {
            obj: Default::default(),
        }
    }

    pub fn new_v3() -> Self {
        Self {
            obj: QuoteHeader {
                version: 3,
                att_key_type: ECDSA_256_WITH_P256_CURVE,
                qe_vendor_id: INTEL_QE_VENDOR_ID,
                ..Default::default()
            },
        }
    }

    pub fn version(self, version: u16) -> Self {
        Self {
            obj: QuoteHeader {
                version,
                ..self.obj
            },
        }
    }

    pub fn att_key_type(self, att_key_type: u16) -> Self {
        Self {
            obj: QuoteHeader {
                att_key_type,
                ..self.obj
            },
        }
    }

    pub fn tee_type(self, tee_type: u32) -> Self {
        Self {
            obj: QuoteHeader {
                tee_type,
                ..self.obj
            },
        }
    }

    pub fn sgx_tee_type(self) -> Self {
        Self {
            obj: QuoteHeader {
                tee_type: SGX_TEE_TYPE,
                ..self.obj
            },
        }
    }

    pub fn tdx_tee_type(self) -> Self {
        Self {
            obj: QuoteHeader {
                tee_type: TDX_TEE_TYPE,
                ..self.obj
            },
        }
    }

    pub fn qe_svn(self, qe_svn: [u8; 2]) -> Self {
        Self {
            obj: QuoteHeader { qe_svn, ..self.obj },
        }
    }

    pub fn pce_svn(self, pce_svn: [u8; 2]) -> Self {
        Self {
            obj: QuoteHeader {
                pce_svn,
                ..self.obj
            },
        }
    }

    pub fn qe_vendor_id(self, qe_vendor_id: [u8; 16]) -> Self {
        Self {
            obj: QuoteHeader {
                qe_vendor_id,
                ..self.obj
            },
        }
    }

    pub fn user_data(self, user_data: [u8; 20]) -> Self {
        Self {
            obj: QuoteHeader {
                user_data,
                ..self.obj
            },
        }
    }

    pub fn build(self) -> QuoteHeader {
        self.obj
    }
}
