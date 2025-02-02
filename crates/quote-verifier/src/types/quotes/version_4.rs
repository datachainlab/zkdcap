use anyhow::bail;

use super::{body::*, CertData, QuoteHeader};
use crate::{
    constants::{ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE},
    Result,
};

#[derive(Clone, Debug)]
pub struct QuoteV4 {
    pub header: QuoteHeader, // [48 bytes]
    // Header of Quote data structure.
    // This field is transparent (the user knows its internal structure).
    // Rest of the Quote data structure can be treated as opaque (hidden from the user).
    pub quote_body: QuoteBody, // May either contain a SGX Enclave Report (384 bytes) or TD10 Report (584 bytes)
    pub signature_len: u32,    // [4 bytes]
    // Size of the Quote Signature Data structure in bytes.
    pub signature: QuoteSignatureDataV4, // [variable bytes]
}

impl QuoteV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        let header = QuoteHeader::from_bytes(&raw_bytes[0..48]);
        let quote_body;
        let mut offset: usize = 48;
        match header.tee_type {
            SGX_TEE_TYPE => {
                offset += ENCLAVE_REPORT_LEN;
                quote_body =
                    QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(&raw_bytes[48..offset])?);
            }
            TDX_TEE_TYPE => {
                offset += TD10_REPORT_LEN;
                quote_body =
                    QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(&raw_bytes[48..offset])?);
            }
            _ => {
                bail!("Unknown TEE type")
            }
        }
        let signature_len = u32::from_le_bytes([
            raw_bytes[offset],
            raw_bytes[offset + 1],
            raw_bytes[offset + 2],
            raw_bytes[offset + 3],
        ]);
        offset += 4;
        let signature_slice = &raw_bytes[offset..offset + signature_len as usize];
        let signature = QuoteSignatureDataV4::from_bytes(signature_slice);

        Ok(QuoteV4 {
            header,
            quote_body,
            signature_len,
            signature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct QuoteSignatureDataV4 {
    pub quote_signature: [u8; 64], // [64 bytes]
    // ECDSA signature, the r component followed by the s component, 2 x 32 bytes.
    // Public part of the Attestation Key generated by the Quoting Enclave.
    pub ecdsa_attestation_key: [u8; 64], // [64 bytes]
    // EC KT-I Public Key, the x-coordinate followed by the y-coordinate (on the RFC 6090 P-256 curve), 2 x 32 bytes.
    // Public part of the Attestation Key generated by the Quoting Enclave.
    pub qe_cert_data: CertData, // [variable bytes]
                                // QE Cert Data
}

impl QuoteSignatureDataV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let mut quote_signature = [0; 64];
        quote_signature.copy_from_slice(&raw_bytes[0..64]);
        let mut ecdsa_attestation_key = [0; 64];
        ecdsa_attestation_key.copy_from_slice(&raw_bytes[64..128]);
        let qe_cert_data = CertData::from_bytes(&raw_bytes[128..]);

        QuoteSignatureDataV4 {
            quote_signature,
            ecdsa_attestation_key,
            qe_cert_data,
        }
    }
}
