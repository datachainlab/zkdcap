use dcap_quote_verifier::{
    collateral::QvCollateral,
    quotes::version_4::verify_quote_v4,
};
use dcap_types::quotes::version_4::QuoteV4;
use serde::Deserialize;
use chrono::Utc;
use dcap_pcs::client::PCSClient;
use anyhow::Context;

#[derive(Deserialize)]
struct LivyAttestation {
    quote: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Livy Quote V4 verification...");
    
    // Load the livy quote from the JSON file
    let attestation: LivyAttestation = serde_json::from_str(
        include_str!("../../crates/quote-verifier/src/quotes/livyquotes/livy.json")
    )?;
    
    // Decode the hex quote
    let hex_quote = hex::decode(&attestation.quote)?;
    let quote = QuoteV4::from_bytes(&hex_quote)?.0;
    
    println!("Quote parsed successfully");
    println!("Quote header version: {}", quote.header.version);
    println!("Quote header TEE type: {}", quote.header.tee_type);
    println!("Quote header att key type: {}", quote.header.att_key_type);
    println!("Quote header QE vendor ID: {:?}", quote.header.qe_vendor_id);
    println!("Quote cert data type: {}", quote.signature.qe_cert_data.cert_data_type);
    
    // Get collateral using PCSClient (same as working test)
    let raw_collateral = PCSClient::default().get_collateral(false, &quote.signature.qe_cert_data)?;

    println!("Quote Collateral tcb info: {:?}", raw_collateral.tcb_info_json);
    println!("QE Identity: {:?}", raw_collateral.qe_identity_json);
    
    // Use the collateral directly (no transformation needed)
    let collateral = QvCollateral {
        tcb_info_json: raw_collateral.tcb_info_json,
        qe_identity_json: raw_collateral.qe_identity_json,
        sgx_intel_root_ca_der: raw_collateral.sgx_intel_root_ca_der,
        sgx_tcb_signing_der: raw_collateral.sgx_tcb_signing_der,
        sgx_intel_root_ca_crl_der: raw_collateral.sgx_intel_root_ca_crl_der,
        sgx_pck_crl_der: raw_collateral.sgx_pck_crl_der,
    };
    
    println!("Collateral created successfully");
    println!("Root CA DER length: {}", collateral.sgx_intel_root_ca_der.len());
    println!("TCB signing cert length: {}", collateral.sgx_tcb_signing_der.len());
    
    // Get current timestamp
    let current_time = Utc::now().timestamp().try_into()?;
    
    // Verify the quote
    let res = verify_quote_v4(&quote, &collateral, current_time);
    
    if res.is_ok() {
        println!("Quote verification successful!");
        let output = res.unwrap();
        println!("Status: {:?}", output.status);
        println!("TEE Type: {:?}", output.tee_type);
    } else {
        println!("Quote verification failed: {:?}", res.err());
    }
    
    Ok(())
}

pub fn extract_raw_certs(cert_chain: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(pem::parse_many(cert_chain)
        .context("Failed to parse certs")?
        .iter()
        .map(|i| i.contents().to_vec())
        .collect())
}

pub fn extract_certs<'a>(cert_chain: &'a [u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    extract_raw_certs(cert_chain)
}
