pub mod cert;
pub mod collateral;
pub mod crl;
pub mod crypto;
pub mod enclave_identity;
pub mod pck;
pub mod quotes;
pub mod sgx_extensions;
pub mod tcb_info;
pub mod tdx_module;
#[cfg(test)]
pub mod tests;
pub mod verifier;

pub use anyhow::Error;
pub use dcap_types as types;

type Result<T> = core::result::Result<T, anyhow::Error>;
