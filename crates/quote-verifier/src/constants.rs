// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteConstants.h

pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

pub const ECDSA_256_WITH_P256_CURVE: u16 = 2;

pub const HEADER_LEN: usize = 48;

pub const ENCLAVE_REPORT_LEN: usize = 384;
pub const TD10_REPORT_LEN: usize = 584;
pub const TD15_REPORT_LEN: usize = 684;

pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

pub const VERIFIER_VERSION: u16 = 0;
