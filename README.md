# zkDCAP

[![test](https://github.com/datachainlab/zkdcap/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/datachainlab/zkdcap/actions/workflows/test.yml)

## Overview

zkDCAP is a guest program that runs inside the [RISC Zero zkVM](https://github.com/risc0/risc0), designed to verify Intel SGX/TDX DCAP quotes and generate a zero-knowledge proof (ZKP) of the result.

Since verifying a quote directly on-chain (e.g., on Ethereum or other EVM-compatible blockchains) is extremely gas-intensive, zkDCAP significantly reduces gas costs by offloading the verification process to the zkVM and proving its validity through ZKP.

The verification logic is based on Intel's reference implementation: [SGX-TDX-DCAP-QuoteVerificationLibrary](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/).

zkDCAP is designed to minimize trust assumptions, requiring trust only in Intel's Root CA certificate. However, performing quote verification inside a zkVM and validating the result via ZKP introduces several challenges. This README outlines these challenges and our design solutions.

## Design Considerations

### Validity Period

#### Background

DCAP quote verification requires multiple components of collateral—including certificates, CRLs, and TCB info—to determine the platform's TCB status.

Each collateral component comes with its own validity period. Verifiers must ensure that the **current time falls within all of these periods**.

If expired collateral (e.g., an outdated TCB info) is used, quotes from already compromised SGX environments may be mistakenly accepted.

#### Our Approach

In a typical quote verification process, the verifier checks whether the current time is within the validity range of the collateral.  

However, it is not practical to securely obtain a trusted current timestamp within the zkVM, as the timestamp provided by the prover may have been tampered with.

To solve this, zkDCAP adopts the following two-step approach:

1. Inside the zkVM, it computes the **intersection of the validity periods** across all collateral components and includes this range in the output.
2. The on-chain verifier (e.g., a smart contract) verifies that the **current block timestamp** falls within this range when verifying the ZKP.

This ensures that the validity check can be enforced **without requiring the verifier to trust any timestamp provided by the prover**.

**Note:** Regarding collateral availability, [Intel documentation](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/#collateral-caching-service) and our observation of PCS API behavior show that each collateral component typically has a validity period of ~30 days after download, which provides sufficient availability for verification.

### TCB Evaluation Data Number (TCB-R Counter)

#### Background

Intel periodically updates TCB info for SGX/TDX platforms through **TCB Recovery** events.

Each update is assigned a unique **TCB Evaluation Data Number**, also known as the **TCB-R Counter**.

Intel's Provisioning Certification Service (PCS) API allows clients to retrieve TCB information corresponding to different TCB-R Counters using the `update` query parameter.  
For example, the `?update=standard` parameter may return an older TCB info version (commonly up to 12 months prior to the latest). This mechanism is intended to support transitional compatibility, but it introduces a potential security risk.

Because the TCB status of a platform is evaluated based on the TCB info version used during verification, using an outdated TCB-R Counter may lead to a false "UpToDate" result for platforms that have been deprecated or have since become vulnerable.

Therefore, to ensure the correctness and freshness of the attestation, verifiers **must validate quotes against the latest available TCB-R Counter**.

#### Our Approach

zkDCAP includes in its output the **minimum TCB Evaluation Data Number (TCB-R Counter)** among those found in the collateral used during verification. This allows the on-chain verifier to determine which version of TCB info the TCB status is based on.

By comparing this value with the latest TCB-R Counter tracked on-chain, the verifier can ensure that the verification result reflects a sufficiently recent TCB update. This mechanism prevents acceptance of attestations based on outdated TCB data.

For example, in the LCP Client, zkDCAP is integrated with a mechanism that maintains and updates the latest TCB-R Counter.

As long as **at least one operator continuously fetches the latest TCB data from Intel PCS**, the LCP Client ensures that all operators perform verification using up-to-date TCB info.

See more at: [https://docs.lcp.network/protocol/lcp-client-zkdcap](https://docs.lcp.network/protocol/lcp-client-zkdcap)

## Verifier Program

The guest program that performs DCAP quote verification inside the zkVM is implemented in [main.rs](./zkvm/risc0/guest/src/bin/main.rs).  
It reads a serialized quote, collateral, and the current timestamp as input, verifies the quote using the `verify_quote` function, and commits the verification result as a serialized output.

This program is compiled into a zkVM guest binary and used to generate the zero-knowledge proof (ZKP) that is verified on-chain.

### Inputs

zkDCAP's verifier program takes the following three inputs:

1. **Quote**

   - A DCAP Quote (SGX/TDX, version 3 or 4)
   - Provided as `Quote::V3(QuoteV3)` or `Quote::V4(QuoteV4)`

2. **QvCollateral**

   The collateral required for DCAP quote verification, typically fetched via PCS/PCCS APIs. The following Rust struct defines the format of the `QvCollateral` input, which contains the collateral data used for verification:

   ```rust
   #[derive(Clone, Debug, Default)]
   pub struct QvCollateral {
       pub tcb_info_json: String,
       pub qe_identity_json: String,
       pub sgx_intel_root_ca_der: Vec<u8>,
       pub sgx_tcb_signing_der: Vec<u8>,
       pub sgx_intel_root_ca_crl_der: Vec<u8>,
       pub sgx_pck_crl_der: Vec<u8>,
   }
   ```

   - `tcb_info_json`: Platform TCB info (e.g., TCB levels, SVN)
   - `qe_identity_json`: QE identity including MRSIGNER
   - `sgx_intel_root_ca_der`: Intel SGX Root CA certificate (DER)
   - `sgx_tcb_signing_der`: TCBInfo signing cert (DER)
   - `sgx_intel_root_ca_crl_der` / `sgx_pck_crl_der`: CRLs for revocation checks

3. **current_time**

   - UNIX timestamp (in seconds), provided by the prover
   - zkDCAP uses it only to **compute the intersection of collateral validity periods**
   - The actual time check is performed by the verifier using **on-chain block timestamp**, without relying on the prover to supply a trusted timestamp

### Output

#### `QuoteVerificationOutput`

The result of the verification process, which includes all necessary data to validate the quote and the integrity of the collateral.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteVerificationOutput {
    pub version: u16,
    pub quote_version: u16,
    pub tee_type: u32,
    pub status: Status,
    pub min_tcb_evaluation_data_number: u32,
    pub fmspc: [u8; 6],
    pub sgx_intel_root_ca_hash: [u8; 32],
    pub validity: Validity,
    pub quote_body: QuoteBody,
    pub advisory_ids: Vec<String>,
}
```

Key fields:

1. **min_tcb_evaluation_data_number**  
   Minimum TCB evaluation data number(TCB-R Counter) from the collateral used during verification.  
   The verifier ensures that this value is greater than or equal to the on-chain configured minimum TCB-R Counter.

2. **validity**  
   Validity intersection (NotBefore / NotAfter) of all collateral.
   The verifier checks if the current block timestamp falls within this range.

3. **status** and **advisory_ids**  
   The resulting TCB status and any associated Intel security advisory IDs (e.g., `INTEL-SA-xxxx`).

4. **sgx_intel_root_ca_hash**  
   Keccak-256 hash of the Intel SGX Root CA certificate. The verifier **MUST** ensure this matches the hash of the expected trusted root CA certificate.

5. **quote_body**  
   Includes enclave measurement (`MRENCLAVE`) and attributes from the verified quote.

This output, when verified together with the ZKP on-chain, enables gas-efficient and secure DCAP quote attestation with significantly reduced gas costs.

## Security Audit

zkDCAP was audited as part of its integration into the LCP Client.

The audit was conducted by [Quantstamp](https://quantstamp.com/). You can find the report here:
[https://certificate.quantstamp.com/full/datachain-lcp-zk-dcap/15bac7cd-3b90-47c7-a25e-b0c3214c6630/index.html](https://certificate.quantstamp.com/full/datachain-lcp-zk-dcap/15bac7cd-3b90-47c7-a25e-b0c3214c6630/index.html)

## Build Instructions

To build the zkDCAP guest program for RISC Zero, run the following command:

```bash
ZKDCAP_RISC0_BUILD=1 cargo build -r --manifest-path=./zkvm/risc0/Cargo.toml
```

This will generate the zkVM guest program file here: `./zkvm/risc0/artifacts/dcap-quote-verifier`

**Note:** Ensure that you have the RISC Zero toolchain properly installed before building.

Also, the generated method ID is automatically written to `zkvm/risc0/src/methods.rs`, where it is embedded and used by the prover and verifier to ensure correct proof generation and verification.

## License

This project is licensed under the **Apache 2.0 License**.

## Contributing

Contributions are welcome! Please open issues or pull requests.

## Acknowledgements

- [RISC Zero](https://github.com/risc0/risc0): We thank the RISC Zero team for providing an excellent zkVM.
- [dcap-rs](https://github.com/automata-network/dcap-rs): Our implementation was initially based on the dcap-rs codebase by Automata. We have since extended it significantly through architectural modifications, enhancements, and adaptations to support zkDCAP's design goals.
