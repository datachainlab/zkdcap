use dcap_collaterals::openssl::pkey::{PKeyRef, Private};
use dcap_collaterals::utils::sign;
use dcap_types::{
    enclave_identity::{EnclaveIdentityV2, EnclaveIdentityV2Inner},
    tcb_info::{TcbInfoV3, TcbInfoV3Inner},
};

pub(crate) fn gen_enclave_identity(
    pkey: &PKeyRef<Private>,
    enclave_identity: EnclaveIdentityV2Inner,
) -> Result<EnclaveIdentityV2, anyhow::Error> {
    let bz = serde_json::to_vec(&enclave_identity)?;
    let signature = sign(pkey, &bz)?;
    Ok(EnclaveIdentityV2 {
        enclave_identity,
        signature: hex::encode(signature),
    })
}

pub(crate) fn gen_tcb_info_v3(
    pkey: &PKeyRef<Private>,
    tcb_info: TcbInfoV3Inner,
) -> Result<TcbInfoV3, anyhow::Error> {
    let bz = serde_json::to_vec(&tcb_info)
        .map_err(|e| anyhow::anyhow!("Failed to serialize TcbInfoV3Inner: {}", e))?;
    let signature = sign(pkey, &bz)?;
    Ok(TcbInfoV3 {
        tcb_info,
        signature: hex::encode(signature),
    })
}
