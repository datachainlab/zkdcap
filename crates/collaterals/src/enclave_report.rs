use dcap_types::{
    enclave_identity::EnclaveIdentityV2Inner,
    quotes::{body::EnclaveReport, QeAuthData},
};
use openssl::sha::sha256;

pub fn build_qe_report_data(attestation_pub_key: &[u8; 64], auth_data: QeAuthData) -> [u8; 64] {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(attestation_pub_key);
    verification_data.extend_from_slice(&auth_data.data);

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(sha256(&verification_data).as_ref());
    report_data
}

pub fn build_qe_auth_data(size: u16) -> QeAuthData {
    let data = vec![0u8; size as usize];
    QeAuthData { size, data }
}

pub struct EnclaveReportBuilder {
    obj: EnclaveReport,
}

impl EnclaveReportBuilder {
    pub fn new() -> Self {
        Self {
            obj: Default::default(),
        }
    }

    pub fn build(self) -> EnclaveReport {
        self.obj
    }

    pub fn build_ref(&self) -> &EnclaveReport {
        &self.obj
    }

    pub fn cpu_svn(self, cpu_svn: [u8; 16]) -> Self {
        Self {
            obj: EnclaveReport {
                cpu_svn,
                ..self.obj
            },
        }
    }

    pub fn misc_select(self, misc_select: [u8; 4]) -> Self {
        Self {
            obj: EnclaveReport {
                misc_select,
                ..self.obj
            },
        }
    }

    pub fn reserved_1(self, reserved_1: [u8; 28]) -> Self {
        Self {
            obj: EnclaveReport {
                reserved_1,
                ..self.obj
            },
        }
    }

    pub fn attributes(self, attributes: [u8; 16]) -> Self {
        Self {
            obj: EnclaveReport {
                attributes,
                ..self.obj
            },
        }
    }

    pub fn mrenclave(self, mrenclave: [u8; 32]) -> Self {
        Self {
            obj: EnclaveReport {
                mrenclave,
                ..self.obj
            },
        }
    }

    pub fn reserved_2(self, reserved_2: [u8; 32]) -> Self {
        Self {
            obj: EnclaveReport {
                reserved_2,
                ..self.obj
            },
        }
    }

    pub fn mrsigner(self, mrsigner: [u8; 32]) -> Self {
        Self {
            obj: EnclaveReport {
                mrsigner,
                ..self.obj
            },
        }
    }

    pub fn reserved_3(self, reserved_3: [u8; 96]) -> Self {
        Self {
            obj: EnclaveReport {
                reserved_3,
                ..self.obj
            },
        }
    }

    pub fn isv_prod_id(self, isv_prod_id: u16) -> Self {
        Self {
            obj: EnclaveReport {
                isv_prod_id,
                ..self.obj
            },
        }
    }

    pub fn isv_svn(self, isv_svn: u16) -> Self {
        Self {
            obj: EnclaveReport {
                isv_svn,
                ..self.obj
            },
        }
    }

    pub fn reserved_4(self, reserved_4: [u8; 60]) -> Self {
        Self {
            obj: EnclaveReport {
                reserved_4,
                ..self.obj
            },
        }
    }

    pub fn report_data(self, report_data: [u8; 64]) -> Self {
        Self {
            obj: EnclaveReport {
                report_data,
                ..self.obj
            },
        }
    }

    pub fn with_enclave_identity_v2(
        self,
        enclave_identity_v2: &EnclaveIdentityV2Inner,
    ) -> Result<Self, anyhow::Error> {
        Ok(self
            .mrsigner(enclave_identity_v2.mrsigner()?)
            .isv_prod_id(enclave_identity_v2.isvprodid)
            .attributes(enclave_identity_v2.attributes()?)
            .misc_select(enclave_identity_v2.miscselect()?.to_le_bytes()))
    }
}
