use std::fmt::Display;

use dcap_types::enclave_identity::{
    EnclaveIdentityV2, EnclaveIdentityV2Inner, EnclaveIdentityV2TcbLevelItem,
};
use openssl::pkey::{PKeyRef, Private};

use crate::utils::sign;

pub struct EnclaveIdentityV2Builder {
    obj: EnclaveIdentityV2Inner,
}

#[allow(non_camel_case_types)]
pub enum EnclaveIdentityId {
    QE,
    TD_QE,
}

impl Display for EnclaveIdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnclaveIdentityId::QE => write!(f, "QE"),
            EnclaveIdentityId::TD_QE => write!(f, "TD_QE"),
        }
    }
}

impl EnclaveIdentityV2Builder {
    pub fn new(id: EnclaveIdentityId) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                version: 2,
                id: id.to_string(),
                ..Default::default()
            },
        }
        .issue_date(1)
        .next_update(u32::MAX as i64)
        .miscselect(Default::default())
        .miscselect_mask(Default::default())
        .attributes(Default::default())
        .attributes_mask(Default::default())
        .mrsigner(Default::default())
    }

    pub fn version(self, version: u64) -> Self {
        // self.obj.version = version;
        // self
        Self {
            obj: EnclaveIdentityV2Inner {
                version,
                ..self.obj
            },
        }
    }

    /// Set the issue date of the TCB Info V3 structure
    ///
    /// # Arguments
    /// - `issue_date` - The issue date in seconds since the Unix epoch
    pub fn issue_date(self, issue_date: i64) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                issue_date: chrono::DateTime::from_timestamp(issue_date, 0)
                    .unwrap()
                    .to_rfc3339(),
                ..self.obj
            },
        }
    }

    /// Set the next update date of the TCB Info V3 structure
    ///
    /// # Arguments
    /// - `next_update` - The next update date in seconds since the Unix epoch
    pub fn next_update(self, next_update: i64) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                next_update: chrono::DateTime::from_timestamp(next_update, 0)
                    .unwrap()
                    .to_rfc3339(),
                ..self.obj
            },
        }
    }

    pub fn tcb_evaluation_data_number(self, tcb_evaluation_data_number: u32) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                tcb_evaluation_data_number,
                ..self.obj
            },
        }
    }

    pub fn miscselect(self, miscselect: [u8; 4]) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                miscselect: hex::encode(miscselect),
                ..self.obj
            },
        }
    }

    pub fn miscselect_mask(self, miscselect_mask: [u8; 4]) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                miscselect_mask: hex::encode(miscselect_mask),
                ..self.obj
            },
        }
    }

    pub fn attributes(self, attributes: [u8; 16]) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                attributes: hex::encode(attributes),
                ..self.obj
            },
        }
    }

    pub fn attributes_mask(self, attributes_mask: [u8; 16]) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                attributes_mask: hex::encode(attributes_mask),
                ..self.obj
            },
        }
    }

    pub fn mrsigner(self, mrsigner: [u8; 32]) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                mrsigner: hex::encode(mrsigner),
                ..self.obj
            },
        }
    }

    pub fn isvprodid(self, isvprodid: u16) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                isvprodid,
                ..self.obj
            },
        }
    }

    pub fn tcb_levels(self, tcb_levels: Vec<EnclaveIdentityV2TcbLevelItem>) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                tcb_levels,
                ..self.obj
            },
        }
    }

    pub fn tcb_levels_json(self, tcb_levels_json: serde_json::Value) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                tcb_levels: serde_json::from_value(tcb_levels_json).unwrap(),
                ..self.obj
            },
        }
    }

    pub fn tcb_levels_json_str(self, tcb_levels_json_str: &str) -> Self {
        Self {
            obj: EnclaveIdentityV2Inner {
                tcb_levels: serde_json::from_str(tcb_levels_json_str).unwrap(),
                ..self.obj
            },
        }
    }

    pub fn build(self) -> EnclaveIdentityV2Inner {
        self.obj
    }

    pub fn build_and_sign(
        self,
        tcb_sign_key: &PKeyRef<Private>,
    ) -> Result<EnclaveIdentityV2, anyhow::Error> {
        let enclave_identity = self.build();
        let enclave_identity_json = serde_json::to_vec(&enclave_identity).unwrap();
        let signature = sign(tcb_sign_key, &enclave_identity_json)?;
        Ok(EnclaveIdentityV2 {
            enclave_identity,
            signature: hex::encode(signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_enclave_identity_build() {
        let eid = EnclaveIdentityV2Builder::new(EnclaveIdentityId::QE)
            .version(2)
            .issue_date(1)
            .next_update(u32::MAX as i64)
            .tcb_evaluation_data_number(1)
            .miscselect([0; 4])
            .miscselect_mask([0; 4])
            .attributes([0; 16])
            .attributes_mask([0; 16])
            .mrsigner([0; 32])
            .isvprodid(0)
            .tcb_levels_json(json!([
            {
              "tcb": {
                "isvsvn": 8
              },
              "tcbDate": "2023-08-09T00:00:00Z",
              "tcbStatus": "UpToDate"
            },
            {
              "tcb": {
                "isvsvn": 6
              },
              "tcbDate": "2021-11-10T00:00:00Z",
              "tcbStatus": "OutOfDate"
            },
            {
              "tcb": {
                "isvsvn": 5
              },
              "tcbDate": "2020-11-11T00:00:00Z",
              "tcbStatus": "OutOfDate"
            },
            {
              "tcb": {
                "isvsvn": 4
              },
              "tcbDate": "2019-11-13T00:00:00Z",
              "tcbStatus": "OutOfDate"
            },
            {
              "tcb": {
                "isvsvn": 2
              },
              "tcbDate": "2019-05-15T00:00:00Z",
              "tcbStatus": "OutOfDate"
            },
            {
              "tcb": {
                "isvsvn": 1
              },
              "tcbDate": "2018-08-15T00:00:00Z",
              "tcbStatus": "OutOfDate"
            }]))
            .build();

        assert_eq!(eid.tcb_levels.len(), 6);
    }
}
