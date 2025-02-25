use dcap_types::tcb_info::{
    TcbComponent, TcbInfoV3, TcbInfoV3Inner, TcbInfoV3TcbLevel, TcbInfoV3TcbLevelItem, TdxModule,
    TdxModuleIdentities,
};
use openssl::pkey::{PKeyRef, Private};

use crate::utils::sign;

pub struct TcbInfoV3Builder {
    pub obj: TcbInfoV3Inner,
}

impl TcbInfoV3Builder {
    pub fn new(is_sgx: bool) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                id: if is_sgx {
                    "SGX".to_string()
                } else {
                    "TDX".to_string()
                },
                version: 3,
                ..Default::default()
            },
        }
        .fmspc(Default::default())
        .pce_id(Default::default())
        .issue_date(1)
        .next_update(u32::MAX as i64)
    }

    /// Set the issue date of the TCB Info V3 structure
    ///
    /// # Arguments
    /// - `issue_date` - The issue date in seconds since the Unix epoch
    pub fn issue_date(self, issue_date: i64) -> Self {
        Self {
            obj: TcbInfoV3Inner {
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
            obj: TcbInfoV3Inner {
                next_update: chrono::DateTime::from_timestamp(next_update, 0)
                    .unwrap()
                    .to_rfc3339(),
                ..self.obj
            },
        }
    }

    pub fn fmspc(self, fmspc: [u8; 6]) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                fmspc: hex::encode(fmspc),
                ..self.obj
            },
        }
    }

    pub fn pce_id(self, pce_id: [u8; 2]) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                pce_id: hex::encode(pce_id),
                ..self.obj
            },
        }
    }

    pub fn tcb_type(self, tcb_type: u64) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tcb_type,
                ..self.obj
            },
        }
    }

    pub fn tcb_evaluation_data_number(self, tcb_evaluation_data_number: u32) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tcb_evaluation_data_number,
                ..self.obj
            },
        }
    }

    pub fn tdx_module(self, tdx_module: TdxModule) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tdx_module: Some(tdx_module),
                ..self.obj
            },
        }
    }

    pub fn tdx_module_identities(self, tdx_module_identities: Vec<TdxModuleIdentities>) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tdx_module_identities: Some(tdx_module_identities),
                ..self.obj
            },
        }
    }

    pub fn tcb_levels(self, tcb_levels: Vec<TcbInfoV3TcbLevelItem>) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tcb_levels,
                ..self.obj
            },
        }
    }

    pub fn tcb_levels_json(self, tcb_levels_json: serde_json::Value) -> Self {
        Self {
            obj: TcbInfoV3Inner {
                tcb_levels: serde_json::from_value(tcb_levels_json).unwrap(),
                ..self.obj
            },
        }
    }

    pub fn build(self) -> TcbInfoV3Inner {
        self.obj
    }

    pub fn build_and_sign(
        self,
        tcb_sign_key: &PKeyRef<Private>,
    ) -> Result<TcbInfoV3, anyhow::Error> {
        let tcb_info = self.build();
        let tcb_info_json = serde_json::to_vec(&tcb_info).unwrap();
        let signature = sign(tcb_sign_key, &tcb_info_json)?;
        Ok(TcbInfoV3 {
            tcb_info,
            signature: hex::encode(signature),
        })
    }
}

pub struct TcbInfoV3TcbLevelItemBuilder {
    pub obj: TcbInfoV3TcbLevelItem,
}

impl TcbInfoV3TcbLevelItemBuilder {
    pub fn new(tcb: TcbInfoV3TcbLevel) -> Self {
        Self {
            obj: TcbInfoV3TcbLevelItem {
                tcb,
                tcb_date: chrono::Utc::now().to_rfc3339(),
                tcb_status: "UpToDate".to_string(),
                advisory_ids: None,
            },
        }
    }

    pub fn tcb_date(self, tcb_date: i64) -> Self {
        Self {
            obj: TcbInfoV3TcbLevelItem {
                tcb_date: chrono::DateTime::from_timestamp(tcb_date, 0)
                    .unwrap()
                    .to_rfc3339(),
                ..self.obj
            },
        }
    }

    pub fn tcb_date_str(self, tcb_date_rfc3399: &str) -> Self {
        chrono::DateTime::parse_from_rfc3339(tcb_date_rfc3399).unwrap();
        Self {
            obj: TcbInfoV3TcbLevelItem {
                tcb_date: tcb_date_rfc3399.to_string(),
                ..self.obj
            },
        }
    }

    pub fn tcb_status(self, tcb_status: &str) -> Self {
        Self {
            obj: TcbInfoV3TcbLevelItem {
                tcb_status: tcb_status.to_string(),
                ..self.obj
            },
        }
    }

    pub fn advisory_ids(self, advisory_ids: &[&str]) -> Self {
        Self {
            obj: TcbInfoV3TcbLevelItem {
                advisory_ids: if advisory_ids.is_empty() {
                    None
                } else {
                    Some(advisory_ids.iter().map(|s| s.to_string()).collect())
                },
                ..self.obj
            },
        }
    }

    pub fn build(self) -> TcbInfoV3TcbLevelItem {
        self.obj
    }
}

pub struct TcbInfoV3TcbLevelBuilder {
    pub obj: TcbInfoV3TcbLevel,
}

impl TcbInfoV3TcbLevelBuilder {
    pub fn new() -> Self {
        Self {
            obj: Default::default(),
        }
    }

    pub fn pcesvn(self, pcesvn: u16) -> Self {
        Self {
            obj: TcbInfoV3TcbLevel { pcesvn, ..self.obj },
        }
    }

    pub fn sgxtcbcomponents(self, sgxtcbcomponents: &[u8; 16]) -> Self {
        Self {
            obj: TcbInfoV3TcbLevel {
                sgxtcbcomponents: gen_tcb_components(sgxtcbcomponents),
                ..self.obj
            },
        }
    }

    pub fn tdxtcbcomponents(self, tdxtcbcomponents: [TcbComponent; 16]) -> Self {
        Self {
            obj: TcbInfoV3TcbLevel {
                tdxtcbcomponents: Some(tdxtcbcomponents),
                ..self.obj
            },
        }
    }

    pub fn build(self) -> TcbInfoV3TcbLevel {
        self.obj
    }
}

pub fn gen_tcb_components(svns: &[u8; 16]) -> [TcbComponent; 16] {
    let mut components: Vec<TcbComponent> = vec![Default::default(); 16];
    for i in 0..16 {
        components[i].svn = svns[i];
    }
    components
        .into_iter()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
