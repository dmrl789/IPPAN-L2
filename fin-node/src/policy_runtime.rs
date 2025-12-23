#![forbid(unsafe_code)]

use crate::policy_store::PolicyStore;
use l2_core::policy::{PolicyDenyCode, PolicyMode};
use l2_core::AccountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStrategy {
    None,
    GlobalAllowlist,
    GlobalDenylist,
}

#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    pub enabled: bool,
    pub strategy: ComplianceStrategy,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: ComplianceStrategy::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRuntime {
    pub mode: PolicyMode,
    pub admins: Vec<AccountId>,
    pub compliance: ComplianceConfig,
    pub store: Option<PolicyStore>,
}

impl Default for PolicyRuntime {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Permissive,
            admins: Vec::new(),
            compliance: ComplianceConfig::default(),
            store: None,
        }
    }
}

impl PolicyRuntime {
    #[allow(dead_code)]
    pub fn is_admin(&self, a: &AccountId) -> bool {
        self.admins.iter().any(|x| x == a)
    }

    fn store(&self) -> Result<&PolicyStore, String> {
        self.store
            .as_ref()
            .ok_or_else(|| "policy store not configured".to_string())
    }

    fn compliance_enabled(&self) -> bool {
        self.compliance.enabled && self.compliance.strategy != ComplianceStrategy::None
    }

    pub fn compliance_check_accounts(&self, accounts: &[AccountId]) -> Result<(), String> {
        if !self.compliance_enabled() {
            return Ok(());
        }
        let store = self.store()?;
        match self.compliance.strategy {
            ComplianceStrategy::None => Ok(()),
            ComplianceStrategy::GlobalAllowlist => {
                for a in accounts {
                    if !store.is_allowlisted(&a.0).map_err(|e| e.to_string())? {
                        return Err(format!(
                            "policy:{}:{}",
                            PolicyDenyCode::ComplianceDenied.as_str(),
                            "account not in allowlist"
                        ));
                    }
                }
                Ok(())
            }
            ComplianceStrategy::GlobalDenylist => {
                for a in accounts {
                    if store.is_denylisted(&a.0).map_err(|e| e.to_string())? {
                        return Err(format!(
                            "policy:{}:{}",
                            PolicyDenyCode::ComplianceDenied.as_str(),
                            "account denylisted"
                        ));
                    }
                }
                Ok(())
            }
        }
    }

    pub fn require_actor_if_compliance_enabled(
        &self,
        actor: Option<&AccountId>,
    ) -> Result<(), String> {
        if self.compliance_enabled() && actor.is_none() {
            return Err(format!(
                "policy:{}:{}",
                PolicyDenyCode::MissingActor.as_str(),
                "missing actor"
            ));
        }
        Ok(())
    }
}
