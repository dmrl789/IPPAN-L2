#![forbid(unsafe_code)]

//! Minimal, explicit policy primitives shared across hubs and fin-node.
//!
//! Design goals:
//! - Deterministic evaluation (state + request fields only)
//! - No external calls, no time dependence
//! - Stable denial codes for auditability and operator UX

use crate::{AccountId, L2HubId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Coarse-grained roles used by policy surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Issuer,
    Operator,
    Admin,
}

/// Policy mode for runtime orchestration.
///
/// Notes:
/// - `Permissive` is intended for local/dev usage.
/// - `Strict` is intended for production operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Permissive,
    Strict,
}

/// High-level action kinds across hubs.
///
/// This is intentionally small and explicit to keep audits tractable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    // hub-fin
    FinCreateAsset,
    FinMintUnits,
    FinTransferUnits,
    FinDelegateOperator,
    FinRevokeDelegateOperator,

    // hub-data
    DataRegisterDataset,
    DataCreateListing,
    DataIssueLicense,
    DataGrantEntitlement,
    DataAppendAttestation,
    DataAddLicensor,
    DataAddAttestor,
}

/// Stable denial codes for policy rejections.
///
/// These are part of the operator contract: do not rename or reuse codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDenyCode {
    /// Actor identity is missing where required in strict mode.
    MissingActor,
    /// Actor is not authorized to perform this action.
    Unauthorized,
    /// Requested operation requires an explicit operator delegation.
    DelegationRequired,
    /// The referenced asset/dataset/listing does not exist.
    NotFound,
    /// Actor or target is blocked by an orchestration-layer compliance hook.
    ComplianceDenied,
    /// Input violates a policy precondition (distinct from schema validation).
    InvalidPolicyInput,
}

impl PolicyDenyCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyDenyCode::MissingActor => "missing_actor",
            PolicyDenyCode::Unauthorized => "unauthorized",
            PolicyDenyCode::DelegationRequired => "delegation_required",
            PolicyDenyCode::NotFound => "not_found",
            PolicyDenyCode::ComplianceDenied => "compliance_denied",
            PolicyDenyCode::InvalidPolicyInput => "invalid_policy_input",
        }
    }
}

/// Minimal subject identifiers associated with a policy check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySubjects {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
}

/// Deterministic context for an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationContext {
    pub actor: AccountId,
    pub hub: L2HubId,
    pub action: ActionKind,
    #[serde(default)]
    pub subjects: PolicySubjects,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_u128: Option<u128>,
}

/// Policy decision for a given authorization context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum PolicyDecision {
    Allow,
    Deny {
        code: PolicyDenyCode,
        /// Static, sanitized message.
        message: &'static str,
    },
}

impl PolicyDecision {
    pub fn deny(code: PolicyDenyCode, message: &'static str) -> Self {
        Self::Deny { code, message }
    }

    pub const fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// Standardized policy error returned by orchestration layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("policy denied ({code:?}): {message}")]
pub struct PolicyError {
    pub code: PolicyDenyCode,
    /// Sanitized message (no sensitive identifiers).
    pub message: String,
    /// Deterministic context identifier (for operator correlation).
    pub context_id: String,
}
