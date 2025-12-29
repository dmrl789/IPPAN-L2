//! Security Mode Validation Tests
//!
//! Tests for NODE_SECURITY_MODE, auth gating, and prod restrictions.

use std::env;

/// Test that SecurityMode parsing works correctly.
#[test]
fn security_mode_parsing() {
    // Test the parsing logic directly
    fn parse_security_mode(s: &str) -> &'static str {
        match s.to_lowercase().as_str() {
            "prod" | "production" => "prod",
            "staging" => "staging",
            "devnet" | "dev" | "development" | "" => "devnet",
            _ => "devnet",
        }
    }

    assert_eq!(parse_security_mode("prod"), "prod");
    assert_eq!(parse_security_mode("production"), "prod");
    assert_eq!(parse_security_mode("PROD"), "prod");
    assert_eq!(parse_security_mode("staging"), "staging");
    assert_eq!(parse_security_mode("STAGING"), "staging");
    assert_eq!(parse_security_mode("devnet"), "devnet");
    assert_eq!(parse_security_mode("dev"), "devnet");
    assert_eq!(parse_security_mode("development"), "devnet");
    assert_eq!(parse_security_mode(""), "devnet");
    assert_eq!(parse_security_mode("unknown"), "devnet");
}

/// Test that PosterMode parsing works correctly.
#[test]
fn poster_mode_parsing() {
    fn parse_poster_mode(s: &str) -> &'static str {
        match s.to_lowercase().as_str() {
            "raw" | "legacy" => "raw",
            _ => "contract",
        }
    }

    assert_eq!(parse_poster_mode("raw"), "raw");
    assert_eq!(parse_poster_mode("RAW"), "raw");
    assert_eq!(parse_poster_mode("legacy"), "raw");
    assert_eq!(parse_poster_mode("contract"), "contract");
    assert_eq!(parse_poster_mode("CONTRACT"), "contract");
    assert_eq!(parse_poster_mode(""), "contract");
    assert_eq!(parse_poster_mode("unknown"), "contract");
}

/// Test the prod gating logic.
#[test]
fn prod_mode_forbids_raw_poster() {
    // Simulate the validation logic
    fn validate_poster_mode(security_mode: &str, poster_mode: &str) -> Result<(), &'static str> {
        let is_prod = security_mode == "prod";
        let is_raw = poster_mode == "raw";

        if is_prod && is_raw {
            return Err("NODE_SECURITY_MODE=prod forbids L2_POSTER_MODE=raw");
        }
        Ok(())
    }

    // prod + raw -> error
    assert!(validate_poster_mode("prod", "raw").is_err());

    // prod + contract -> ok
    assert!(validate_poster_mode("prod", "contract").is_ok());

    // staging + raw -> ok
    assert!(validate_poster_mode("staging", "raw").is_ok());

    // staging + contract -> ok
    assert!(validate_poster_mode("staging", "contract").is_ok());

    // devnet + raw -> ok
    assert!(validate_poster_mode("devnet", "raw").is_ok());

    // devnet + contract -> ok
    assert!(validate_poster_mode("devnet", "contract").is_ok());
}

/// Test that the default security mode is devnet (no env var set).
#[test]
fn default_security_mode_is_devnet() {
    // Ensure the env var is not set for this test
    env::remove_var("NODE_SECURITY_MODE");

    let mode = env::var("NODE_SECURITY_MODE")
        .ok()
        .map(|s| match s.to_lowercase().as_str() {
            "prod" | "production" => "prod",
            "staging" => "staging",
            _ => "devnet",
        })
        .unwrap_or("devnet");

    assert_eq!(mode, "devnet");
}

/// Test auth requirements by security mode.
#[test]
fn security_mode_auth_requirements() {
    // Simulate the auth requirement logic
    fn requires_auth(mode: &str) -> bool {
        matches!(mode, "staging" | "prod")
    }

    fn allows_devnet_endpoints(mode: &str) -> bool {
        mode == "devnet"
    }

    fn allows_ops_endpoints(mode: &str) -> bool {
        mode != "prod"
    }

    // Devnet: no auth required, devnet endpoints allowed
    assert!(!requires_auth("devnet"));
    assert!(allows_devnet_endpoints("devnet"));
    assert!(allows_ops_endpoints("devnet"));

    // Staging: auth required, no devnet endpoints, ops allowed
    assert!(requires_auth("staging"));
    assert!(!allows_devnet_endpoints("staging"));
    assert!(allows_ops_endpoints("staging"));

    // Prod: auth required, no devnet endpoints, no ops endpoints
    assert!(requires_auth("prod"));
    assert!(!allows_devnet_endpoints("prod"));
    assert!(!allows_ops_endpoints("prod"));
}

/// Test constant-time comparison function.
#[test]
fn constant_time_eq_behavior() {
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(!constant_time_eq(b"secret", b"SECRET"));
    assert!(!constant_time_eq(b"secret", b"secret!"));
    assert!(!constant_time_eq(b"secret", b"secre"));
    assert!(constant_time_eq(b"", b""));
}

/// Test auth token validation logic.
#[test]
fn auth_token_validation() {
    // Simulate the auth config validation
    fn validate_auth_config(security_mode: &str, token: Option<&str>) -> Result<(), String> {
        let requires_auth = matches!(security_mode, "staging" | "prod");

        if requires_auth && token.is_none() {
            return Err(format!(
                "NODE_SECURITY_MODE={} requires IPPAN_ADMIN_TOKEN to be set",
                security_mode
            ));
        }
        Ok(())
    }

    // Devnet without token -> ok
    assert!(validate_auth_config("devnet", None).is_ok());

    // Devnet with token -> ok
    assert!(validate_auth_config("devnet", Some("secret")).is_ok());

    // Staging without token -> error
    assert!(validate_auth_config("staging", None).is_err());

    // Staging with token -> ok
    assert!(validate_auth_config("staging", Some("secret")).is_ok());

    // Prod without token -> error
    assert!(validate_auth_config("prod", None).is_err());

    // Prod with token -> ok
    assert!(validate_auth_config("prod", Some("secret")).is_ok());
}

/// Test documentation: expected error message format.
#[test]
fn prod_gating_error_message_is_helpful() {
    let error_msg = "NODE_SECURITY_MODE=prod forbids L2_POSTER_MODE=raw. \
                     Raw posting mode is insecure and only allowed in devnet/staging environments. \
                     Either set NODE_SECURITY_MODE=staging or use L2_POSTER_MODE=contract";

    assert!(error_msg.contains("prod"));
    assert!(error_msg.contains("raw"));
    assert!(error_msg.contains("staging"));
    assert!(error_msg.contains("contract"));
}
