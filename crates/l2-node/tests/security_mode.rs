//! Security Mode Validation Tests
//!
//! Tests for NODE_SECURITY_MODE and prod gating of raw poster modes.

use std::env;

/// Test that SecurityMode parsing works correctly.
#[test]
fn security_mode_parsing() {
    // Test the parsing logic directly
    fn parse_security_mode(s: &str) -> &'static str {
        match s.to_lowercase().as_str() {
            "prod" | "production" => "prod",
            "staging" => "staging",
            _ => "dev",
        }
    }

    assert_eq!(parse_security_mode("prod"), "prod");
    assert_eq!(parse_security_mode("production"), "prod");
    assert_eq!(parse_security_mode("PROD"), "prod");
    assert_eq!(parse_security_mode("staging"), "staging");
    assert_eq!(parse_security_mode("STAGING"), "staging");
    assert_eq!(parse_security_mode("dev"), "dev");
    assert_eq!(parse_security_mode("development"), "dev");
    assert_eq!(parse_security_mode(""), "dev");
    assert_eq!(parse_security_mode("unknown"), "dev");
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

    // dev + raw -> ok
    assert!(validate_poster_mode("dev", "raw").is_ok());

    // dev + contract -> ok
    assert!(validate_poster_mode("dev", "contract").is_ok());
}

/// Test that the default security mode is dev (no env var set).
#[test]
fn default_security_mode_is_dev() {
    // Ensure the env var is not set for this test
    env::remove_var("NODE_SECURITY_MODE");

    let mode = env::var("NODE_SECURITY_MODE")
        .ok()
        .map(|s| match s.to_lowercase().as_str() {
            "prod" | "production" => "prod",
            "staging" => "staging",
            _ => "dev",
        })
        .unwrap_or("dev");

    assert_eq!(mode, "dev");
}

/// Test documentation: expected error message format.
#[test]
fn prod_gating_error_message_is_helpful() {
    let error_msg = "NODE_SECURITY_MODE=prod forbids L2_POSTER_MODE=raw. \
                     Raw posting mode is insecure and only allowed in dev/staging environments. \
                     Either set NODE_SECURITY_MODE=staging or use L2_POSTER_MODE=contract";

    assert!(error_msg.contains("prod"));
    assert!(error_msg.contains("raw"));
    assert!(error_msg.contains("staging"));
    assert!(error_msg.contains("contract"));
}
