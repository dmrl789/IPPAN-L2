#![forbid(unsafe_code)]

use crate::metrics;
use l2_core::l1_contract::{L1ChainStatus, L1Client};
use serde::Serialize;
use std::sync::Arc;
use tiny_http::{Header, Response, Server};
use tracing::{info, warn};

#[derive(Debug, Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
}

#[derive(Debug, Serialize)]
struct ReadyResponse<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    l1: Option<L1StatusSummary<'a>>,
}

#[derive(Debug, Serialize)]
struct L1StatusSummary<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn serve(
    bind: &str,
    l1: Arc<dyn L1Client + Send + Sync>,
    expected_network_id: Option<String>,
    metrics_enabled: bool,
) -> Result<(), String> {
    let server =
        Server::http(bind).map_err(|e| format!("failed to bind http server on {bind}: {e}"))?;
    info!(bind, "fin-node http server started");

    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().as_str().to_string();

        let resp = match (method.as_str(), url.as_str()) {
            ("GET", "/healthz") => {
                let body = serde_json::to_string(&HealthResponse { status: "ok" })
                    .unwrap_or_else(|_| "{\"status\":\"ok\"}".to_string());
                let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                Response::from_string(body)
                    .with_status_code(200)
                    .with_header(h)
            }
            ("GET", "/readyz") => {
                let (code, body) = readiness_body(l1.as_ref(), expected_network_id.as_deref());
                let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                Response::from_string(body)
                    .with_status_code(code)
                    .with_header(h)
            }
            ("GET", "/metrics") if metrics_enabled => {
                let body = metrics::gather_text();
                let h = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..])
                    .unwrap();
                Response::from_string(body)
                    .with_status_code(200)
                    .with_header(h)
            }
            ("GET", "/metrics") => {
                Response::from_string("metrics disabled\n").with_status_code(404)
            }
            _ => Response::from_string("not found\n").with_status_code(404),
        };

        if let Err(e) = req.respond(resp) {
            warn!(error = %e, "failed writing http response");
        }
    }
    Ok(())
}

fn readiness_body(l1: &dyn L1Client, expected_network_id: Option<&str>) -> (u16, String) {
    match l1.chain_status() {
        Ok(L1ChainStatus {
            network_id, height, ..
        }) => {
            if let Some(expected) = expected_network_id {
                if network_id.0 != expected {
                    let body = ReadyResponse {
                        status: "not_ready",
                        l1: Some(L1StatusSummary {
                            ok: false,
                            network_id: Some(&network_id.0),
                            height: Some(height.0),
                            error: Some(format!("network_id mismatch (expected {expected})")),
                        }),
                    };
                    return (503, serde_json::to_string(&body).unwrap_or_default());
                }
            }
            let body = ReadyResponse {
                status: "ready",
                l1: Some(L1StatusSummary {
                    ok: true,
                    network_id: Some(&network_id.0),
                    height: Some(height.0),
                    error: None,
                }),
            };
            (200, serde_json::to_string(&body).unwrap_or_default())
        }
        Err(e) => {
            let body = ReadyResponse {
                status: "not_ready",
                l1: Some(L1StatusSummary {
                    ok: false,
                    network_id: None,
                    height: None,
                    error: Some(e.to_string()),
                }),
            };
            (503, serde_json::to_string(&body).unwrap_or_default())
        }
    }
}
