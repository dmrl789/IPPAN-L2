#![forbid(unsafe_code)]

use crate::data_api::{ApiError as DataApiError, DataApi};
use crate::fin_api::{ApiError, FinApi};
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
    fin_api: FinApi,
    data_api: DataApi,
) -> Result<(), String> {
    let server =
        Server::http(bind).map_err(|e| format!("failed to bind http server on {bind}: {e}"))?;
    info!(bind, "fin-node http server started");

    for mut req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().as_str().to_string();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));

        let resp = match (method.as_str(), path) {
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
            ("POST", "/fin/actions") => {
                let mut body = Vec::new();
                if let Err(e) = req.as_reader().read_to_end(&mut body) {
                    return Err(format!("failed reading request body: {e}"));
                }
                match fin_api.submit_action(&body) {
                    Ok(out) => json_response(200, &out),
                    Err(e) => api_error_response(e),
                }
            }
            ("POST", "/data/datasets") => {
                let mut body = Vec::new();
                if let Err(e) = req.as_reader().read_to_end(&mut body) {
                    return Err(format!("failed reading request body: {e}"));
                }
                match serde_json::from_slice::<hub_data::RegisterDatasetRequestV1>(&body) {
                    Ok(req) => match data_api.submit_register_dataset(req) {
                        Ok(out) => json_response(200, &out),
                        Err(e) => data_api_error_response(e),
                    },
                    Err(e) => json_response(
                        400,
                        &serde_json::json!({"schema_version": 1, "error": e.to_string()}),
                    ),
                }
            }
            ("POST", "/data/licenses") => {
                let mut body = Vec::new();
                if let Err(e) = req.as_reader().read_to_end(&mut body) {
                    return Err(format!("failed reading request body: {e}"));
                }
                match serde_json::from_slice::<hub_data::IssueLicenseRequestV1>(&body) {
                    Ok(req) => match data_api.submit_issue_license(req) {
                        Ok(out) => json_response(200, &out),
                        Err(e) => data_api_error_response(e),
                    },
                    Err(e) => json_response(
                        400,
                        &serde_json::json!({"schema_version": 1, "error": e.to_string()}),
                    ),
                }
            }
            ("POST", "/data/attestations") => {
                let mut body = Vec::new();
                if let Err(e) = req.as_reader().read_to_end(&mut body) {
                    return Err(format!("failed reading request body: {e}"));
                }
                match serde_json::from_slice::<hub_data::AppendAttestationRequestV1>(&body) {
                    Ok(req) => match data_api.submit_append_attestation(req) {
                        Ok(out) => json_response(200, &out),
                        Err(e) => data_api_error_response(e),
                    },
                    Err(e) => json_response(
                        400,
                        &serde_json::json!({"schema_version": 1, "error": e.to_string()}),
                    ),
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") && p.ends_with("/licenses") => {
                let dataset_id = p
                    .trim_start_matches("/data/datasets/")
                    .trim_end_matches("/licenses");
                match data_api.list_licenses_by_dataset(dataset_id) {
                    Ok(list) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "licenses": list}),
                    ),
                    Err(e) => data_api_error_response(e),
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") && p.ends_with("/attestations") => {
                let dataset_id = p
                    .trim_start_matches("/data/datasets/")
                    .trim_end_matches("/attestations");
                match data_api.list_attestations_by_dataset(dataset_id) {
                    Ok(list) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "attestations": list}),
                    ),
                    Err(e) => data_api_error_response(e),
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") => {
                let dataset_id = p.trim_start_matches("/data/datasets/");
                match data_api.get_dataset(dataset_id) {
                    Ok(Some(ds)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset": ds}),
                    ),
                    Ok(None) => json_response(
                        404,
                        &serde_json::json!({"schema_version": 1, "error": "not_found"}),
                    ),
                    Err(e) => data_api_error_response(e),
                }
            }
            ("GET", p) if p.starts_with("/data/licenses/") => {
                let license_id = p.trim_start_matches("/data/licenses/");
                match data_api.get_license(license_id) {
                    Ok(Some(lic)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "license": lic}),
                    ),
                    Ok(None) => json_response(
                        404,
                        &serde_json::json!({"schema_version": 1, "error": "not_found"}),
                    ),
                    Err(e) => data_api_error_response(e),
                }
            }
            ("GET", p) if p.starts_with("/fin/assets/") => {
                let asset_id = p.trim_start_matches("/fin/assets/");
                match fin_api.get_asset(asset_id) {
                    Ok(Some(asset)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "asset": asset}),
                    ),
                    Ok(None) => json_response(
                        404,
                        &serde_json::json!({"schema_version": 1, "error": "not_found"}),
                    ),
                    Err(e) => api_error_response(e),
                }
            }
            ("GET", "/fin/balances") => {
                let params = parse_query(query);
                let asset_id = params.get("asset_id").map(String::as_str).unwrap_or("");
                let account = params.get("account").map(String::as_str).unwrap_or("");
                if asset_id.is_empty() || account.is_empty() {
                    json_response(
                        400,
                        &serde_json::json!({"schema_version": 1, "error": "missing asset_id or account"}),
                    )
                } else {
                    match fin_api.get_balance(asset_id, account) {
                        Ok(amount) => json_response(
                            200,
                            &serde_json::json!({"schema_version": 1, "asset_id": asset_id, "account": account, "amount_scaled_u128": amount}),
                        ),
                        Err(e) => api_error_response(e),
                    }
                }
            }
            ("GET", p) if p.starts_with("/fin/receipts/") => {
                let action_id = p.trim_start_matches("/fin/receipts/");
                match fin_api.get_receipt(action_id) {
                    Ok(Some(raw)) => {
                        let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                        Response::from_data(raw)
                            .with_status_code(200)
                            .with_header(h)
                    }
                    Ok(None) => json_response(
                        404,
                        &serde_json::json!({"schema_version": 1, "error": "not_found"}),
                    ),
                    Err(e) => api_error_response(e),
                }
            }
            ("GET", p) if p.starts_with("/data/receipts/") => {
                let action_id = p.trim_start_matches("/data/receipts/");
                match data_api.get_receipt(action_id) {
                    Ok(Some(raw)) => {
                        let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                        Response::from_data(raw)
                            .with_status_code(200)
                            .with_header(h)
                    }
                    Ok(None) => json_response(
                        404,
                        &serde_json::json!({"schema_version": 1, "error": "not_found"}),
                    ),
                    Err(e) => data_api_error_response(e),
                }
            }
            _ => Response::from_string("not found\n").with_status_code(404),
        };

        if let Err(e) = req.respond(resp) {
            warn!(error = %e, "failed writing http response");
        }
    }
    Ok(())
}

fn json_response<T: Serialize>(code: u16, v: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_data(body)
        .with_status_code(code)
        .with_header(h)
}

fn api_error_response(e: ApiError) -> Response<std::io::Cursor<Vec<u8>>> {
    match e {
        ApiError::BadRequest(msg) => {
            json_response(400, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
        ApiError::Upstream(msg) => {
            json_response(502, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
        ApiError::Internal(msg) => {
            json_response(500, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
    }
}

fn data_api_error_response(e: DataApiError) -> Response<std::io::Cursor<Vec<u8>>> {
    match e {
        DataApiError::BadRequest(msg) => {
            json_response(400, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
        DataApiError::Upstream(msg) => {
            json_response(502, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
        DataApiError::Internal(msg) => {
            json_response(500, &serde_json::json!({"schema_version": 1, "error": msg}))
        }
    }
}

fn parse_query(q: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for part in q.split('&') {
        if part.trim().is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let k = url_decode(k);
        let v = url_decode(v);
        out.insert(k, v);
    }
    out
}

fn url_decode(s: &str) -> String {
    // Minimal query decoding: replace '+' with space and decode %XX.
    let s = s.replace('+', " ");
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if let (Some(hi), Some(lo)) = (from_hex(hi), from_hex(lo)) {
                out.push((hi * 16 + lo) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
