#![forbid(unsafe_code)]
// Prometheus histograms require `f64` observations.
#![allow(clippy::float_arithmetic)]
#![allow(clippy::float_cmp)]

use crate::bootstrap_mirror_health::MirrorHealthStore;
use crate::config::{
    CorsConfig, LimitsConfig, PaginationConfig, RateLimitConfig, SecurityConfig, SecurityMode,
};
use crate::data_api::{ApiError as DataApiError, DataApi};
use crate::fin_api::{ApiError, FinApi};
use crate::ha::supervisor::HaState;
use crate::linkage::{ApiError as LinkageApiError, BuyLicenseRequestV1, LinkageApi};
use crate::metrics;
use crate::rate_limit::{RateLimiter, SystemTimeSource};
use crate::recon_store::ReconStore;
use l2_core::l1_contract::{L1ChainStatus, L1Client};
use serde::Serialize;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tiny_http::{Header, Response, Server};
use tracing::{info, warn};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
const API_VERSION: &str = "v1";
static OPENAPI_SPEC_V1: &str = include_str!("../../docs/openapi/fin-node.openapi.json");

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

#[derive(Debug, Clone, Serialize)]
pub struct EncryptionStatus {
    pub schema_version: u32,
    pub enabled: bool,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_key_id: Option<String>,
    pub keyring_ids: Vec<String>,
    pub plaintext_allowed: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn serve(
    bind: &str,
    l1: Arc<dyn L1Client + Send + Sync>,
    expected_network_id: Option<String>,
    metrics_enabled: bool,
    fin_api: FinApi,
    data_api: DataApi,
    linkage_api: LinkageApi,
    recon: Option<ReconStore>,
    limits: LimitsConfig,
    pagination: PaginationConfig,
    rate_limit: RateLimitConfig,
    security: SecurityConfig,
    _cors: CorsConfig,
    max_inflight_requests: usize,
    bootstrap_db_dir: String,
    encryption_status: EncryptionStatus,
    ha_state: Arc<HaState>,
    write_pause: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let server =
        Server::http(bind).map_err(|e| format!("failed to bind http server on {bind}: {e}"))?;
    info!(
        bind,
        mode = security.mode.name(),
        "fin-node http server started"
    );

    let limiter = Arc::new(RateLimiter::new(rate_limit, SystemTimeSource));
    let inflight = Arc::new(AtomicUsize::new(0));
    let security = Arc::new(security);

    while !stop.load(Ordering::Relaxed) {
        let mut req = match server.recv_timeout(Duration::from_millis(250)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                warn!(error = %e, "http accept failed");
                continue;
            }
        };

        let request_id = new_request_id();
        let origin = header_value(&req, "Origin");
        let started = std::time::Instant::now();

        let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
        let _guard = InflightGuard {
            inflight: inflight.clone(),
        };
        if cur > max_inflight_requests.max(1) {
            metrics::HTTP_REQUESTS_TOTAL
                .with_label_values(&["overloaded", "503"])
                .inc();
            metrics::HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&["overloaded"])
                .observe(started.elapsed().as_secs_f64());
            let resp = error_response(503, "overloaded", "node_overloaded", &request_id);
            let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
            let _ = req.respond(resp);
            continue;
        }

        let url = req.url().to_string();
        let method = req.method().as_str().to_string();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));
        let (path, is_versioned) = strip_api_v1_prefix(path);
        let route = route_label(method.as_str(), path);
        let ip = req
            .remote_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        // Per-IP rate limiting with route-aware cost (best-effort, deterministic).
        if limiter.enabled() {
            let d = limiter.check_route(&ip, path);
            if !d.allowed {
                metrics::RATE_LIMITED_TOTAL.with_label_values(&["ip"]).inc();
                metrics::HTTP_RATE_LIMITED_TOTAL
                    .with_label_values(&[route])
                    .inc();
                metrics::HTTP_REQUESTS_TOTAL
                    .with_label_values(&[route, "429"])
                    .inc();
                metrics::HTTP_REQUEST_DURATION_SECONDS
                    .with_label_values(&[route])
                    .observe(started.elapsed().as_secs_f64());
                let resp = with_common_headers(
                    rate_limited_response(d.retry_after_secs, &request_id),
                    &request_id,
                    &_cors,
                    origin.as_deref(),
                );
                // Ignore respond errors (client disconnected).
                let _ = req.respond(resp);
                continue;
            }
        }

        // Security mode gating: check if route is allowed in current mode.
        match check_security(&security, &req, path) {
            SecurityCheckResult::Allowed => {}
            SecurityCheckResult::RouteDisabled => {
                metrics::SECURITY_ROUTE_GATED_TOTAL
                    .with_label_values(&[route])
                    .inc();
                metrics::HTTP_REQUESTS_TOTAL
                    .with_label_values(&[route, "404"])
                    .inc();
                metrics::HTTP_REQUEST_DURATION_SECONDS
                    .with_label_values(&[route])
                    .observe(started.elapsed().as_secs_f64());
                let resp = route_disabled_response(&request_id);
                let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
                let _ = req.respond(resp);
                continue;
            }
            SecurityCheckResult::AuthRequired => {
                metrics::SECURITY_AUTH_FAILURES_TOTAL
                    .with_label_values(&[route, "missing_or_invalid"])
                    .inc();
                metrics::HTTP_REQUESTS_TOTAL
                    .with_label_values(&[route, "401"])
                    .inc();
                metrics::HTTP_REQUEST_DURATION_SECONDS
                    .with_label_values(&[route])
                    .observe(started.elapsed().as_secs_f64());
                let resp = auth_required_response(&request_id);
                let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
                let _ = req.respond(resp);
                continue;
            }
        }

        // HA write gating (leader_only): block non-leader write requests.
        if ha_blocks_write(method.as_str(), &ha_state) {
            metrics::HTTP_REQUESTS_TOTAL
                .with_label_values(&[route, "503"])
                .inc();
            metrics::HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&[route])
                .observe(started.elapsed().as_secs_f64());
            let resp = not_leader_response(&request_id, ha_state.leader_url());
            let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
            let _ = req.respond(resp);
            continue;
        }

        // Snapshot pause: block write requests while a snapshot is being created.
        if is_write_method(method.as_str()) && write_pause.load(Ordering::Relaxed) {
            metrics::HTTP_REQUESTS_TOTAL
                .with_label_values(&[route, "503"])
                .inc();
            metrics::HTTP_REQUEST_DURATION_SECONDS
                .with_label_values(&[route])
                .observe(started.elapsed().as_secs_f64());
            let resp = error_response(
                503,
                "SNAPSHOT_IN_PROGRESS",
                "snapshot_in_progress",
                &request_id,
            );
            let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
            let _ = req.respond(resp);
            continue;
        }

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
            ("GET", "/ha/status") => {
                let snap = ha_state.snapshot();
                json_response(200, &snap)
            }
            ("GET", "/bootstrap/sources/status") => {
                let list = MirrorHealthStore::open(bootstrap_db_dir.as_str())
                    .ok()
                    .and_then(|s: MirrorHealthStore| s.list().ok())
                    .unwrap_or_default();
                json_response(
                    200,
                    &serde_json::json!({
                        "schema_version": 1,
                        "bootstrap_db_dir": bootstrap_db_dir,
                        "mirrors": list,
                    }),
                )
            }
            ("GET", "/encryption/status") => json_response(200, &encryption_status),
            // OpenAPI (v1): served only under the versioned prefix.
            ("GET", "/openapi.json") if is_versioned => {
                let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                Response::from_string(OPENAPI_SPEC_V1)
                    .with_status_code(200)
                    .with_header(h)
            }
            ("GET", "/recon/pending") => {
                if let Some(store) = recon.as_ref() {
                    let params = parse_query(query);
                    let limit = params
                        .get("limit")
                        .and_then(|x| x.parse::<usize>().ok())
                        .unwrap_or(pagination.default_limit)
                        .min(pagination.max_limit);
                    let cursor = params
                        .get("cursor")
                        .map(String::as_str)
                        .filter(|s| !s.trim().is_empty());
                    let (list, next_cursor) = store
                        .list_pending_page(cursor, limit)
                        .map_err(|e| format!("failed listing recon pending: {e}"))?;
                    json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "pending": list, "next_cursor": next_cursor}),
                    )
                } else {
                    error_response(404, "not_found", "recon_disabled", &request_id)
                }
            }
            ("POST", "/fin/actions") => match read_body_limited(&mut req, limits.max_body_bytes) {
                Ok(body) => {
                    if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                        error_response(400, "bad_request", &msg, &request_id)
                    } else {
                        match serde_json::from_slice::<hub_fin::FinActionRequestV1>(&body) {
                            Ok(req_obj) => {
                                let actor = fin_action_actor(&req_obj);
                                match enforce_actor_rate_limit(&limiter, &actor, &request_id) {
                                    Some(resp) => resp,
                                    None => {
                                        match fin_api.submit_action_obj(req_obj.into_action()) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => api_error_response(e, &request_id),
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error_response(400, "bad_request", &e.to_string(), &request_id)
                            }
                        }
                    }
                }
                Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                Err(BodyReadError::Io(e)) => error_response(
                    500,
                    "internal",
                    &format!("body_read_failed: {e}"),
                    &request_id,
                ),
            },
            ("POST", "/data/datasets") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::RegisterDatasetRequestV1>(
                                &body,
                            ) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.owner.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_register_dataset(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("POST", "/data/licenses") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::IssueLicenseRequestV1>(&body) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.licensor.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_issue_license(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("POST", "/data/attestations") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::AppendAttestationRequestV1>(
                                &body,
                            ) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.attestor.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_append_attestation(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("POST", "/data/listings") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::CreateListingRequestV1>(&body)
                            {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.licensor.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_create_listing(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("POST", "/data/allowlist/licensors") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::AddLicensorRequestV1>(&body) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.actor.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_add_licensor(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("POST", "/data/allowlist/attestors") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<hub_data::AddAttestorRequestV1>(&body) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.actor.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match data_api.submit_add_attestor(req_obj) {
                                            Ok(out) => json_response(200, &out),
                                            Err(e) => data_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") && p.ends_with("/licenses") => {
                let dataset_id = p
                    .trim_start_matches("/data/datasets/")
                    .trim_end_matches("/licenses");
                let params = parse_query(query);
                let limit = params
                    .get("limit")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(pagination.default_limit)
                    .min(pagination.max_limit);
                let cursor = params
                    .get("cursor")
                    .map(String::as_str)
                    .filter(|s| !s.trim().is_empty());
                match data_api.list_licenses_by_dataset_page(dataset_id, cursor, limit) {
                    Ok((list, next_cursor)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "items": list, "next_cursor": next_cursor}),
                    ),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") && p.ends_with("/attestations") => {
                let dataset_id = p
                    .trim_start_matches("/data/datasets/")
                    .trim_end_matches("/attestations");
                let params = parse_query(query);
                let limit = params
                    .get("limit")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(pagination.default_limit)
                    .min(pagination.max_limit);
                let cursor = params
                    .get("cursor")
                    .map(String::as_str)
                    .filter(|s| !s.trim().is_empty());
                match data_api.list_attestations_by_dataset_page(dataset_id, cursor, limit) {
                    Ok((list, next_cursor)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "items": list, "next_cursor": next_cursor}),
                    ),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("GET", "/data/listings") => {
                let params = parse_query(query);
                let dataset_id = params.get("dataset_id").map(String::as_str).unwrap_or("");
                if dataset_id.is_empty() {
                    error_response(400, "bad_request", "missing dataset_id", &request_id)
                } else {
                    match hub_data::Hex32::from_hex(dataset_id) {
                        Ok(did) => {
                            let limit = params
                                .get("limit")
                                .and_then(|x| x.parse::<usize>().ok())
                                .unwrap_or(pagination.default_limit)
                                .min(pagination.max_limit);
                            let cursor = params
                                .get("cursor")
                                .map(String::as_str)
                                .filter(|s| !s.trim().is_empty());
                            match data_api.list_listings_by_dataset_page_typed(did, cursor, limit) {
                                Ok((list, next_cursor)) => {
                                    let v: Vec<serde_json::Value> = list
                                        .into_iter()
                                        .map(|x| serde_json::to_value(x).expect("serde value"))
                                        .collect();
                                    json_response(
                                        200,
                                        &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "items": v, "next_cursor": next_cursor}),
                                    )
                                }
                                Err(e) => data_api_error_response(e, &request_id),
                            }
                        }
                        Err(e) => error_response(
                            400,
                            "bad_request",
                            &format!("invalid dataset_id: {e}"),
                            &request_id,
                        ),
                    }
                }
            }
            ("GET", "/data/entitlements") => {
                let params = parse_query(query);
                let dataset_id = params.get("dataset_id").map(String::as_str).unwrap_or("");
                let licensee = params.get("licensee").map(String::as_str).unwrap_or("");
                let offset = params
                    .get("offset")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(0);
                let limit = params
                    .get("limit")
                    .and_then(|x| x.parse::<usize>().ok())
                    .unwrap_or(pagination.default_limit)
                    .min(pagination.max_limit);
                let cursor = params
                    .get("cursor")
                    .map(String::as_str)
                    .filter(|s| !s.trim().is_empty());
                if !dataset_id.is_empty() && !licensee.is_empty() {
                    error_response(
                        400,
                        "bad_request",
                        "pass dataset_id OR licensee",
                        &request_id,
                    )
                } else if !dataset_id.is_empty() {
                    match hub_data::Hex32::from_hex(dataset_id) {
                        Ok(did) => {
                            if cursor.is_some() {
                                match data_api
                                    .list_entitlements_by_dataset_page_typed(did, cursor, limit)
                                {
                                    Ok((list, next_cursor)) => {
                                        let v: Vec<serde_json::Value> = list
                                            .into_iter()
                                            .map(|ent| entitlement_view_json(&data_api, ent))
                                            .collect();
                                        json_response(
                                            200,
                                            &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "limit": limit, "items": v, "next_cursor": next_cursor}),
                                        )
                                    }
                                    Err(e) => data_api_error_response(e, &request_id),
                                }
                            } else {
                                match data_api.list_entitlements_by_dataset_typed(did) {
                                    Ok(list) => {
                                        let v: Vec<serde_json::Value> = list
                                            .into_iter()
                                            .skip(offset)
                                            .take(limit)
                                            .map(|ent| entitlement_view_json(&data_api, ent))
                                            .collect();
                                        json_response(
                                            200,
                                            &serde_json::json!({"schema_version": 1, "dataset_id": dataset_id, "offset": offset, "limit": limit, "items": v}),
                                        )
                                    }
                                    Err(e) => data_api_error_response(e, &request_id),
                                }
                            }
                        }
                        Err(e) => error_response(
                            400,
                            "bad_request",
                            &format!("invalid dataset_id: {e}"),
                            &request_id,
                        ),
                    }
                } else if !licensee.is_empty() {
                    if cursor.is_some() {
                        match data_api
                            .list_entitlements_by_licensee_page_typed(licensee, cursor, limit)
                        {
                            Ok((list, next_cursor)) => {
                                let v: Vec<serde_json::Value> = list
                                    .into_iter()
                                    .map(|ent| entitlement_view_json(&data_api, ent))
                                    .collect();
                                json_response(
                                    200,
                                    &serde_json::json!({"schema_version": 1, "licensee": licensee, "limit": limit, "items": v, "next_cursor": next_cursor}),
                                )
                            }
                            Err(e) => data_api_error_response(e, &request_id),
                        }
                    } else {
                        match data_api.list_entitlements_by_licensee_typed(licensee) {
                            Ok(list) => {
                                let v: Vec<serde_json::Value> = list
                                    .into_iter()
                                    .skip(offset)
                                    .take(limit)
                                    .map(|ent| entitlement_view_json(&data_api, ent))
                                    .collect();
                                json_response(
                                    200,
                                    &serde_json::json!({"schema_version": 1, "licensee": licensee, "offset": offset, "limit": limit, "items": v}),
                                )
                            }
                            Err(e) => data_api_error_response(e, &request_id),
                        }
                    }
                } else {
                    error_response(
                        400,
                        "bad_request",
                        "missing dataset_id or licensee",
                        &request_id,
                    )
                }
            }
            ("GET", p) if p.starts_with("/data/datasets/") => {
                let dataset_id = p.trim_start_matches("/data/datasets/");
                match data_api.get_dataset(dataset_id) {
                    Ok(Some(ds)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "dataset": ds}),
                    ),
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("GET", p) if p.starts_with("/data/licenses/") => {
                let license_id = p.trim_start_matches("/data/licenses/");
                match data_api.get_license(license_id) {
                    Ok(Some(lic)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "license": lic}),
                    ),
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("GET", p) if p.starts_with("/fin/assets/") => {
                let asset_id = p.trim_start_matches("/fin/assets/");
                match fin_api.get_asset(asset_id) {
                    Ok(Some(asset)) => json_response(
                        200,
                        &serde_json::json!({"schema_version": 1, "asset": asset}),
                    ),
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => api_error_response(e, &request_id),
                }
            }
            ("GET", "/fin/balances") => {
                let params = parse_query(query);
                let asset_id = params.get("asset_id").map(String::as_str).unwrap_or("");
                let account = params.get("account").map(String::as_str).unwrap_or("");
                if asset_id.is_empty() || account.is_empty() {
                    error_response(
                        400,
                        "bad_request",
                        "missing asset_id or account",
                        &request_id,
                    )
                } else {
                    match fin_api.get_balance(asset_id, account) {
                        Ok(amount) => json_response(
                            200,
                            &serde_json::json!({"schema_version": 1, "asset_id": asset_id, "account": account, "amount_scaled_u128": amount}),
                        ),
                        Err(e) => api_error_response(e, &request_id),
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
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => api_error_response(e, &request_id),
                }
            }
            ("GET", p) if p.starts_with("/receipts/fin/") => {
                let action_id = p.trim_start_matches("/receipts/fin/");
                match fin_api.get_receipt(action_id) {
                    Ok(Some(raw)) => {
                        let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                        Response::from_data(raw)
                            .with_status_code(200)
                            .with_header(h)
                    }
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => api_error_response(e, &request_id),
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
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("GET", p) if p.starts_with("/receipts/data/") => {
                let action_id = p.trim_start_matches("/receipts/data/");
                match data_api.get_receipt(action_id) {
                    Ok(Some(raw)) => {
                        let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                        Response::from_data(raw)
                            .with_status_code(200)
                            .with_header(h)
                    }
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => data_api_error_response(e, &request_id),
                }
            }
            ("POST", "/linkage/buy-license") => {
                match read_body_limited(&mut req, limits.max_body_bytes) {
                    Ok(body) => {
                        if let Err(msg) = validate_json_depth(&body, limits.max_json_depth) {
                            error_response(400, "bad_request", &msg, &request_id)
                        } else {
                            match serde_json::from_slice::<BuyLicenseRequestV1>(&body) {
                                Ok(req_obj) => {
                                    match enforce_actor_rate_limit(
                                        &limiter,
                                        &req_obj.buyer_account.0,
                                        &request_id,
                                    ) {
                                        Some(resp) => resp,
                                        None => match linkage_api.buy_license(req_obj) {
                                            Ok(receipt) => json_response(
                                                200,
                                                &serde_json::json!({"schema_version": 1, "receipt": receipt}),
                                            ),
                                            Err(e) => linkage_api_error_response(e, &request_id),
                                        },
                                    }
                                }
                                Err(e) => {
                                    error_response(400, "bad_request", &e.to_string(), &request_id)
                                }
                            }
                        }
                    }
                    Err(BodyReadError::TooLarge) => payload_too_large_response(&request_id),
                    Err(BodyReadError::Io(e)) => error_response(
                        500,
                        "internal",
                        &format!("body_read_failed: {e}"),
                        &request_id,
                    ),
                }
            }
            ("GET", p) if p.starts_with("/linkage/purchase/") => {
                let purchase_id = p.trim_start_matches("/linkage/purchase/");
                match linkage_api.get_purchase_receipt(purchase_id) {
                    Ok(Some(r)) => {
                        json_response(200, &serde_json::json!({"schema_version": 1, "receipt": r}))
                    }
                    Ok(None) => error_response(404, "not_found", "not_found", &request_id),
                    Err(e) => linkage_api_error_response(e, &request_id),
                }
            }
            _ => error_response(404, "not_found", "not_found", &request_id),
        };

        let status = resp.status_code().0.to_string();
        metrics::HTTP_REQUESTS_TOTAL
            .with_label_values(&[route, status.as_str()])
            .inc();
        metrics::HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[route])
            .observe(started.elapsed().as_secs_f64());

        let resp = with_common_headers(resp, &request_id, &_cors, origin.as_deref());
        if let Err(e) = req.respond(resp) {
            warn!(error = %e, "failed writing http response");
        }
    }
    Ok(())
}

struct InflightGuard {
    inflight: Arc<AtomicUsize>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn new_request_id() -> String {
    let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("req-{ms}-{n}")
}

fn header_value(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    for h in req.headers() {
        if h.field.equiv(name) {
            return Some(h.value.as_str().to_string());
        }
    }
    None
}

fn with_common_headers(
    resp: Response<std::io::Cursor<Vec<u8>>>,
    request_id: &str,
    cors: &CorsConfig,
    origin: Option<&str>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp =
        resp.with_header(Header::from_bytes(&b"X-Request-Id"[..], request_id.as_bytes()).unwrap());
    resp = resp
        .with_header(Header::from_bytes(&b"X-Api-Version"[..], API_VERSION.as_bytes()).unwrap());
    resp = resp
        .with_header(Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap());
    if cors.enabled {
        if let Some(origin) = origin {
            if cors.allow_origins.iter().any(|o| o.as_str() == origin) {
                resp = resp.with_header(
                    Header::from_bytes(&b"Access-Control-Allow-Origin"[..], origin.as_bytes())
                        .unwrap(),
                );
                resp = resp.with_header(Header::from_bytes(&b"Vary"[..], &b"Origin"[..]).unwrap());
            }
        }
    }
    resp
}

fn rate_limited_response(
    retry_after_secs: u64,
    request_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let h_ra =
        Header::from_bytes(&b"Retry-After"[..], retry_after_secs.to_string().as_bytes()).unwrap();
    let resp = json_response(
        429,
        &ErrorEnvelope {
            error: ErrorBody {
                code: "rate_limited",
                message: "rate_limited".to_string(),
                request_id,
                leader_url: None,
            },
            retry_after_secs: Some(retry_after_secs),
        },
    );
    resp.with_header(h_ra)
}

fn fin_action_actor(req: &hub_fin::FinActionRequestV1) -> String {
    match req {
        hub_fin::FinActionRequestV1::CreateAssetV1(a) => {
            a.actor.as_ref().unwrap_or(&a.issuer).0.clone()
        }
        hub_fin::FinActionRequestV1::MintUnitsV1(a) => {
            a.actor.as_ref().unwrap_or(&a.to_account).0.clone()
        }
        hub_fin::FinActionRequestV1::TransferUnitsV1(a) => {
            a.actor.as_ref().unwrap_or(&a.from_account).0.clone()
        }
    }
}

fn enforce_actor_rate_limit(
    limiter: &Arc<RateLimiter<SystemTimeSource>>,
    actor: &str,
    request_id: &str,
) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if !limiter.enabled() {
        return None;
    }
    let d = limiter.check_actor(actor);
    if d.allowed {
        None
    } else {
        metrics::RATE_LIMITED_TOTAL
            .with_label_values(&["actor"])
            .inc();
        Some(rate_limited_response(d.retry_after_secs, request_id))
    }
}

#[derive(Debug)]
enum BodyReadError {
    TooLarge,
    Io(std::io::Error),
}

fn read_body_limited(
    req: &mut tiny_http::Request,
    max_bytes: usize,
) -> Result<Vec<u8>, BodyReadError> {
    read_to_end_limited(req.as_reader(), max_bytes).map_err(|e| match e {
        ReadToEndLimitedError::TooLarge => BodyReadError::TooLarge,
        ReadToEndLimitedError::Io(io) => BodyReadError::Io(io),
    })
}

#[derive(Debug)]
enum ReadToEndLimitedError {
    TooLarge,
    Io(std::io::Error),
}

fn read_to_end_limited<R: std::io::Read>(
    mut r: R,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadToEndLimitedError> {
    let mut body = Vec::new();
    let mut limited = (&mut r).take((max_bytes.saturating_add(1)) as u64);
    limited
        .read_to_end(&mut body)
        .map_err(ReadToEndLimitedError::Io)?;
    if body.len() > max_bytes {
        return Err(ReadToEndLimitedError::TooLarge);
    }
    Ok(body)
}

fn payload_too_large_response(request_id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    metrics::PAYLOAD_REJECTED_TOTAL
        .with_label_values(&["body_too_large"])
        .inc();
    error_response(413, "payload_too_large", "payload_too_large", request_id)
}

fn validate_json_depth(body: &[u8], max_depth: usize) -> Result<(), String> {
    if max_depth == 0 {
        return Ok(());
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "invalid_json".to_string())?;
    let depth = json_depth(&v);
    if depth > max_depth {
        return Err(format!("json_too_deep (max_depth={max_depth})"));
    }
    Ok(())
}

fn json_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => 1,
        serde_json::Value::Array(a) => 1 + a.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(m) => 1 + m.values().map(json_depth).max().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_end_limited_rejects_oversize() {
        let max = 10usize;
        let body = vec![b'a'; max + 1];
        let r = std::io::Cursor::new(body);
        let err = read_to_end_limited(r, max).unwrap_err();
        assert!(matches!(err, ReadToEndLimitedError::TooLarge));
    }

    #[test]
    fn payload_too_large_response_is_413() {
        let r = payload_too_large_response("test-req");
        assert_eq!(r.status_code(), 413);
    }

    #[test]
    fn ha_blocks_write_when_follower_in_leader_only_mode() {
        let cfg = crate::config::HaConfig {
            enabled: true,
            write_mode: crate::config::HaWriteMode::LeaderOnly,
            node_id: "node-a".to_string(),
            ..crate::config::HaConfig::default()
        };

        let ha_state = HaState::new(cfg);
        ha_state.set_from_holder(
            false,
            Some(crate::ha::lock_provider::LeaderInfo {
                node_id: "node-b".to_string(),
                expires_at_ms: u64::MAX,
            }),
        );

        assert!(ha_blocks_write("POST", &ha_state));
        let r = not_leader_response("req-1", Some("http://leader:3000".to_string()));
        assert_eq!(r.status_code(), 503);
    }
}

fn json_response<T: Serialize>(code: u16, v: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_data(body)
        .with_status_code(code)
        .with_header(h)
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
    request_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_url: Option<String>,
}

fn sanitize_message(s: &str) -> String {
    let mut out = s.replace(['\n', '\r', '\t'], " ");
    out = out.trim().to_string();
    const MAX: usize = 256;
    if out.len() > MAX {
        out.truncate(MAX);
    }
    out
}

fn error_response(
    http_status: u16,
    code: &'static str,
    message: &str,
    request_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        http_status,
        &ErrorEnvelope {
            error: ErrorBody {
                code,
                message: sanitize_message(message),
                request_id,
                leader_url: None,
            },
            retry_after_secs: None,
        },
    )
}

fn not_leader_response(
    request_id: &str,
    leader_url: Option<String>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        503,
        &ErrorEnvelope {
            error: ErrorBody {
                code: "NOT_LEADER",
                message: "Write requests must go to leader".to_string(),
                request_id,
                leader_url,
            },
            retry_after_secs: None,
        },
    )
}

fn ha_blocks_write(method: &str, ha_state: &HaState) -> bool {
    is_write_method(method)
        && ha_state.enabled()
        && ha_state.write_mode() == crate::config::HaWriteMode::LeaderOnly
        && !ha_state.is_leader()
}

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "DELETE" | "PATCH")
}

fn api_error_response(e: ApiError, request_id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    match e {
        ApiError::BadRequest(msg) => error_response(400, "bad_request", &msg, request_id),
        ApiError::PolicyDenied(p) => error_response(403, "policy_denied", &p.message, request_id),
        ApiError::Upstream(msg) => error_response(502, "upstream", &msg, request_id),
        ApiError::Internal(msg) => error_response(500, "internal", &msg, request_id),
    }
}

fn data_api_error_response(
    e: DataApiError,
    request_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match e {
        DataApiError::BadRequest(msg) => error_response(400, "bad_request", &msg, request_id),
        DataApiError::PolicyDenied(p) => {
            error_response(403, "policy_denied", &p.message, request_id)
        }
        DataApiError::Upstream(msg) => error_response(502, "upstream", &msg, request_id),
        DataApiError::Internal(msg) => error_response(500, "internal", &msg, request_id),
    }
}

fn linkage_api_error_response(
    e: LinkageApiError,
    request_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match e {
        LinkageApiError::BadRequest(msg) => error_response(400, "bad_request", &msg, request_id),
        LinkageApiError::Upstream(msg) => error_response(502, "upstream", &msg, request_id),
        LinkageApiError::Internal(msg) => error_response(500, "internal", &msg, request_id),
    }
}

fn entitlement_view_json(
    data_api: &DataApi,
    ent: hub_data::GrantEntitlementV1,
) -> serde_json::Value {
    // Best-effort enrichment with listing price/currency for query UX.
    let listing = data_api.get_listing_typed(ent.listing_id).ok().flatten();
    let (price_microunits, currency_asset_id) = match listing {
        Some(l) => (
            Some(l.price_microunits.0.to_string()),
            Some(l.currency_asset_id.to_hex()),
        ),
        None => (None, None),
    };

    let data_action_id =
        hub_data::DataEnvelopeV1::new(hub_data::DataActionV1::GrantEntitlementV1(ent.clone()))
            .map(|e| e.action_id.to_hex())
            .unwrap_or_else(|_| "unknown".to_string());

    serde_json::json!({
        "purchase_id": ent.purchase_id.to_hex(),
        "dataset_id": ent.dataset_id.to_hex(),
        "listing_id": ent.listing_id.to_hex(),
        "licensee": ent.licensee.0,
        "price_microunits": price_microunits,
        "currency_asset_id": currency_asset_id,
        "status": "entitled",
        "references": {
            "fin_action_id": ent.payment_ref.fin_action_id.to_hex(),
            "fin_receipt_hash": ent.payment_ref.fin_receipt_hash.to_hex(),
            "data_action_id": data_action_id,
            "license_id": ent.license_id.to_hex(),
        }
    })
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

fn route_label(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("GET", "/healthz") => "GET /healthz",
        ("GET", "/readyz") => "GET /readyz",
        ("GET", "/metrics") => "GET /metrics",
        ("GET", "/openapi.json") => "GET /openapi.json",
        ("GET", "/ha/status") => "GET /ha/status",
        ("GET", "/bootstrap/sources/status") => "GET /bootstrap/sources/status",
        ("GET", "/encryption/status") => "GET /encryption/status",
        ("GET", "/recon/pending") => "GET /recon/pending",
        ("POST", "/fin/actions") => "POST /fin/actions",
        ("POST", "/data/datasets") => "POST /data/datasets",
        ("POST", "/data/licenses") => "POST /data/licenses",
        ("POST", "/data/attestations") => "POST /data/attestations",
        ("POST", "/data/listings") => "POST /data/listings",
        ("POST", "/data/allowlist/licensors") => "POST /data/allowlist/licensors",
        ("POST", "/data/allowlist/attestors") => "POST /data/allowlist/attestors",
        ("GET", "/data/listings") => "GET /data/listings",
        ("GET", "/data/entitlements") => "GET /data/entitlements",
        ("POST", "/linkage/buy-license") => "POST /linkage/buy-license",
        _ => {
            if method == "GET" && path.starts_with("/data/datasets/") && path.ends_with("/licenses")
            {
                "GET /data/datasets/:id/licenses"
            } else if method == "GET"
                && path.starts_with("/data/datasets/")
                && path.ends_with("/attestations")
            {
                "GET /data/datasets/:id/attestations"
            } else if method == "GET" && path.starts_with("/data/datasets/") {
                "GET /data/datasets/:id"
            } else if method == "GET" && path.starts_with("/data/licenses/") {
                "GET /data/licenses/:id"
            } else if method == "GET" && path.starts_with("/fin/assets/") {
                "GET /fin/assets/:id"
            } else if method == "GET" && path.starts_with("/fin/receipts/") {
                "GET /fin/receipts/:action_id"
            } else if method == "GET" && path.starts_with("/receipts/fin/") {
                "GET /receipts/fin/:action_id"
            } else if method == "GET" && path.starts_with("/data/receipts/") {
                "GET /data/receipts/:action_id"
            } else if method == "GET" && path.starts_with("/receipts/data/") {
                "GET /receipts/data/:action_id"
            } else if method == "GET" && path.starts_with("/linkage/purchase/") {
                "GET /linkage/purchase/:purchase_id"
            } else {
                "unknown"
            }
        }
    }
}

/// Strip `/api/v1` prefix from the path, if present.
///
/// This enables `/api/v1/...` routing while keeping legacy (unversioned) paths working.
fn strip_api_v1_prefix(path: &str) -> (&str, bool) {
    const PREFIX: &str = "/api/v1";
    if path == PREFIX {
        return ("/", true);
    }
    if let Some(rest) = path.strip_prefix(PREFIX) {
        if rest.is_empty() {
            return ("/", true);
        }
        if rest.starts_with('/') {
            return (rest, true);
        }
        // Defensive: only treat it as a prefix when it splits on `/`.
        return (path, false);
    }
    (path, false)
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

// ============================================================
// Security mode gating helpers
// ============================================================

/// Check if a route is gated (disabled) in the current security mode.
fn is_route_gated(security: &SecurityConfig, path: &str) -> bool {
    let mode = security.mode;

    // In prod mode, certain devnet-only endpoints are disabled
    if mode == SecurityMode::Prod {
        // M2M topup endpoint (devnet only)
        if path.starts_with("/m2m/topup") {
            return true;
        }
        // M2M ledger ops endpoints (devnet only)
        if path.contains("/ledger") && path.starts_with("/m2m/") {
            return true;
        }
    }

    false
}

/// Check if a route requires admin auth in the current security mode.
fn route_requires_admin_auth(security: &SecurityConfig, path: &str) -> bool {
    let mode = security.mode;

    // In prod mode, sensitive endpoints require auth
    if mode == SecurityMode::Prod {
        // List all proofs requires auth
        if path == "/bridge/proofs" || path.starts_with("/bridge/proofs?") {
            return true;
        }
        // Eth header submission requires auth
        if path.starts_with("/bridge/headers") {
            return true;
        }
    }

    // In staging mode, eth headers require auth
    if mode == SecurityMode::Staging && path.starts_with("/bridge/headers") {
        return true;
    }

    false
}

/// Extract admin token from request headers.
fn extract_admin_token(req: &tiny_http::Request) -> Option<String> {
    // Check X-Admin-Token header
    for h in req.headers() {
        if h.field.equiv("X-Admin-Token") {
            return Some(h.value.as_str().to_string());
        }
        // Also support Authorization: Bearer <token>
        if h.field.equiv("Authorization") {
            let v = h.value.as_str();
            if let Some(token) = v.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Security check result.
enum SecurityCheckResult {
    /// Request is allowed to proceed.
    Allowed,
    /// Route is disabled in this security mode.
    RouteDisabled,
    /// Auth required but not provided or invalid.
    AuthRequired,
}

/// Perform security checks on a request.
fn check_security(
    security: &SecurityConfig,
    req: &tiny_http::Request,
    path: &str,
) -> SecurityCheckResult {
    // Check if route is gated
    if is_route_gated(security, path) {
        return SecurityCheckResult::RouteDisabled;
    }

    // Check if route requires admin auth
    if route_requires_admin_auth(security, path) {
        if let Some(token) = extract_admin_token(req) {
            if security.verify_admin_token(&token) {
                return SecurityCheckResult::Allowed;
            }
        }
        return SecurityCheckResult::AuthRequired;
    }

    SecurityCheckResult::Allowed
}

fn route_disabled_response(request_id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    error_response(
        404,
        "route_disabled",
        "this endpoint is disabled in the current security mode",
        request_id,
    )
}

fn auth_required_response(request_id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    error_response(
        401,
        "auth_required",
        "authentication required for this endpoint",
        request_id,
    )
}
