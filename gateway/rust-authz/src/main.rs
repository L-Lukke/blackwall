use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::HashMap, env, fs, sync::Arc};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    shared_secret: String,
    trusted_issuer: String,
    gateway_id: String,
    policy_file: String,
    revocation_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
    issuer: String,
    subject: String,
    gateway: String,
    device_scopes: Vec<String>,
    action_scopes: Vec<String>,
    #[serde(default)]
    delegated_by: Option<String>,
    #[serde(default)]
    parent_credential_id: Option<String>,
    #[serde(default)]
    transferred_by: Option<String>,
    #[serde(default)]
    replaces_credential_id: Option<String>,
    issued_at: String,
    expires_at: String,
    status: String,
    proof: Proof,
}

#[derive(Debug, Deserialize)]
struct AuthzRequest {
    subject: String,
    device_id: String,
    action: String,
    credential: Credential,
}

#[derive(Debug, Serialize)]
struct AuthzResponse {
    allow: bool,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Revocations {
    revoked_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Policies {
    devices: HashMap<String, DevicePolicy>,
}

#[derive(Debug, Deserialize)]
struct DevicePolicy {
    allowed_actions: Vec<String>,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        shared_secret: env::var("AUTHZ_SHARED_SECRET").unwrap_or_else(|_| "dev-secret".to_string()),
        trusted_issuer: env::var("TRUSTED_ISSUER")
            .unwrap_or_else(|_| "did:example:issuer".to_string()),
        gateway_id: env::var("GATEWAY_ID").unwrap_or_else(|_| "gateway-home-1".to_string()),
        policy_file: env::var("POLICY_FILE")
            .unwrap_or_else(|_| "../../testdata/policies/devices.json".to_string()),
        revocation_file: env::var("REVOCATION_FILE")
            .unwrap_or_else(|_| "../../testdata/revocations/revoked_ids.json".to_string()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/authorize", post(authorize))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081")
        .await
        .expect("bind failed");

    println!("rust-authz listening on http://0.0.0.0:8081");
    axum::serve(listener, app).await.expect("server failed");
}

async fn health() -> Json<AuthzResponse> {
    Json(AuthzResponse {
        allow: true,
        reason: "ok".to_string(),
    })
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthzRequest>,
) -> Json<AuthzResponse> {
    match evaluate(&state, &req) {
        Ok(reason) => Json(AuthzResponse {
            allow: true,
            reason,
        }),
        Err(reason) => Json(AuthzResponse {
            allow: false,
            reason,
        }),
    }
}

fn evaluate(state: &AppState, req: &AuthzRequest) -> Result<String, String> {
    validate_common(state, req)?;

    match req.credential.cred_type.as_str() {
        "OwnerCredential" => authorize_owner(req),
        "DelegationCredential" => authorize_delegation(req),
        _ => Err("unsupported_credential_type".to_string()),
    }
}

fn validate_common(state: &AppState, req: &AuthzRequest) -> Result<(), String> {
    let cred = &req.credential;

    if cred.issuer != state.trusted_issuer {
        return Err("issuer_not_trusted".to_string());
    }
    if cred.subject != req.subject {
        return Err("subject_mismatch".to_string());
    }
    if cred.status != "active" {
        return Err("credential_not_active".to_string());
    }
    if cred.gateway != state.gateway_id {
        return Err("credential_for_different_gateway".to_string());
    }
    if is_expired(&cred.expires_at)? {
        return Err("credential_expired".to_string());
    }
    if is_revoked(&state.revocation_file, &cred.id)? {
        return Err("credential_revoked".to_string());
    }
    if !verify_signature(&state.shared_secret, cred) {
        return Err("bad_signature".to_string());
    }
    if !in_scope(&cred.device_scopes, &req.device_id) {
        return Err("device_out_of_scope".to_string());
    }
    if !in_scope(&cred.action_scopes, &req.action) {
        return Err("action_out_of_scope".to_string());
    }
    if !policy_allows(&state.policy_file, &req.device_id, &req.action)? {
        return Err("denied_by_local_policy".to_string());
    }

    Ok(())
}

fn authorize_owner(req: &AuthzRequest) -> Result<String, String> {
    let cred = &req.credential;

    let has_transfer_lineage =
        cred.transferred_by.as_deref().filter(|v| !v.is_empty()).is_some()
        && cred.replaces_credential_id.as_deref().filter(|v| !v.is_empty()).is_some();

    if has_transfer_lineage {
        Ok("allowed_by_transferred_owner_credential".to_string())
    } else {
        Ok("allowed_by_owner_credential".to_string())
    }
}

fn authorize_delegation(req: &AuthzRequest) -> Result<String, String> {
    let cred = &req.credential;

    let delegated_by = cred
        .delegated_by
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing_delegated_by".to_string())?;

    let parent_credential_id = cred
        .parent_credential_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing_parent_credential_id".to_string())?;

    if delegated_by == cred.subject {
        return Err("self_delegation_not_allowed".to_string());
    }

    if parent_credential_id == cred.id {
        return Err("invalid_parent_credential_id".to_string());
    }

    Ok("allowed_by_delegation_credential".to_string())
}

fn is_expired(expires_at: &str) -> Result<bool, String> {
    let expiry = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|e| format!("bad_expiry_format: {}", e))?
        .with_timezone(&Utc);

    Ok(Utc::now() >= expiry)
}

fn in_scope(scopes: &[String], requested: &str) -> bool {
    scopes.iter().any(|s| s == "*" || s == requested)
}

fn policy_allows(policy_file: &str, device_id: &str, action: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(policy_file)
        .map_err(|e| format!("policy_file_read_error: {}", e))?;
    let policies: Policies = serde_json::from_str(&raw)
        .map_err(|e| format!("policy_file_parse_error: {}", e))?;

    let Some(device_policy) = policies.devices.get(device_id) else {
        return Ok(false);
    };

    Ok(device_policy.allowed_actions.iter().any(|a| a == action))
}

fn is_revoked(revocation_file: &str, credential_id: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(revocation_file)
        .map_err(|e| format!("revocation_file_read_error: {}", e))?;
    let revocations: Revocations = serde_json::from_str(&raw)
        .map_err(|e| format!("revocation_file_parse_error: {}", e))?;

    Ok(revocations.revoked_ids.iter().any(|id| id == credential_id))
}

fn verify_signature(secret: &str, cred: &Credential) -> bool {
    let expected = sign(secret, &signing_input(cred));
    expected == cred.proof.value
}

fn signing_input(cred: &Credential) -> String {
    let mut devices = cred.device_scopes.clone();
    let mut actions = cred.action_scopes.clone();
    devices.sort();
    actions.sort();

    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        cred.id,
        cred.cred_type,
        cred.issuer,
        cred.subject,
        cred.gateway,
        devices.join(","),
        actions.join(","),
        cred.delegated_by.clone().unwrap_or_default(),
        cred.parent_credential_id.clone().unwrap_or_default(),
        cred.transferred_by.clone().unwrap_or_default(),
        cred.replaces_credential_id.clone().unwrap_or_default(),
        cred.issued_at,
        cred.expires_at,
        cred.status
    )
}

fn sign(secret: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(data.as_bytes());
    let out = mac.finalize().into_bytes();
    hex::encode(out)
}