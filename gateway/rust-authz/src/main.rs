use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::HashMap, env, fs, sync::Arc};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    shared_secret: String,
    trusted_issuer: String,
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
        trusted_issuer: env::var("TRUSTED_ISSUER").unwrap_or_else(|_| "did:example:issuer".to_string()),
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
    let cred = &req.credential;

    if cred.cred_type != "OwnerCredential" {
        return Err("unsupported_credential_type".to_string());
    }

    if cred.issuer != state.trusted_issuer {
        return Err("issuer_not_trusted".to_string());
    }

    if cred.subject != req.subject {
        return Err("subject_mismatch".to_string());
    }

    if cred.status != "active" {
        return Err("credential_not_active".to_string());
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

    Ok("allowed_by_owner_credential".to_string())
}

fn in_scope(scopes: &[String], requested: &str) -> bool {
    scopes.iter().any(|s| s == "*" || s == requested)
}

fn policy_allows(policy_file: &str, device_id: &str, action: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(policy_file)
        .map_err(|e| format!("policy_file_read_error: {}", e))?;
    let policies: Policies =
        serde_json::from_str(&raw).map_err(|e| format!("policy_file_parse_error: {}", e))?;

    let Some(device_policy) = policies.devices.get(device_id) else {
        return Ok(false);
    };

    Ok(device_policy.allowed_actions.iter().any(|a| a == action))
}

fn is_revoked(revocation_file: &str, credential_id: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(revocation_file)
        .map_err(|e| format!("revocation_file_read_error: {}", e))?;
    let revocations: Revocations =
        serde_json::from_str(&raw).map_err(|e| format!("revocation_file_parse_error: {}", e))?;

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
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        cred.id,
        cred.cred_type,
        cred.issuer,
        cred.subject,
        cred.gateway,
        devices.join(","),
        actions.join(","),
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
