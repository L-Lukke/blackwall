mod did;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use did::DidKeyResolver;
use ed25519_dalek::{Signature, Verifier};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, sync::Arc};

#[derive(Clone)]
struct AppState {
    trusted_issuer: String,
    gateway_id: String,
    policy_file: String,
    issuer_db_path: String,
    service_auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    cryptosuite: String,
    created: String,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    #[serde(rename = "proofValue")]
    proof_value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Credential {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    cred_type: Vec<String>,
    issuer: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "validUntil")]
    valid_until: String,
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject,
    #[serde(rename = "credentialStatus")]
    credential_status: CredentialStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CredentialSubject {
    id: String,
    gateway: String,
    #[serde(rename = "deviceScopes")]
    device_scopes: Vec<String>,
    #[serde(rename = "actionScopes")]
    action_scopes: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "delegatedBy"
    )]
    delegated_by: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "parentCredentialId"
    )]
    parent_credential_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "transferredBy"
    )]
    transferred_by: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "replacesCredentialId"
    )]
    replaces_credential_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CredentialStatus {
    id: String,
    #[serde(rename = "type")]
    status_type: String,
    #[serde(rename = "statusPurpose")]
    status_purpose: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzRequest {
    subject: String,
    device_id: String,
    action: String,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    presentation: Option<VerifiablePresentation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifiablePresentation {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    pres_type: Vec<String>,
    holder: String,
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<Credential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<PresentationProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresentationProof {
    #[serde(rename = "type")]
    proof_type: String,
    cryptosuite: String,
    created: String,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    challenge: String,
    domain: String,
    #[serde(rename = "proofValue")]
    proof_value: String,
}

#[derive(Debug, Serialize)]
struct AuthzResponse {
    allow: bool,
    reason: String,
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
        trusted_issuer: required_env("TRUSTED_ISSUER"),
        gateway_id: env::var("GATEWAY_ID").unwrap_or_else(|_| "gateway-home-1".to_string()),
        policy_file: env::var("POLICY_FILE")
            .unwrap_or_else(|_| "../../configs/policies/devices.json".to_string()),
        issuer_db_path: env::var("ISSUER_DB_PATH")
            .unwrap_or_else(|_| "../../runtime/issuer/issuer.db".to_string()),
        service_auth_token: required_env("SERVICE_AUTH_TOKEN"),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/authorize", post(authorize))
        .with_state(state);

    let addr = env::var("AUTHZ_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind failed");

    println!("rust-authz listening on http://{}", addr);
    axum::serve(listener, app).await.expect("server failed");
}

async fn health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<AuthzResponse>) {
    if let Err(resp) = authenticate(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(resp));
    }
    (
        StatusCode::OK,
        Json(AuthzResponse {
            allow: true,
            reason: "ok".to_string(),
        }),
    )
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AuthzRequest>,
) -> (StatusCode, Json<AuthzResponse>) {
    if let Err(resp) = authenticate(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(resp));
    }
    match evaluate(&state, &req) {
        Ok(reason) => (
            StatusCode::OK,
            Json(AuthzResponse {
                allow: true,
                reason,
            }),
        ),
        Err(reason) => (
            StatusCode::OK,
            Json(AuthzResponse {
                allow: false,
                reason,
            }),
        ),
    }
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), AuthzResponse> {
    match headers
        .get("x-blackwall-service-token")
        .and_then(|v| v.to_str().ok())
    {
        Some(token) if token == state.service_auth_token => Ok(()),
        _ => Err(AuthzResponse {
            allow: false,
            reason: "service_auth_required".to_string(),
        }),
    }
}

fn evaluate(state: &AppState, req: &AuthzRequest) -> Result<String, String> {
    let resolved = resolve_request_credential(state, req)?;

    validate_common(state, req, &resolved)?;

    if has_type(&resolved, "OwnerCredential") {
        authorize_owner(&resolved)
    } else if has_type(&resolved, "DelegationCredential") {
        authorize_delegation(&resolved)
    } else {
        Err("unsupported_credential_type".to_string())
    }
}

fn resolve_request_credential(state: &AppState, req: &AuthzRequest) -> Result<Credential, String> {
    if let Some(presentation) = &req.presentation {
        return verify_presentation(state, req, presentation);
    }

    Err("presentation_required".to_string())
}

fn verify_presentation(
    state: &AppState,
    req: &AuthzRequest,
    presentation: &VerifiablePresentation,
) -> Result<Credential, String> {
    if !presentation
        .pres_type
        .iter()
        .any(|t| t == "VerifiablePresentation")
    {
        return Err("not_a_verifiable_presentation".to_string());
    }
    if presentation.holder != req.subject {
        return Err("presentation_holder_mismatch".to_string());
    }
    if presentation.verifiable_credential.len() != 1 {
        return Err("presentation_must_contain_one_credential".to_string());
    }

    let Some(proof) = &presentation.proof else {
        return Err("presentation_proof_missing".to_string());
    };
    let Some(challenge) = &req.challenge else {
        return Err("presentation_challenge_required".to_string());
    };
    if proof.challenge != *challenge {
        return Err("presentation_challenge_mismatch".to_string());
    }
    if proof.domain != state.gateway_id {
        return Err("presentation_domain_mismatch".to_string());
    }
    if proof.proof_type != "DataIntegrityProof"
        || proof.cryptosuite != "eddsa-rdfc-2022"
        || proof.proof_purpose != "authentication"
    {
        return Err("unsupported_presentation_proof".to_string());
    }
    if !proof
        .verification_method
        .starts_with(&(presentation.holder.clone() + "#"))
    {
        return Err("presentation_verification_method_mismatch".to_string());
    }

    let resolver = DidKeyResolver;
    let key =
        resolver.resolve_verification_key(&presentation.holder, &proof.verification_method)?;
    let signature = decode_signature(&proof.proof_value)?;
    if key
        .verify(
            presentation_signing_input(presentation).as_bytes(),
            &signature,
        )
        .is_err()
    {
        return Err("bad_presentation_signature".to_string());
    }

    let credential = presentation.verifiable_credential[0].clone();
    if credential.credential_subject.id != presentation.holder {
        return Err("presentation_credential_subject_mismatch".to_string());
    }

    Ok(credential)
}

fn validate_common(state: &AppState, req: &AuthzRequest, cred: &Credential) -> Result<(), String> {
    if cred.issuer != state.trusted_issuer {
        return Err("issuer_not_trusted".to_string());
    }
    if !has_type(cred, "VerifiableCredential") {
        return Err("not_a_verifiable_credential".to_string());
    }
    if !cred
        .context
        .iter()
        .any(|c| c == "https://www.w3.org/ns/credentials/v2")
    {
        return Err("missing_vc_context".to_string());
    }
    if cred.credential_subject.id != req.subject {
        return Err("subject_mismatch".to_string());
    }
    if cred.credential_status.status != "active" {
        return Err("credential_not_active".to_string());
    }
    if cred.credential_status.status_purpose != "revocation" {
        return Err("unsupported_credential_status".to_string());
    }
    if cred.credential_subject.gateway != state.gateway_id {
        return Err("credential_for_different_gateway".to_string());
    }
    if is_not_yet_valid(&cred.valid_from)? {
        return Err("credential_not_yet_valid".to_string());
    }
    if is_expired(&cred.valid_until)? {
        return Err("credential_expired".to_string());
    }
    if is_revoked(&state.issuer_db_path, &cred.id)? {
        return Err("credential_revoked".to_string());
    }
    if !verify_credential_signature(cred) {
        return Err("bad_signature".to_string());
    }
    if !in_scope(&cred.credential_subject.device_scopes, &req.device_id) {
        return Err("device_out_of_scope".to_string());
    }
    if !in_scope(&cred.credential_subject.action_scopes, &req.action) {
        return Err("action_out_of_scope".to_string());
    }
    if !policy_allows(&state.policy_file, &req.device_id, &req.action)? {
        return Err("denied_by_local_policy".to_string());
    }

    Ok(())
}

fn authorize_owner(cred: &Credential) -> Result<String, String> {
    let has_transfer_lineage = cred
        .credential_subject
        .transferred_by
        .as_deref()
        .filter(|v| !v.is_empty())
        .is_some()
        && cred
            .credential_subject
            .replaces_credential_id
            .as_deref()
            .filter(|v| !v.is_empty())
            .is_some();

    if has_transfer_lineage {
        Ok("allowed_by_transferred_owner_credential".to_string())
    } else {
        Ok("allowed_by_owner_credential".to_string())
    }
}

fn authorize_delegation(cred: &Credential) -> Result<String, String> {
    let delegated_by = cred
        .credential_subject
        .delegated_by
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing_delegated_by".to_string())?;

    let parent_credential_id = cred
        .credential_subject
        .parent_credential_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing_parent_credential_id".to_string())?;

    if delegated_by == cred.credential_subject.id {
        return Err("self_delegation_not_allowed".to_string());
    }

    if parent_credential_id == cred.id {
        return Err("invalid_parent_credential_id".to_string());
    }

    Ok("allowed_by_delegation_credential".to_string())
}

fn is_not_yet_valid(valid_from: &str) -> Result<bool, String> {
    let start = DateTime::parse_from_rfc3339(valid_from)
        .map_err(|e| format!("bad_valid_from_format: {}", e))?
        .with_timezone(&Utc);

    Ok(Utc::now() < start)
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
    let raw =
        fs::read_to_string(policy_file).map_err(|e| format!("policy_file_read_error: {}", e))?;
    let policies: Policies =
        serde_json::from_str(&raw).map_err(|e| format!("policy_file_parse_error: {}", e))?;

    let Some(device_policy) = policies.devices.get(device_id) else {
        return Ok(false);
    };

    Ok(device_policy.allowed_actions.iter().any(|a| a == action))
}

fn is_revoked(issuer_db_path: &str, credential_id: &str) -> Result<bool, String> {
    let conn =
        Connection::open(issuer_db_path).map_err(|e| format!("issuer_db_open_error: {}", e))?;
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM revocations WHERE credential_id = ?1",
            [credential_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("issuer_db_revocation_query_error: {}", e))?;

    Ok(found.is_some())
}

fn verify_credential_signature(cred: &Credential) -> bool {
    let Some(proof) = &cred.proof else {
        return false;
    };
    if proof.proof_type != "DataIntegrityProof"
        || proof.cryptosuite != "eddsa-rdfc-2022"
        || proof.proof_purpose != "assertionMethod"
    {
        return false;
    }

    if !proof
        .verification_method
        .starts_with(&(cred.issuer.clone() + "#"))
    {
        return false;
    }

    let resolver = DidKeyResolver;
    let Ok(verifying_key) =
        resolver.resolve_verification_key(&cred.issuer, &proof.verification_method)
    else {
        return false;
    };

    let Ok(signature) = decode_signature(&proof.proof_value) else {
        return false;
    };

    verifying_key
        .verify(signing_input(cred).as_bytes(), &signature)
        .is_ok()
}

fn decode_signature(proof_value: &str) -> Result<Signature, String> {
    let signature_bytes = hex::decode(proof_value).map_err(|_| "bad_signature_hex".to_string())?;
    let signature_array = <[u8; 64]>::try_from(signature_bytes.as_slice())
        .map_err(|_| "bad_signature_length".to_string())?;
    Ok(Signature::from_bytes(&signature_array))
}

fn signing_input(cred: &Credential) -> String {
    let mut unsigned = cred.clone();
    unsigned.proof = None;
    serde_json::to_string(&unsigned).unwrap_or_default()
}

fn presentation_signing_input(presentation: &VerifiablePresentation) -> String {
    let mut unsigned = presentation.clone();
    unsigned.proof = None;
    serde_json::to_string(&unsigned).unwrap_or_default()
}

fn has_type(cred: &Credential, kind: &str) -> bool {
    cred.cred_type.iter().any(|t| t == kind)
}

fn required_env(key: &str) -> String {
    env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| panic!("{} must be set", key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::path::PathBuf;

    const DEVICE_ID: &str = "lock-front-door";
    const ACTION: &str = "unlock";
    const GATEWAY_ID: &str = "gateway-home-1";

    #[test]
    fn denies_bad_credential_signature() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&[ACTION], &[]);
        let mut cred = signed_owner_credential(&issuer_key, &issuer_did, &holder_did);
        cred.proof.as_mut().unwrap().proof_value = "00".repeat(64);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "bad_signature");
    }

    #[test]
    fn denies_expired_credential() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&[ACTION], &[]);
        let mut cred = unsigned_owner_credential(&issuer_did, &holder_did);
        cred.valid_from = (Utc::now() - chrono::Duration::minutes(20)).to_rfc3339();
        cred.valid_until = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        sign_credential(&mut cred, &issuer_key, &issuer_did);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "credential_expired");
    }

    #[test]
    fn denies_revoked_credential() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) =
            fixture(&[ACTION], &["urn:uuid:test-credential"]);
        let cred = signed_owner_credential(&issuer_key, &issuer_did, &holder_did);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "credential_revoked");
    }

    #[test]
    fn denies_device_scope_mismatch() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&[ACTION], &[]);
        let mut cred = unsigned_owner_credential(&issuer_did, &holder_did);
        cred.credential_subject.device_scopes = vec!["light-living-room".to_string()];
        sign_credential(&mut cred, &issuer_key, &issuer_did);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "device_out_of_scope");
    }

    #[test]
    fn denies_action_scope_mismatch() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&[ACTION], &[]);
        let mut cred = unsigned_owner_credential(&issuer_did, &holder_did);
        cred.credential_subject.action_scopes = vec!["lock".to_string()];
        sign_credential(&mut cred, &issuer_key, &issuer_did);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "action_out_of_scope");
    }

    #[test]
    fn denies_local_policy_mismatch() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&["lock"], &[]);
        let cred = signed_owner_credential(&issuer_key, &issuer_did, &holder_did);

        let req = signed_request(cred, &holder_key, &holder_did, ACTION, "challenge");

        assert_denied(req, &state, "denied_by_local_policy");
    }

    #[test]
    fn denies_presentation_challenge_mismatch() {
        let (state, issuer_key, holder_key, issuer_did, holder_did) = fixture(&[ACTION], &[]);
        let cred = signed_owner_credential(&issuer_key, &issuer_did, &holder_did);
        let mut req = signed_request(cred, &holder_key, &holder_did, ACTION, "proof-challenge");
        req.challenge = Some("request-challenge".to_string());

        assert_denied(req, &state, "presentation_challenge_mismatch");
    }

    fn fixture(
        allowed_policy_actions: &[&str],
        revoked_ids: &[&str],
    ) -> (AppState, SigningKey, SigningKey, String, String) {
        let issuer_key = SigningKey::from_bytes(&[1; 32]);
        let holder_key = SigningKey::from_bytes(&[2; 32]);
        let issuer_did = did_key_from_signing_key(&issuer_key);
        let holder_did = did_key_from_signing_key(&holder_key);
        let policy_file = write_policy(allowed_policy_actions);
        let issuer_db_path = write_issuer_db(revoked_ids);

        (
            AppState {
                trusted_issuer: issuer_did.clone(),
                gateway_id: GATEWAY_ID.to_string(),
                policy_file,
                issuer_db_path,
                service_auth_token: "test-service-token".to_string(),
            },
            issuer_key,
            holder_key,
            issuer_did,
            holder_did,
        )
    }

    fn signed_owner_credential(
        issuer_key: &SigningKey,
        issuer_did: &str,
        holder_did: &str,
    ) -> Credential {
        let mut cred = unsigned_owner_credential(issuer_did, holder_did);
        sign_credential(&mut cred, issuer_key, issuer_did);
        cred
    }

    fn unsigned_owner_credential(issuer_did: &str, holder_did: &str) -> Credential {
        Credential {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://blackwall.local/contexts/smart-home-credential/v1".to_string(),
            ],
            id: "urn:uuid:test-credential".to_string(),
            cred_type: vec![
                "VerifiableCredential".to_string(),
                "OwnerCredential".to_string(),
            ],
            issuer: issuer_did.to_string(),
            valid_from: (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339(),
            valid_until: (Utc::now() + chrono::Duration::minutes(30)).to_rfc3339(),
            credential_subject: CredentialSubject {
                id: holder_did.to_string(),
                gateway: GATEWAY_ID.to_string(),
                device_scopes: vec![DEVICE_ID.to_string()],
                action_scopes: vec![ACTION.to_string()],
                ..CredentialSubject::default()
            },
            credential_status: CredentialStatus {
                id: "urn:uuid:test-credential#status".to_string(),
                status_type: "StatusList2021Entry".to_string(),
                status_purpose: "revocation".to_string(),
                status: "active".to_string(),
            },
            proof: None,
        }
    }

    fn sign_credential(cred: &mut Credential, issuer_key: &SigningKey, issuer_did: &str) {
        let signature = issuer_key.sign(signing_input(cred).as_bytes());
        cred.proof = Some(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-rdfc-2022".to_string(),
            created: Utc::now().to_rfc3339(),
            verification_method: format!("{}#key-1", issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: hex::encode(signature.to_bytes()),
        });
    }

    fn signed_request(
        cred: Credential,
        holder_key: &SigningKey,
        holder_did: &str,
        action: &str,
        challenge: &str,
    ) -> AuthzRequest {
        let mut presentation = VerifiablePresentation {
            context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
            id: "urn:uuid:test-presentation".to_string(),
            pres_type: vec!["VerifiablePresentation".to_string()],
            holder: holder_did.to_string(),
            verifiable_credential: vec![cred],
            proof: None,
        };
        let signature = holder_key.sign(presentation_signing_input(&presentation).as_bytes());
        presentation.proof = Some(PresentationProof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-rdfc-2022".to_string(),
            created: Utc::now().to_rfc3339(),
            verification_method: format!("{}#key-1", holder_did),
            proof_purpose: "authentication".to_string(),
            challenge: challenge.to_string(),
            domain: GATEWAY_ID.to_string(),
            proof_value: hex::encode(signature.to_bytes()),
        });

        AuthzRequest {
            subject: holder_did.to_string(),
            device_id: DEVICE_ID.to_string(),
            action: action.to_string(),
            challenge: Some(challenge.to_string()),
            presentation: Some(presentation),
        }
    }

    fn assert_denied(req: AuthzRequest, state: &AppState, reason: &str) {
        assert_eq!(evaluate(state, &req), Err(reason.to_string()));
    }

    fn write_policy(allowed_actions: &[&str]) -> String {
        let path = temp_path("policy", "json");
        let actions = allowed_actions
            .iter()
            .map(|action| format!(r#""{}""#, action))
            .collect::<Vec<_>>()
            .join(",");
        fs::write(
            &path,
            format!(
                r#"{{"devices":{{"{}":{{"allowed_actions":[{}]}}}}}}"#,
                DEVICE_ID, actions
            ),
        )
        .unwrap();
        path.to_string_lossy().into_owned()
    }

    fn write_issuer_db(revoked_ids: &[&str]) -> String {
        let path = temp_path("issuer", "db");
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE revocations (credential_id TEXT PRIMARY KEY)",
            [],
        )
        .unwrap();
        for id in revoked_ids {
            conn.execute("INSERT INTO revocations (credential_id) VALUES (?1)", [id])
                .unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    fn temp_path(label: &str, ext: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "blackwall-authz-{}-{}-{}.{}",
            label,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap(),
            ext
        ))
    }

    fn did_key_from_signing_key(key: &SigningKey) -> String {
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(key.verifying_key().as_bytes());
        format!("did:key:z{}", base58_encode(&prefixed))
    }

    fn base58_encode(raw: &[u8]) -> String {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if raw.is_empty() {
            return String::new();
        }

        let mut digits = vec![0u8];
        for byte in raw {
            let mut carry = *byte as u32;
            for digit in digits.iter_mut().rev() {
                carry += (*digit as u32) << 8;
                *digit = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.insert(0, (carry % 58) as u8);
                carry /= 58;
            }
        }

        for byte in raw {
            if *byte == 0 {
                digits.insert(0, 0);
            } else {
                break;
            }
        }

        digits
            .iter()
            .map(|digit| ALPHABET[*digit as usize] as char)
            .collect()
    }
}
