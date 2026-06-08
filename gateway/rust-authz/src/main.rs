use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, sync::Arc};

#[derive(Clone)]
struct AppState {
    trusted_issuer: String,
    gateway_id: String,
    policy_file: String,
    revocation_file: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialStatus {
    id: String,
    #[serde(rename = "type")]
    status_type: String,
    #[serde(rename = "statusPurpose")]
    status_purpose: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct AuthzRequest {
    subject: String,
    device_id: String,
    action: String,
    #[serde(default)]
    credential: Credential,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    presentation: Option<VerifiablePresentation>,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            context: vec![],
            id: String::new(),
            cred_type: vec![],
            issuer: String::new(),
            valid_from: String::new(),
            valid_until: String::new(),
            credential_subject: CredentialSubject::default(),
            credential_status: CredentialStatus::default(),
            proof: None,
        }
    }
}

impl Default for CredentialSubject {
    fn default() -> Self {
        Self {
            id: String::new(),
            gateway: String::new(),
            device_scopes: vec![],
            action_scopes: vec![],
            delegated_by: None,
            parent_credential_id: None,
            transferred_by: None,
            replaces_credential_id: None,
        }
    }
}

impl Default for CredentialStatus {
    fn default() -> Self {
        Self {
            id: String::new(),
            status_type: String::new(),
            status_purpose: String::new(),
            status: String::new(),
        }
    }
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
        trusted_issuer: env::var("TRUSTED_ISSUER").unwrap_or_else(|_| {
            "did:key:z6MkqPsfMdhSg1HSGhoxJG9Pm16yEYZ7oGMJm6QVALhqM3m2".to_string()
        }),
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
    let resolved = resolve_request_credential(state, req)?;
    let req = AuthzRequest {
        subject: req.subject.clone(),
        device_id: req.device_id.clone(),
        action: req.action.clone(),
        credential: resolved,
        challenge: req.challenge.clone(),
        presentation: req.presentation.clone(),
    };

    validate_common(state, &req)?;

    if has_type(&req.credential, "OwnerCredential") {
        authorize_owner(&req)
    } else if has_type(&req.credential, "DelegationCredential") {
        authorize_delegation(&req)
    } else {
        Err("unsupported_credential_type".to_string())
    }
}

fn resolve_request_credential(state: &AppState, req: &AuthzRequest) -> Result<Credential, String> {
    if let Some(presentation) = &req.presentation {
        return verify_presentation(state, req, presentation);
    }

    if req.credential.id.is_empty() {
        return Err("credential_or_presentation_required".to_string());
    }

    Ok(req.credential.clone())
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

    let key = resolve_did_key(&presentation.holder)?;
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

fn validate_common(state: &AppState, req: &AuthzRequest) -> Result<(), String> {
    let cred = &req.credential;

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
    if is_revoked(&state.revocation_file, &cred.id)? {
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

fn authorize_owner(req: &AuthzRequest) -> Result<String, String> {
    let cred = &req.credential;

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

fn authorize_delegation(req: &AuthzRequest) -> Result<String, String> {
    let cred = &req.credential;

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

fn is_revoked(revocation_file: &str, credential_id: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(revocation_file)
        .map_err(|e| format!("revocation_file_read_error: {}", e))?;
    let revocations: Revocations =
        serde_json::from_str(&raw).map_err(|e| format!("revocation_file_parse_error: {}", e))?;

    Ok(revocations.revoked_ids.iter().any(|id| id == credential_id))
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

    let Ok(verifying_key) = resolve_did_key(&cred.issuer) else {
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

fn resolve_did_key(did: &str) -> Result<VerifyingKey, String> {
    let Some(encoded) = did.strip_prefix("did:key:z") else {
        return Err("unsupported_did_method".to_string());
    };

    let decoded = base58_decode(encoded)?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err("unsupported_did_key_multicodec".to_string());
    }

    let public_key_array =
        <[u8; 32]>::try_from(&decoded[2..34]).map_err(|_| "bad_did_key_length".to_string())?;
    VerifyingKey::from_bytes(&public_key_array).map_err(|_| "bad_did_key".to_string())
}

fn base58_decode(input: &str) -> Result<Vec<u8>, String> {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = vec![0];

    for ch in input.bytes() {
        let Some(mut carry) = alphabet.iter().position(|&c| c == ch).map(|p| p as u32) else {
            return Err("bad_base58_character".to_string());
        };

        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }

        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    for ch in input.bytes() {
        if ch == b'1' {
            bytes.insert(0, 0);
        } else {
            break;
        }
    }

    Ok(bytes)
}

fn has_type(cred: &Credential, kind: &str) -> bool {
    cred.cred_type.iter().any(|t| t == kind)
}
