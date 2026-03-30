
# SSI Smart Home Gateway PoC

## What this project is

This repository contains a **software-only proof of concept (PoC)** for a **gateway-based smart home architecture** that uses **Self-Sovereign Identity (SSI)** concepts to improve **user sovereignty** over device access and household data.

The PoC is designed around four main components:

- **Gateway API (Go):** receives access requests and mediates communication with devices
- **Authorization service (Rust):** evaluates credentials, revocation state, and local policy to return allow/deny decisions
- **Issuer service (Go):** issues authorization credentials for users
- **Device simulators:** emulate smart home devices such as locks, lights, and sensors

The main architectural goal is to demonstrate that **smart devices do not need to implement SSI directly**. Instead, a **locally controlled gateway** handles identity and authorization logic on their behalf.

---

## Implemented / To be implemented

### Already implemented

- Initial PoC architecture and service split
- First end-to-end vertical slice for **owner control**
- Initial **owner credential issuance** endpoint in the issuer
- Initial **authorization** endpoint in the Rust authz service
- Initial **gateway access request** endpoint
- First device simulator (**lock-sim**) and gateway-mediated lock control

### To be implemented

- **Delegation** credential support and delegated access flows
- **Revocation** support and revocation-aware authorization
- **Ownership transfer** flows
- Additional device simulators and adapters (**light**, **sensor**)
- Data-flow mediation/redirection for compatible devices
- More complete SSI alignment for the credential model
- Local policy management and richer household rules
- Audit logging and authorization traceability
- Scenario runners for all evaluation scenarios
- Integration tests, scenario tests, and performance measurements
- ADRs, API documentation, scripts, and CI workflows

---

## Testing

Start each service in a separate terminal.

### 1) Start the authorization service
```bash
cd gateway/rust-authz

AUTHZ_SHARED_SECRET=dev-secret \
TRUSTED_ISSUER=did:example:issuer \
GATEWAY_ID=gateway-home-1 \
POLICY_FILE=../../testdata/policies/devices.json \
REVOCATION_FILE=../../testdata/revocations/revoked_ids.json \
cargo run
````

### 2) Start the lock simulator

```bash
cd devices/lock-sim
go run .
```

### 3) Start the gateway API

```bash
cd gateway/go-api

AUTHZ_URL=http://localhost:8081/v1/authorize \
LOCK_URL=http://localhost:8090 \
go run .
```

### 4) Start the issuer

```bash
cd issuer/go-issuer

ISSUER_DID=did:example:issuer \
ISSUER_SHARED_SECRET=dev-secret \
SAVE_CREDENTIALS_DIR=../../testdata/credentials \
go run .
```

### 5) Issue an owner credential

```bash
curl -s http://localhost:8082/credentials/owner \
  -H 'Content-Type: application/json' \
  -d '{
    "subject": "did:example:alice",
    "gateway": "gateway-home-1",
    "device_scopes": ["lock-front-door"],
    "action_scopes": ["unlock", "lock"]
  }' > /tmp/alice-owner.json
```

### 6) Issue a delegation credential

```bash
curl -s http://localhost:8082/credentials/delegation \
  -H 'Content-Type: application/json' \
  -d "{
    \"delegated_by\": \"did:example:alice\",
    \"subject\": \"did:example:bob\",
    \"gateway\": \"gateway-home-1\",
    \"device_scopes\": [\"lock-front-door\"],
    \"action_scopes\": [\"unlock\"],
    \"ttl_minutes\": 120,
    \"owner_credential\": $(cat /tmp/alice-owner.json)
  }" > /tmp/bob-delegation.json
```

### 7) Test allowed access

```bash
curl -s http://localhost:8080/access/request \
  -H 'Content-Type: application/json' \
  -d "{
    \"subject\": \"did:example:bob\",
    \"device_id\": \"lock-front-door\",
    \"action\": \"unlock\",
    \"credential\": $(cat /tmp/bob-delegation.json)
  }"
```

Expected: `allowed: true` with reason `allowed_by_delegation_credential`.

### 8) Test denied access

```bash
curl -s http://localhost:8080/access/request \
  -H 'Content-Type: application/json' \
  -d "{
    \"subject\": \"did:example:bob\",
    \"device_id\": \"lock-front-door\",
    \"action\": \"lock\",
    \"credential\": $(cat /tmp/bob-delegation.json)
  }"
```

Expected: `allowed: false` with reason `action_out_of_scope`.

### 9) Optional revocation test

Set `testdata/revocations/revoked_ids.json` to:

```json
{
  "revoked_ids": ["<bob-credential-id>"]
}
```

Then retry step 7. Expected: `allowed: false` with reason `credential_revoked`.

````

Also make sure `testdata/revocations/revoked_ids.json` starts as:

```json
{
  "revoked_ids": []
}
````

If everything is working, the gateway should authorize the request and the lock simulator should report the state as `unlocked`.
