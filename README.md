
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

## How to run it

### 1. Start the authorization service

```bash
cd gateway/rust-authz

AUTHZ_SHARED_SECRET=dev-secret \
TRUSTED_ISSUER=did:example:issuer \
POLICY_FILE=../../testdata/policies/devices.json \
REVOCATION_FILE=../../testdata/revocations/revoked_ids.json \
cargo run
````

### 2. Start the lock simulator

```bash
cd devices/lock-sim
go run .
```

### 3. Start the gateway API

```bash
cd gateway/go-api

AUTHZ_URL=http://localhost:8081/v1/authorize \
LOCK_URL=http://localhost:8090 \
go run .
```

### 4. Start the issuer

```bash
cd issuer/go-issuer

ISSUER_DID=did:example:issuer \
ISSUER_SHARED_SECRET=dev-secret \
SAVE_CREDENTIALS_DIR=../../testdata/credentials \
go run .
```

### 5. Issue an owner credential

```bash
curl -s http://localhost:8082/credentials/owner \
  -H 'Content-Type: application/json' \
  -d '{
    "subject": "did:example:alice",
    "gateway": "gateway-home-1",
    "device_scopes": ["lock-front-door"],
    "action_scopes": ["unlock", "lock"]
  }' > /tmp/alice-owner-credential.json
```

### 6. Request access through the gateway

```bash
curl -s http://localhost:8080/access/request \
  -H 'Content-Type: application/json' \
  -d "{
    \"subject\": \"did:example:alice\",
    \"device_id\": \"lock-front-door\",
    \"action\": \"unlock\",
    \"credential\": $(cat /tmp/alice-owner-credential.json)
  }"
```

### 7. Check the lock state

```bash
curl -s http://localhost:8090/state
```

If everything is working, the gateway should authorize the request and the lock simulator should report the state as `unlocked`.
