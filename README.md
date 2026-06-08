
# SSI Smart Home Gateway PoC

## What this project is

This repository contains a **software-only proof of concept (PoC)** for a **gateway-based smart home architecture** that uses **Self-Sovereign Identity (SSI)** concepts to improve **user sovereignty** over device access and household data.

The PoC is designed around five main components:

- **Gateway API (Go):** receives access requests and mediates communication with devices
- **Authorization service (Rust):** evaluates credentials, revocation state, and local policy to return allow/deny decisions
- **Issuer service (Go):** issues authorization credentials for users
- **Holder wallet service (Go):** owns a holder `did:key`, stores credentials, and signs verifiable presentations
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
- **Delegation** credential support and delegated access flows
- **Revocation** support and revocation-aware authorization
- **Ownership transfer** flows
- Additional device simulators and adapters (**light**, **sensor**)
- Data-flow mediation/redirection for compatible devices
- Audit logging and authorization traceability
- Scenario runners for all evaluation scenarios
- VC-shaped SSI credentials with DID issuers, holder subjects, credential status, and Ed25519 Data Integrity proofs
- `did:key` resolution for issuer and holder verification keys
- Holder wallet and challenge-bound verifiable presentation flow

### To be implemented

- Local policy management and richer household rules
- Integration tests, scenario tests, and performance measurements
- ADRs, API documentation, scripts, and CI workflows

---

## Testing

The PoC is composed of local services:

- **Authorization service (Rust)**  
- **Gateway API (Go)**  
- **Issuer service (Go)**  
- **Holder wallet service (Go)**  
- **Device simulators (Go)**  

The recommended way to test the current PoC is to use the **scenario orchestrator**, which can start the local services and run the implemented scenarios from an interactive menu.

### Prerequisites

Make sure the following tools are available locally:

- `go`
- `cargo`

Also run all commands from the **repository root**, unless noted otherwise.

### Build checks

Run the Go modules from their module directories:

```bash
(cd issuer/go-issuer && go test ./...)
(cd gateway/go-api && go test ./...)
(cd holder/go-wallet && go test ./...)
(cd scenarios && go test ./...)
```

Run the Rust authorization service checks from its package directory:

```bash
(cd gateway/rust-authz && cargo check)
```

### Using the orchestrator

First, sync the Go workspace:

```bash
go work sync
```

Then start the orchestrator:

```bash
go run ./scenarios/orchestrator
```

You should see a menu:

```text
1) Show status / health
2) Use devices
3) Test flows
4) Quit
```

### What the orchestrator does

The orchestrator starts these local processes:

* `gateway/rust-authz`
* `devices/lock-sim`
* `devices/sensor-sim`
* `devices/light-sim`
* `gateway/go-api`
* `issuer/go-issuer`
* `holder/go-wallet`

It also runs the implemented end-to-end scenarios against the live HTTP services.

### Orchestrator logs

When services are started by the orchestrator, logs are written under:

```text
scenarios/.logs/
```

These logs are runtime output and are intentionally ignored by git.

### Expected scenario outcomes

#### Owner control

* an owner credential is issued
* the owner requests `unlock`
* the request is allowed
* expected reason: `allowed_by_owner_credential`

#### Delegation

* an owner credential is issued
* a delegated credential is issued for another subject
* delegated `unlock` is allowed
* delegated `lock` is denied
* expected deny reason: `action_out_of_scope`

#### Revocation

* a delegated credential is issued and works before revocation
* the issuer revokes that delegated credential
* the same delegated request is denied afterward
* expected deny reason: `credential_revoked`

#### VP challenge

* the holder wallet exposes a holder `did:key`
* an owner credential is issued to that holder DID
* the gateway issues a challenge and domain
* the wallet signs a verifiable presentation containing the credential
* the authorization service resolves issuer and holder `did:key` values and verifies both proofs
* expected reason: `allowed_by_owner_credential`

### SSI flow

The VP challenge flow follows this shape:

```text
Issuer -> Holder wallet: issue VC to holder did:key
Holder wallet -> Gateway: request device access challenge
Gateway -> Holder wallet: return challenge + domain
Holder wallet -> Gateway: submit signed VP containing the VC
Gateway -> Authorization service: forward access request + VP
Authorization service: resolve issuer/holder did:key values, verify VC + VP proofs, check revocation and policy
Gateway -> Device simulator: execute command only after allow
```

This is still a PoC. The current challenge is bound into the VP proof and checked by the authorization service, but challenge persistence, expiry enforcement, and one-time-use replay protection are the next security-hardening step.

### Version-control hygiene

The repository tracks source code, lockfiles, policy fixtures, and empty fixture directories. It intentionally ignores generated local state:

* Rust build output under `gateway/rust-authz/target/`
* Orchestrator logs under `scenarios/.logs/`
* Issued credential JSON files under `testdata/credentials/`
* Audit logs under `testdata/audit/`
* Local sensor sink output under `testdata/data/*.ndjson`

To reset runtime state between manual scenario runs, remove generated files from those ignored paths. The seed policy and revocation fixture files under `testdata/policies/` and `testdata/revocations/` are kept in version control.

### Notes

* The orchestrator uses `127.0.0.1` for service URLs to avoid local IPv6 `localhost` issues on some systems.
* The current automated test flow covers **owner control**, **delegation**, **revocation**, **ownership transfer**, **data-flow mediation**, and **VP challenge**.
