
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

The PoC is composed of four local services:

- **Authorization service (Rust)**  
- **Lock simulator (Go)**  
- **Gateway API (Go)**  
- **Issuer service (Go)**  

The recommended way to test the current PoC is to use the **scenario orchestrator**, which can start the local services and run the implemented scenarios from an interactive menu.
### Prerequisites

Make sure the following tools are available locally:

- `go`
- `cargo`

Also run all commands from the **repository root**, unless noted otherwise.

### Using the orchestrator

First, sync the Go workspace:

```bash
go work sync
````

Then start the orchestrator:

```bash
go run ./scenarios/orchestrator
```

You should see a menu:

```text
1) Start all services
2) Stop all services
3) Show status / health
4) Run owner-control
5) Run delegation
6) Run revocation
7) Run ownership-transfer
8) Run all tests
0) Exit
```

### What the orchestrator does

The orchestrator starts these local processes:

* `gateway/rust-authz`
* `devices/lock-sim`
* `gateway/go-api`
* `issuer/go-issuer`

It also runs the implemented end-to-end scenarios against the live HTTP services.

### Orchestrator logs

When services are started by the orchestrator, logs are written under:

```text
scenarios/.logs/
```

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

### Notes

* The orchestrator uses `127.0.0.1` for service URLs to avoid local IPv6 `localhost` issues on some systems.
* The current automated test flow covers **owner control**, **delegation**, and **revocation**.
