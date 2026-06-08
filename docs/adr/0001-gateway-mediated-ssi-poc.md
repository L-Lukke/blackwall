# ADR 0001: Gateway-Mediated SSI Proof of Concept

## In-depth architecture diagram

```mermaid
sequenceDiagram
    participant I as Issuer
    participant W as Holder Wallet
    participant G as Gateway
    participant A as Authorization Service
    participant R as DID Resolver
    participant D as Device Simulator

    I->>W: Issue VC to holder did:key
    W->>G: Request access challenge
    G->>G: Store challenge with subject/device/action/domain/expiry
    G->>W: Return challenge + domain
    W->>W: Sign VP containing VC + challenge
    W->>G: Submit access request + VP
    G->>G: Consume challenge once
    G->>A: Forward request + VP
    A->>R: Resolve issuer did:key
    A->>R: Resolve holder did:key
    A->>A: Verify VC proof, VP proof, expiry, revocation, scopes, policy
    A->>G: allow / deny
    G->>D: Execute command if allowed
```

## Context

Blackwall is a software-only proof of concept for applying Self-Sovereign Identity (SSI) ideas to smart home access control and data mediation.

Most consumer smart devices are resource-constrained, vendor-specific, and unlikely to implement DID resolution, verifiable credential validation, holder wallets, or verifiable presentation protocols directly. The PoC therefore needs to demonstrate SSI-style authorization without requiring changes inside every device simulator.

The current system has five local components:

- Gateway API in Go
- Authorization service in Rust
- Issuer service in Go
- Holder wallet service in Go
- Device simulators in Go

The architecture must remain small enough for local scenario testing while still showing the key SSI control points: issuance, holding, presentation, verification, revocation, delegation, ownership transfer, and local policy.

## Decision

Use a gateway-mediated SSI architecture.

Smart devices stay SSI-unaware. The gateway receives access requests, handles challenge issuance, forwards authorization material to the Rust authorization service, and only calls device simulators after an allow decision.

Use VC-shaped credentials with:

- DID issuers and holder subjects
- `credentialSubject` device/action scopes
- `credentialStatus` for revocation state
- Ed25519 Data Integrity-style proofs

Use a holder wallet service for the holder role.

The wallet owns a holder `did:key`, stores credentials issued to that DID, and signs challenge-bound verifiable presentations. Access through the stronger SSI path uses:

```text
Issuer -> Holder wallet: issue VC to holder did:key
Holder wallet -> Gateway: request access challenge
Gateway -> Holder wallet: return challenge + domain
Holder wallet -> Gateway: submit VP containing VC
Gateway -> Authorization service: forward access request + VP
Authorization service: verify VP, VC, revocation, scopes, and policy
Gateway -> Device simulator: execute only after allow
```

Use `did:key` for the initial DID method.

`did:key` keeps DID resolution deterministic and local. It avoids adding a registry, web hosting dependency, or external resolver while still providing a real DID method and a DID document/resolver boundary. The authorization service resolves issuer and holder verification methods through a resolver module instead of accepting raw public keys in the access request.

Use stateful gateway challenges.

The gateway stores issued VP challenges in memory with subject, device, action, domain, and expiry metadata. A challenge is consumed on first use, so replaying the same VP is denied.

Use file-backed revocation and policy fixtures for the PoC.

Revocation is represented by `testdata/revocations/revoked_ids.json`. Device policy is represented by `testdata/policies/devices.json`. These are intentionally simple, inspectable fixtures for local scenario runs.

## Consequences

### Benefits

- Devices remain simple and SSI-unaware.
- The gateway becomes the local sovereignty and mediation point.
- The PoC now has recognizable issuer, holder, verifier, and subject roles.
- `did:key` provides real DID-derived verification keys without network dependencies.
- Challenge-bound VPs prove holder control of the holder DID key.
- One-time challenge consumption gives basic replay protection.
- Local files keep policy and revocation easy to inspect during demos.

### Trade-offs

- `did:key` is less operationally realistic than `did:web` or registry-backed DID methods for issuer governance.
- The wallet is an in-memory/local service, not a production wallet.
- Gateway challenge state is in memory and is lost on restart.
- Challenge state is not shared across multiple gateway instances.
- Revocation is custom and file-backed, not a standards-aligned Status List implementation.
- Proof handling is pragmatic JSON signing, not full VC Data Integrity canonicalization.
- The authorization service is still mostly a PoC verifier, not a general-purpose SSI verifier.

### Security Notes

The current VP flow checks:

- VP holder matches the request subject.
- VP proof challenge matches the gateway-issued challenge.
- VP proof domain matches the gateway domain.
- Challenge subject/device/action match the access request.
- Challenge is consumed once.
- VC subject matches the VP holder.
- VC issuer matches the trusted issuer DID.
- VC and VP signatures verify through DID resolution.
- Credential expiry, revocation, scopes, and local policy are enforced.

The current PoC does not yet provide:

- Durable challenge storage.
- Multi-gateway challenge replication.
- Full DID method support beyond `did:key`.
- Standards-aligned Status List revocation.
- Selective disclosure.
- Production key storage or recovery.

## Follow-Up Decisions

Likely next ADRs:

- Whether to add `did:web` for issuer identity.
- Whether to replace file-backed revocation with a Status List model.
- Whether to make challenge storage durable.
- Whether to introduce a real presentation exchange protocol.
- How to model local household policy management.
