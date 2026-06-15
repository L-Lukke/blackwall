# Completed PoC Checklist

- [X] Define the initial PoC architecture and service split (Go gateway + Go issuer + Rust authz + device simulators)
- [X] Implement the first end-to-end vertical slice for owner control
- [X] Implement the initial issuer endpoint for owner credential issuance
- [X] Implement the initial authorization endpoint in the Rust service
- [X] Implement the initial gateway access-request endpoint
- [X] Implement the first device simulator and gateway-to-device mediation
- [X] Add delegation credential support and delegated-access flows
- [X] Add revocation support and revocation-aware authorization
- [X] Add ownership-transfer support and authority replacement flows
- [X] Implement additional device simulators and adapters (light, sensor)
- [X] Add data-flow mediation/redirection for compatible devices
- [X] Add audit logging and authorization decision traceability
- [X] Implement scenario runners for owner control, delegation, revocation, and ownership transfer
- [X] Add performance/feasibility measurements (latency, verification time, resource usage)
- [X] Expand the credential model toward fuller SSI alignment (DIDs, VC-like structures, proof handling)
- [X] Add focused authorization/gateway unit tests and a non-interactive scenario smoke runner
- [X] Add CI workflows for build, lint, test, and scenario smoke checks
- [X] Add issuer, wallet, gateway, and authorization unit coverage for critical SSI/security paths
- [X] Add all-device non-interactive smoke coverage with flow/json/timeout options
- [X] Add local policy fixture management CLI
- [X] Add repeatable scenario measurement runner
- [X] Add reproducible check, smoke, measurement, policy-list, and reset commands
- [X] Document richer household policy semantics as production hardening beyond the closed PoC scope
- [X] Document broader regression/performance baseline tracking as production hardening beyond the closed PoC scope
- [X] Complete project README, ADR, scenario documentation, and reproducible dev/runtime commands

## Closed Scope Notes

The PoC is complete as a local, software-only SSI smart-home gateway demonstration. Production hardening work such as authenticated policy administration, standards-aligned Status List revocation, selective disclosure, production wallet/key storage, multi-gateway state replication, formal API specs, and release-blocking performance baselines is intentionally documented as productization work rather than implemented in this repository.
