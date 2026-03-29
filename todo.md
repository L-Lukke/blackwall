# Implementation Plan

- [X] Define the initial PoC architecture and service split (Go gateway + Go issuer + Rust authz + device simulators)
- [X] Implement the first end-to-end vertical slice for owner control
- [X] Implement the initial issuer endpoint for owner credential issuance
- [X] Implement the initial authorization endpoint in the Rust service
- [X] Implement the initial gateway access-request endpoint
- [X] Implement the first device simulator and gateway-to-device mediation

- [ ] Add delegation credential support and delegated-access flows
- [ ] Add revocation support and revocation-aware authorization
- [ ] Add ownership-transfer support and authority replacement flows
- [ ] Implement additional device simulators and adapters (light, sensor)
- [ ] Add data-flow mediation/redirection for compatible devices
- [ ] Expand the credential model toward fuller SSI alignment (DIDs, VC-like structures, proof handling)
- [ ] Implement local policy management and policy-enforcement support for household rules
- [ ] Add audit logging and authorization decision traceability
- [ ] Implement scenario runners for owner control, delegation, revocation, and ownership transfer
- [ ] Add integration tests, scenario tests, and correctness validation
- [ ] Add performance/feasibility measurements (latency, verification time, resource usage)
- [ ] Write ADRs, API documentation, and reproducible dev/runtime scripts
- [ ] Add CI workflows for build, lint, test, and scenario smoke checks