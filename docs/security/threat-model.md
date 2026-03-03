    # Threat Model (Draft)

    Status: Draft (must be completed before production claims / fund handling)
    Repository: `aethelred-contracts`

    ## 1. System Scope

    Describe what this repository is responsible for and what it is not.

    ## 2. Assets

    - Cryptographic keys / signing authority
    - User funds / token balances (if applicable)
    - Attestation evidence and trust anchors (if applicable)
    - Sensitive configuration and secrets
    - Operational availability / liveness

    ## 3. Trust Boundaries

    - Client <-> service / node / chain
    - Cross-process or cross-host boundaries
    - Cross-chain / oracle / external dependencies
    - CI/CD and release artifact trust chain

    ## 4. Adversary Capabilities

    - Remote unauthenticated attacker
    - Malicious integrator / SDK consumer misuse
    - Malicious or compromised operator / relayer / validator
    - Supply-chain attacker (dependency / CI artifact compromise)

    ## 5. Abuse Paths / Threat Scenarios (Repository-Specific)

    - Access control / upgrade authority
- Cross-chain message trust assumptions
- Oracle / PoR / circuit-breaker dependencies

    ## 6. Existing Controls

    List code-level, config-level, CI-level, and operational controls currently implemented.

    ## 7. Known Gaps / Assumptions

    Document assumptions that must hold for security claims to be valid.

    ## 8. Required Tests / Evidence

    - Unit tests for security-critical paths
    - Integration tests / negative tests
    - Fuzz/property tests (where appropriate)
    - Static analysis / dependency scans
    - Runtime hardening / deployment evidence
