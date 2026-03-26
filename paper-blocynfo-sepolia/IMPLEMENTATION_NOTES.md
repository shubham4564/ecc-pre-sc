# BloCyNfo-Share Implementation Notes

## 1. Paper Understanding

Goal:

- Privacy-preserving CTI sharing with fine-grained access control and non-repudiable auditability using blockchain + CP-ABE + proxy re-encryption.

System model:

- `Oi` (owner organizations), `QOk` (query organizations), `CS` (honest-but-curious proxy/storage), `Tm` (trusted manager), blockchain smart contract layer.

Algorithm flow:

1. Setup public params.
2. Register organizations + attributes/credentials.
3. Key generation.
4. Rekey generation per delegator->delegatee.
5. First-level encryption and CTI hash anchoring.
6. Re-encryption by proxy when attributes/policy satisfy.
7. Query-side decryption.
8. Revocation via rekey removal.

Author assumptions:

- Trusted manager exists and correctly validates credentials.
- Cloud/proxy follows protocol but is curious.
- CP-ABE and PRE primitives are available off-chain.

## 2. Mapping Decisions

Directly mapped on-chain:

- parameter anchoring and retrieval
- organization registration and manager approval
- query public-key anchoring
- CTI hash anchoring
- rekey anchoring and revocation
- verify checks for CTI hash + active rekey hash

Kept off-chain:

- CP-ABE encrypt/decrypt
- PRE transform and bilinear pairings
- credential authority signature issuance

## 3. Gaps and Assumptions

Paper-supported:

- function-level blockchain workflow and PRE/ABE roles
- hash recording for non-repudiation and integrity

Inferred:

- explicit approval lifecycle (`orgRegistration` + `approveOrganization`)
- schema for policy hash / attributes hash canonicalization
- deterministic prototype rekey representation for benchmark repeatability

Needs experimental validation:

- true end-to-end CP-ABE/PRE crypto runtime under realistic CTI payloads
- cloud proxy throughput under high request fan-out
- attribute-policy mismatch handling at scale

## 4. Benchmark Matrix

| paper requirement | implemented component | placement | benchmark metric | assumption |
|---|---|---|---|---|
| public params publication | `storeParams`, `retrieveParams` | on-chain | gas + latency per call | params stored as hash + URI |
| org onboarding | `orgRegistration`, `approveOrganization` | on-chain | registration gas, approval gas | manager approval explicit in contract |
| query key registration | `regPubKey` | on-chain | gas + latency | signature represented by signed-key hash |
| CTI integrity anchoring | `hashCTI` | on-chain | gas + storage growth | ciphertext kept off-chain |
| rekey delegation | `storeReKey` | on-chain anchor + off-chain blob | gas + blob size | full PRE key math not executed in Solidity |
| requester verification | `verify` | on-chain | call latency + false/true rates | verify checks anchored hashes and active status |
| revocation | `revokeReKey` | on-chain | revocation gas + post-revoke verify result | revocation by key-state toggle |
| CP-ABE/PRE cryptography | `offchain_helpers.py` placeholder hooks | off-chain | CPU time, memory, throughput | placeholder deterministic rekey for prototype |
