# Implementation Notes

## Scope

This prototype implements a paper-aligned workflow for anonymous IoT proxy re-encryption control using pseudonymous identifiers and owner-mediated re-encryption approvals.

## On-chain decisions

- Pseudonyms are represented as bytes32 values.
- Data grants are bound to owner pseudonym, device pseudonym, ciphertext hash, and policy hash.
- Re-encryption requests are bound to requester address and nonce.

## Off-chain assumptions

- Full cryptographic PRE transform is represented by commitment/hash binding for benchmark repeatability.
- Storage and transport of full ciphertext remain off-chain.

## Benchmark methodology

Benchmark captures gas and latency for:
- registerOwner
- registerDevice
- authorizeData
- submitReKey
- requestReEncryption
- approveReEncryption
