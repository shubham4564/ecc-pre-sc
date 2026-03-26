# SENSH Implementation Notes

This document explains how the SENSH paper was mapped into this Python-only prototype.

## Contract Design

- `SENSHSearchableEncryption.sol` is the main paper-facing contract.
- `BloomFilter.sol` is deployed internally twice by the SE contract:
  - `authorizedUsersFilter`
  - `labelsFilter`

The method surface follows the paper section on smart contracts and Algorithms 1 to 4.

## Algorithm Mapping

1. Algorithm 1 (authorization/revocation):
- `authorizeUser(address)`
- `revokeUser(address)`
- user hash path: `keccak256(abi.encodePacked(user))`

2. Algorithm 2 (label generation/update):
- `k1 = H(K || "k1")`
- `label = H(k1 || Endata)`
- store into LEDD map and push to label filter
- `updateLabel(label, newEncryptedValue)` updates encrypted value and timestamp

3. Algorithm 3 (token generation):
- increment per-label count
- `k2 = H(label || "k2")`
- `token = H(label || version || count || k2)`

4. Algorithm 4 (search):
- verify membership with Bloom filter
- return array size `obfuscationFactor`
- index 0 is real label (or zero if not found in LEDD)
- remaining entries are random obfuscation hashes

## Security and Engineering Notes

- This prototype treats cryptographic payloads as `bytes32` references/hashes.
- AES/PRE transform math remains off-chain by design.
- `searchResult` stores the latest matched encrypted payload for easy verification in scripts.
- `removeLabel` is owner-only helper for lifecycle management; not a required paper API.

## Benchmark Design

The benchmark script measures transaction latency and gas for:

- `generateLabel`
- `generateToken`
- `search`
- `updateLabel`

It also emits end-to-end comparisons against available baseline CSV files in:

- `benchmarks/timing_bench.csv`
- `paper-vpre-sepolia/benchmarks/paper_vpre_sepolia_summary.csv`
- `paper-blocynfo-sepolia/benchmarks/paper_blocynfo_sepolia_summary.csv`
