# Implementation Notes

## 1) Paper Understanding

### Goal

Enable low-latency and secure data sharing in cloud-edge-end (drone swarm style) systems using:

- outsourced ABE for reduced end-device burden,
- blockchain smart contracts for policy enforcement and result verifiability.

### System Model

- Drone terminals (resource-constrained, potentially untrusted)
- Ground control station (edge node)
- Cloud server (untrusted compute/storage)
- Blockchain network (edge consortium)
- Command center (trusted authority)

### Flow (paper-mapped)

1. Setup `(lambda, U) -> (pp, msk)`
2. Symmetric edge-end encryption and transfer
3. MLE + partial ABE on edge
4. Outsourced ABE part on cloud
5. Access request and policy check by `ACC SC`
6. Outsourced partial decryption and terminal final decryption
7. Proof submission and consistency check by `VER SC`

### Author Assumptions

- Trusted command center for setup/keygen
- GCS more trusted/auditable than cloud
- Cloud untrusted but available for outsourced operations
- Smart contracts are tamper-resistant and auditable

### On-chain vs Off-chain mapping

On-chain:

- Policy vectors and access checks (`ACCSC`)
- Punishment state for repeated invalid requests (`ACCSC`)
- Cipher tag and verification metadata (`VERSC`)
- Consistency equation verification (`VERSC`)

Off-chain:

- AES encryption/decryption
- Full MLE and ABE math
- Partial encryption/decryption transforms

## 2) Contract Architecture

- `ACCSC.sol`
  - Stores policy vector per `mtag`
  - Implements paper-style `arrPolicyVerify` and punishment logic
  - Exposes benchmark-friendly `arrPolicyVerifyCode`

- `VERSC.sol`
  - Stores `(mtag, Ctag, H2(R))`
  - Implements `conformVerify` and tx wrapper `conformVerifyTx`

## 3) Storage Layout

### ACCSC

- `mapping(address => PunishInfo) punish`
- `mapping(bytes32 => uint8[]) _tagPolicies`
- `mapping(bytes32 => TagPolicy) tagPolicies`

### VERSC

- `mapping(bytes32 => CipherMeta) cipherMetaByTag`
- immutable `phi`, `varphi`

## 4) Key Functions

- `setTagPolicy(mtag, polCloud, rDigest)`
- `arrPolicyVerify(mtag, arrUser, userId, userAdd)`
- `punishment(userAdd)`
- `registerCipherMeta(mtag, cTag, h2R)`
- `conformVerify(mtag, h2m, h2r)`
- `conformVerifyTx(mtag, h2m, h2r)`

## 5) Access Control

- Owner-only policy/meta registration
- Requester invokes policy matching
- Punishment branch activates after repeated failures in bounded interval

## 6) Ambiguities and Engineering Assumptions

Directly supported by paper:

- Two smart contracts (`ACC SC`, `VER SC`)
- Punishment mechanism structure
- Consistency equation `Ctag = phi xor varphi xor H2(m') xor H2(R)`

Inferred for deployable prototype:

- `mtag`-indexed policy storage format (`uint8[]` bit-vector)
- `H2(R)` storage (instead of raw `R`) to keep metadata minimal
- tx helper wrapper `conformVerifyTx` for gas benchmarking

Must be validated experimentally:

- End-to-end latency under real drone/GCS/cloud topology
- Fidelity of Java-style outsourced ABE math vs placeholder deterministic helpers
- High-concurrency behavior beyond simple script load

## 7) Benchmark Matrix

| paper requirement | implemented component | placement | benchmark metric | assumption |
|---|---|---|---|---|
| policy matching contract | `ACCSC.arrPolicyVerifyCode` | on-chain | gas/call, latency/call, concurrency trend | policy represented as bit-vector |
| punishment logic | `ACCSC.punishment` branch via repeated failures | on-chain | failure threshold behavior, gas overhead | one-minute window from block timestamp |
| consistency verification contract | `VERSC.conformVerifyTx` | on-chain | gas/call, latency/call | verification inputs are `H2(m')` and `H2(R)` |
| store blockchain metadata `{mtag,Ctag,R,(A,rho)}` | `setTagPolicy` + `registerCipherMeta` | on-chain | storage gas, deploy cost | `R` stored as digest `H2(R)` |
| outsourced encryption/decryption | `scripts/offchain_helpers.py` simulation hooks | off-chain | local compute time, reproducibility | deterministic placeholder crypto for benchmarking |
| low-latency objective | benchmark CSV + cross-paper comparison script | mixed | end-to-end gas and latency sums | aggregation across representative contract calls |
