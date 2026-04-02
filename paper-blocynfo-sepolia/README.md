# BloCyNfo-Share Paper Prototype (Sepolia, No NPM)

This folder contains a Python-only implementation of the BloCyNfo-Share paper:

**"BloCyNfo-Share: Blockchain based Cybersecurity Information Sharing with Fine Grained Access Control"**

## Paper-to-Prototype Scope

Implemented on-chain functions are aligned with the paper API surface:

- `storeParams` ~ `StoreParams()`
- `retrieveParams` ~ `RetrieveParams()`
- `orgRegistration` + `approveOrganization` ~ `OrgRegistration()` with trusted manager validation
- `regPubKey` ~ `RegPubKey()`
- `hashCTI` ~ `HashCTI()`
- `storeReKey` / `revokeReKey` ~ `StoreReKey()` and revocation handling
- `verify` ~ `Verify()`

## What Is On-Chain vs Off-Chain

On-chain:

- Organization registration/approval state
- Public parameter hash/URI
- CTI ciphertext hash and policy hash
- Re-encryption key hash and encrypted rekey blob
- Verification checks and immutable event logs

Off-chain:

- CP-ABE encryption and decryption
- Proxy re-encryption transform math
- Attribute issuance by external credential authorities
- Ciphertext storage backend (e.g., cloud/IPFS)
- Rekey helper derivation context-binding (`owner`, `policy`, `ctiId`, `queryOrg`) for non-reusable prototype artifacts

## Project Structure

- `contracts/BloCyNfoShare.sol`: main paper-mapped contract
- `scripts/deploy_sepolia_python.py`: Python deployer for Sepolia
- `scripts/interact_blocynfo_python.py`: end-to-end interaction flow
- `scripts/benchmark_sepolia_python.py`: gas/latency benchmark runner
- `scripts/offchain_helpers.py`: policy/attribute hash + prototype rekey helpers
- `tests/test_blocynfo_share.py`: Python unit/integration-style tests (Ethereum tester)

## Prerequisites

- Python 3.10+
- Install requirements:

```bash
pip install -r requirements.txt
```

- Solidity compiler binary `solc-windows.exe` in one of:

1. `paper-blocynfo-sepolia/scripts/solc-windows.exe`
2. `paper-vpre-sepolia/scripts/solc-windows.exe`

## Environment

Create `.env` from `.env.example` and set:

- `ALCHEMY_SEPOLIA_URL`
- `DEPLOYER_PRIVATE_KEY`
- optional `QUERY_PRIVATE_KEY`
- `CHAIN_ID=11155111`

## Deploy (Sepolia)

```bash
python scripts/deploy_sepolia_python.py
```

Deployment output is saved to:

- `data/deployed.sepolia.json`

## Interaction Flow

```bash
python scripts/interact_blocynfo_python.py
```

This runs:

1. setup param hash
2. organization registrations
3. trusted-manager approvals
4. query pubkey registration
5. CTI hash submission
6. rekey storage
7. verify() check

## Benchmark

```bash
set BENCH_ITERS=3
python scripts/benchmark_sepolia_python.py
```

Outputs:

- `benchmarks/paper_blocynfo_sepolia_detail.csv`
- `benchmarks/paper_blocynfo_sepolia_summary.csv`

## Tests

```bash
pytest -q tests/test_blocynfo_share.py
```

Covered scenarios:

- normal flow and successful `verify()`
- revocation path (`revokeReKey` invalidates verify)
- ownership/access-control checks for sensitive functions

## Security Notes

- Contract uses strict ownership checks for manager-only operations.
- Only CTI owner can assign/revoke rekeys.
- Immutable transaction/event history supports non-repudiation audit trail.
- Hash anchoring protects against CTI/rekey tampering in storage middleware.

## Engineering Assumptions

- The paper omits full Solidity-level CP-ABE/PRE implementation details.
- This prototype keeps expensive cryptographic transforms off-chain and anchors verifiable hashes on-chain.
- `offchain_helpers.py` provides deterministic prototype rekey derivation for benchmarking only; replace with full cryptographic stack for production.
- Current prototype rekey hash/blob derivation includes `ctiId` and `queryOrg` context to avoid cross-context reuse during tests and benchmarks.
