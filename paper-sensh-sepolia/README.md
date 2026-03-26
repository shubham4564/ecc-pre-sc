# SENSH Paper Prototype (Sepolia, No NPM)

This folder contains a Python-only prototype inspired by the SENSH paper:

**"A secure encrypted search mechanism for health data with blockchain and proxy re-encryption"**

The implementation follows the paper's smart-contract-facing API and algorithm flow with no npm/Hardhat dependency.

## Paper-to-Prototype Mapping

- `authorizeUser` / `revokeUser` from Algorithm 1
- `generateLabel` / `updateLabel` from Algorithm 2
- `generateToken` from Algorithm 3
- `search` with obfuscation-factor from Algorithm 4
- `BloomFilter` contract methods: `hash`, `add`, `exists`, `remove`

## What Is On-Chain vs Off-Chain

On-chain:

- Authorized-user and label membership checks using Bloom filters
- LEDD mapping for label to encrypted payload metadata
- Token/version/count state used for query authentication semantics
- Search result generation with obfuscation outputs and audit events

Off-chain:

- AES encryption/decryption of medical payloads
- Proxy re-encryption key derivation and conversion pipeline
- Label/token orchestration with real hospital systems and cloud storage

## Project Structure

- `contracts/BloomFilter.sol`: counting-style Bloom filter interface from paper
- `contracts/SENSHSearchableEncryption.sol`: SENSH contract with paper-mapped methods
- `scripts/deploy_sepolia_python.py`: Python deployment script
- `scripts/interact_sensh_python.py`: end-to-end interaction workflow
- `scripts/benchmark_sepolia_python.py`: gas/latency benchmark
- `tests/test_sensh_contracts.py`: local contract tests via Ethereum tester

## Prerequisites

- Python 3.10+
- Install dependencies:

```bash
pip install -r requirements.txt
```

- Solidity compiler binary `solc-windows.exe` in either:

1. `paper-sensh-sepolia/scripts/solc-windows.exe`
2. `paper-vpre-sepolia/scripts/solc-windows.exe`

## Environment

Copy `.env.example` to `.env` and set:

- `ALCHEMY_SEPOLIA_URL`
- `DEPLOYER_PRIVATE_KEY`
- optional `QUERY_PRIVATE_KEY`
- `CHAIN_ID=11155111`
- optional `BF_BITS` and `BF_HASHES`

## Deploy (Sepolia)

```bash
python scripts/deploy_sepolia_python.py
```

Deployment output:

- `data/deployed.sepolia.json`

## Interaction Flow

```bash
python scripts/interact_sensh_python.py
```

This runs:

1. user authorization (if query key provided)
2. label generation for encrypted data pointer
3. token generation
4. searchable query with obfuscated result set
5. label update

## Benchmark

```bash
set BENCH_ITERS=3
python scripts/benchmark_sepolia_python.py
```

Outputs:

- `benchmarks/paper_sensh_sepolia_detail.csv`
- `benchmarks/paper_sensh_sepolia_summary.csv`
- `benchmarks/comparison_with_existing_vpre_blocynfo.csv`

## Tests

```bash
pytest -q tests/test_sensh_contracts.py
```

Covered scenarios:

- authorization/revocation behavior
- label/token/search happy path
- unauthorized write rejection
- ciphertext update behavior through `updateLabel`

## Assumptions and Gaps

- The paper describes high-level searchable-encryption and PRE workflow; this prototype anchors searchable state and metadata on-chain.
- AES/PRE cryptography remains off-chain and represented on-chain by `bytes32` encrypted-value placeholders.
- Bloom `remove` follows the paper's simplified deletion pattern and may introduce false negatives as in standard non-counting reset behavior.
