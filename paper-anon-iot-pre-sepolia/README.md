# Proxy Re-encryption Enabled Secure and Anonymous IoT (Sepolia, No NPM)

This folder contains a Python-only prototype inspired by the paper:

"Proxy re-encryption enabled secure and anonymous IoT"

The implementation follows the same style as other paper tracks in this repository:
- Solidity contracts compiled/deployed by Python
- Sepolia interaction and benchmark scripts
- Local tests using Ethereum tester

## Paper-to-Prototype Mapping

On-chain:
- owner pseudonym registration
- device pseudonym registration
- data authorization for owner-device pair
- re-encryption key commitment submission
- re-encryption request and owner approval
- transformed ciphertext verification

Off-chain:
- pseudonym generation helpers
- rekey commitment derivation
- transformed ciphertext hash derivation

## Project Structure

- contracts/IoTAnonymousPRE.sol
- scripts/common.py
- scripts/offchain_helpers.py
- scripts/deploy_sepolia_python.py
- scripts/interact_anoniot_python.py
- scripts/benchmark_sepolia_python.py
- tests/test_iot_anonymous_pre.py
- tests/test_offchain_helpers.py

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure environment:

```bash
copy .env.example .env
```

## Deploy

```bash
python scripts/deploy_sepolia_python.py
```

Deployment output:
- data/deployed.sepolia.json

## Interaction Demo

```bash
python scripts/interact_anoniot_python.py
```

Output:
- data/interaction_result.json

## Benchmark

```bash
set BENCH_ITERS=3
python scripts/benchmark_sepolia_python.py
```

Outputs:
- benchmarks/paper_anon_iot_pre_sepolia_detail.csv
- benchmarks/paper_anon_iot_pre_sepolia_summary.csv
- benchmarks/comparison_with_existing_and_other_papers.csv

## Tests

```bash
pytest -q
```
