# Low-Latency OABE Paper Prototype (Sepolia, No NPM)

This folder contains a Python-only prototype for:

**"A Low-Latency and Secure Data Sharing Method Based on Blockchain and Outsourced Attribute-Based Encryption"**

No npm/Hardhat/Foundry is used. Contracts are compiled and deployed via Python scripts and `solc-windows.exe`.

## Paper-to-Prototype Mapping

- Policy matching contract: `ACC SC` -> `ACCSC.sol`
- Consistency verification contract: `VER SC` -> `VERSC.sol`
- Tag metadata on-chain (`mtag`, `Ctag`, `H2(R)`) for verification workflow
- Off-chain outsourced ABE/MLE/AES stages represented with benchmark-oriented helper simulation

## Project Layout

- `contracts/ACCSC.sol`: policy matching and punishment mechanism
- `contracts/VERSC.sol`: consistency verification condition `Ctag = phi xor varphi xor H2(m') xor H2(R)`
- `scripts/deploy_sepolia_python.py`: deploy ACCSC and VERSC on Sepolia
- `scripts/interact_lowlatency_python.py`: normal flow interaction demo
- `scripts/benchmark_sepolia_python.py`: benchmark and generate comparison CSV
- `scripts/offchain_helpers.py`: off-chain cryptographic placeholders used for repeatable tests/benchmarks
- `tests/test_lowlatency_oabe.py`: contract tests

## Prerequisites

- Python 3.10+
- `pip install -r requirements.txt`
- `solc-windows.exe` in one of:
  1. `paper-lowlatency-oabe-sepolia/scripts/solc-windows.exe`
  2. `paper-vpre-sepolia/scripts/solc-windows.exe`

## Environment

Copy `.env.example` to `.env` and set:

- `ALCHEMY_SEPOLIA_URL`
- `DEPLOYER_PRIVATE_KEY`
- optional `QUERY_PRIVATE_KEY`
- `CHAIN_ID=11155111`
- optional `ATTR_COUNT`

## Deploy (Sepolia)

```bash
python scripts/deploy_sepolia_python.py
```

Output file:

- `data/deployed.sepolia.json`

## Interaction Demo

```bash
python scripts/interact_lowlatency_python.py
```

## Benchmark

```bash
set BENCH_ITERS=3
python scripts/benchmark_sepolia_python.py
```

Outputs:

- `benchmarks/paper_lowlatency_oabe_sepolia_detail.csv`
- `benchmarks/paper_lowlatency_oabe_sepolia_summary.csv`
- `benchmarks/comparison_with_existing_vpre_blocynfo_sensh.csv`

## Tests

```bash
pytest -q tests/test_lowlatency_oabe.py
```

## Security Notes

- `ACCSC` includes on-chain punishment logic for repeated failed requests.
- `VERSC` verifies outsourced-result consistency with immutable formula-based check.
- Private ABE secrets remain off-chain; on-chain contracts store only policy/verification metadata.

## Engineering Scope

- The paper does not publish full low-level Java crypto source; this prototype mirrors contract-layer protocol and verification semantics.
- Off-chain cryptographic helper code is deterministic for repeatable benchmarks, not production cryptography.
