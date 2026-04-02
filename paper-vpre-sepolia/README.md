# Paper-Faithful VPRE Prototype (Sepolia)

This prototype implements the core on-chain workflow from:

**"Fair Data Trading on Blockchain Through Verifiable Proxy Re-Encryption" (IEEE TCSS, 2026)**

## Scope

Implemented contracts map to paper Algorithms 1-4:

- `Authentication.sol` (Algorithm 1)
- `DataList.sol` (Algorithm 2)
- `FundFlow.sol` (Algorithm 3)
- `Trading.sol` (Algorithm 4)

Off-chain helper scripts provide:

- key generation
- `rk`, `vk`, and `cmit` generation
- AES-GCM sample encryption/decryption
- interaction and gas benchmark automation

## Prerequisites

- Python 3.10+
- Installed Python package dependencies from `requirements.txt`
- A local Solidity compiler binary at `scripts/solc-windows.exe` (already included)

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure environment:

```bash
copy .env.example .env
```

3. Optional off-chain sanity check:

```bash
python scripts/vpre_offchain_demo.py
```

This script now acts as a conformance gate and exits with failure if `cmit(rk)` and `cmit(vk)` diverge.

## Deploy to Sepolia

1. Fill `.env` values:
- `ALCHEMY_API_KEY` (or `ALCHEMY_SEPOLIA_URL`)
- `DEPLOYER_PRIVATE_KEY`
- `ETHERSCAN_API_KEY`

Example Alchemy URL:

```bash
ALCHEMY_SEPOLIA_URL=https://eth-sepolia.g.alchemy.com/v2/<your-api-key>
```

2. Deploy:

```bash
python scripts/deploy_sepolia_python.py
```

3. Copy output addresses into `.env`:
- `DEPLOYER_ADDRESS`
- `EVALUATOR_ADDRESS`
- `AUTH_ADDRESS`
- `DATALIST_ADDRESS`
- `FUNDFLOW_ADDRESS`
- `TRADING_ADDRESS`

## Off-Chain Demo

```bash
python scripts/vpre_offchain_demo.py
```

## End-to-End Interaction (with deployed contracts)

```bash
python scripts/interact_trade_python.py
```

## Benchmarks

Generate Sepolia benchmark CSV (no npm):

```bash
set BENCH_ITERS=3
python scripts/benchmark_sepolia_python.py
```

Output:

- `benchmarks/paper_vpre_sepolia_detail.csv`
- `benchmarks/paper_vpre_sepolia_summary.csv`

## Security Notes

- Escrow payouts/refunds use checks-effects-interactions with explicit status flags.
- Trade lock prevents concurrent purchase races per `uid`.
- Off-chain cryptographic parameter generation must be deterministic between counterparties.
- This prototype does not include evaluator-governance economics; see paper limitations section.

## Engineering Assumptions (explicit)

To keep the prototype deployable and benchmark-friendly on Sepolia:

- On-chain verification uses finite-field modular exponentiation (`modexp` precompile) for `g^rk` and `vk` commitment checks.
- Off-chain `rk`/`vk` derivation is context-bound with `uid` to prevent cross-trade reuse.
- Full PRE ciphertext transformation (`rEnc`) remains off-chain.
- Product file storage and retrieval (`DOS`) are represented by `dataAddress` (e.g., IPFS URI).
- Public keys for `DS`/`DB` are stored as scalar-compatible values needed by off-chain VPRE helper flow.
