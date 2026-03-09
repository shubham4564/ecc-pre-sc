# ECC-PRE for Secure Download Counting

This project implements an elliptic-curve proxy re-encryption (ECC-PRE) workflow integrated with Ethereum smart contracts for controlled content access and download counting. The system lets a content owner encrypt content off-chain, deploy a PRE smart contract on-chain, re-encrypt ciphertext for an authorized user, and increment a download counter only when the re-encryption flow succeeds.

In short, the repository combines:

- off-chain cryptographic key generation, encryption, re-encryption, and re-decryption
- on-chain PRE verification and controlled re-encryption
- a counter contract that records successful usage events
- benchmark scripts for off-chain and on-chain performance evaluation

## Main components

- [src/CODeployment.py](src/CODeployment.py)  
	Generates parameters, compiles contracts, writes compiled artifacts, deploys the PRE contract, and stores deployment metadata.

- [src/SP.py](src/SP.py)  
	Generates re-encryption keys, calls `reEncrypt()` on-chain, retrieves returned values, and re-decrypts them locally.

- [src/CountChecker.py](src/CountChecker.py)  
	Reads the counter contract state and prints the current count for the configured wallet.

- [contracts/PREandCounter.sol](contracts/PREandCounter.sol)  
	Contains the PRE contract and the counter contract.

- [benchmarks](benchmarks)  
	Contains scripts to measure off-chain and on-chain performance.

## Repository structure

- [src](src) — Python source code
- [contracts](contracts) — Solidity contracts
- [contracts/compiled](contracts/compiled) — generated per-contract compilation artifacts
- [data](data) — generated runtime JSON files and aggregate compiled output
- [artifacts](artifacts) — existing contract artifact files used by benchmark scripts
- [benchmarks](benchmarks) — benchmark scripts and CSV outputs
- [.env](.env) — local environment configuration

## Requirements

- Python 3.x
- Any Python environment manager such as Conda, `venv`, or virtualenv
- Internet access to reach the Sepolia RPC endpoint
- funded Sepolia account for deployment and transaction execution

Python dependencies are listed in [requirements.txt](requirements.txt).

## Environment setup

Create and activate any Python environment of your choice, then install the dependencies from [requirements.txt](requirements.txt).

Examples:

### Option 1: Conda

```powershell
conda activate eccvenv
pip install -r requirements.txt
```

### Option 2: Python `venv`

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Use whichever environment manager you normally prefer. The commands in the rest of this README assume that your Python environment is already activated.

## Environment variables

Create or update [.env](.env) in the repository root.

```env
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-key>
CHAIN_ID=11155111
PRIVATE_KEY=0x<your-private-key>
ALCHEMY_API=<your-alchemy-key>
WALLET_ADDRESS=0x<your-wallet-address>
```

Notes:

- `PRIVATE_KEY`, `ALCHEMY_API`, and `WALLET_ADDRESS` are used by the deployment and contract interaction scripts.
- `RPC_URL` and `CHAIN_ID` are used by the benchmark scripts.

## How to replicate and run the project

Always run commands from the repository root.

### Step 1: activate the environment

```powershell
# Activate your chosen Python environment first
```

### Step 2: deploy and initialize the system

```powershell
python src/CODeployment.py
```

This script:

- compiles [contracts/PREandCounter.sol](contracts/PREandCounter.sol)
- prints the Solidity compiler version
- writes aggregate compiled output to [data/PRE_compData1.json](data/PRE_compData1.json)
- writes per-contract artifacts to [contracts/compiled](contracts/compiled)
- generates cryptographic parameters and stores them in [data/system_parameters.json](data/system_parameters.json)
- deploys the PRE contract
- stores the deployed contract address in [data/contract_info.json](data/contract_info.json)

Wait for it to complete and confirm output similar to:

- `Compiler version: 0.7.6`
- `Smart contract deployed at: ...`

### Step 3: run re-encryption and local re-decryption

```powershell
python src/SP.py
```

This script:

- loads parameters from [data/system_parameters.json](data/system_parameters.json)
- loads the deployed contract address from [data/contract_info.json](data/contract_info.json)
- loads compiled contract data from [data/PRE_compData1.json](data/PRE_compData1.json)
- generates re-encryption keys
- sends a `reEncrypt()` transaction on-chain
- prints `C1'`, `C2'`, `C3'`, and `C4'`
- reconstructs the returned points and re-decrypts locally

Wait for it to complete and confirm output similar to:

- `reEncrypt() transaction successful!`
- the returned ciphertext values
- the recovered decrypted key bytes

### Step 4: verify the count

```powershell
python src/CountChecker.py
```

This script verifies the counter contract was updated after a successful re-encryption flow.

## Expected generated files

After a normal run, the following important files should exist or be updated:

- [data/system_parameters.json](data/system_parameters.json)
- [data/contract_info.json](data/contract_info.json)
- [data/PRE_compData1.json](data/PRE_compData1.json)
- [contracts/compiled/compiler_info.json](contracts/compiled/compiler_info.json)
- [contracts/compiled/PRE.json](contracts/compiled/PRE.json)
- [contracts/compiled/Counter.json](contracts/compiled/Counter.json)

## Benchmarks

Benchmark scripts are available in [benchmarks](benchmarks).

### Off-chain benchmark

```powershell
python benchmarks/bench_offchain.py
```

Output:

- [benchmarks/offchain_bench.csv](benchmarks/offchain_bench.csv)

### On-chain benchmark

```powershell
python benchmarks/bench_reencrypt.py
```

Output:

- [benchmarks/reencrypt_bench.csv](benchmarks/reencrypt_bench.csv)

For benchmark-specific notes, see [benchmarks/README.md](benchmarks/README.md).

## Recommended full workflow

```powershell
conda activate eccvenv
python src/CODeployment.py
python src/SP.py
python src/CountChecker.py
python benchmarks/bench_offchain.py
python benchmarks/bench_reencrypt.py
```

## Troubleshooting

- If the block explorer does not show the contract immediately, wait for indexing and verify the address on the Sepolia network.
- If you redeploy using [src/CODeployment.py](src/CODeployment.py), rerun [src/SP.py](src/SP.py) and [src/CountChecker.py](src/CountChecker.py) against the new deployment.
- If a script cannot find a JSON file, make sure the deployment step completed first.
- If transaction execution fails, verify `.env` values, wallet funding, and RPC connectivity.

## Purpose of the project

The project demonstrates how proxy re-encryption can be combined with smart contracts to enforce access control and maintain tamper-resistant usage accounting. It is suitable for experimentation, benchmarking, and reproduction of the ECC-PRE workflow described in the associated research context.
