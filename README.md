# ECC-PRE for Secure Download Counting

This project implements an elliptic-curve proxy re-encryption (ECC-PRE) workflow integrated with Ethereum smart contracts for controlled content access and download counting. The system lets a content owner encrypt content off-chain, deploy a PRE smart contract on-chain, re-encrypt ciphertext for an authorized user via zero-knowledge proofs and user-signed intent tokens, and atomically increment a download counter only when the re-encryption flow succeeds.

In short, the repository combines:

- off-chain decentralized key generation (eliminating TTP key-escrow), local encryption, re-encryption, and re-decryption
- on-chain zero-knowledge proof verification (LatticeZKP over matrix groups), EIP-191 user intent signature verification, and user replay protection
- a counter contract that atomically records successful access events
- benchmark scripts for off-chain and on-chain performance evaluation

## Main components

- [src/CODeployment.py](src/CODeployment.py)  
	Generates local CO key parameters, compiles contracts, writes compiled artifacts, deploys the PRE contract, registers initial SP allowlists, and stores deployment metadata.

- [src/SP.py](src/SP.py)  
	Generates local SP proof keys, binds user intent tokens into zero-knowledge proofs, calls `reEncrypt()` on-chain, retrieves returned ciphertext values, and re-decrypts them locally.

- [src/User.py](src/User.py)  
	Generates local User keypairs, constructs and signs EIP-191 access request tokens, and performs local re-decryption of the re-encrypted ciphertext returned by the SP.

- [src/CountChecker.py](src/CountChecker.py)  
	Reads the counter contract state and prints the current count for the configured wallet.

- [src/SPManager.py](src/SPManager.py)  
	Manages the Service Provider allowlist and SP proof public keys after deployment by adding, removing, checking, or transferring SP administration.

- [src/GasReporter.py](src/GasReporter.py)  
	Summarizes deployment gas and recorded runtime gas usage for blockchain-interacting operations.

- [contracts/PREandCounter.sol](contracts/PREandCounter.sol)  
	Contains the PRE contract and the counter contract. Implements Zero-Knowledge Proof verification (`verifyLatticeZKP()`), EIP-191 `verifyUserIntent()` signature recovery, and `usedUserNonces` replay protection. When a valid proof and user signature are verified, each successful `reEncrypt()` call atomically increments the counter.

- [contracts/FastEcMul.sol](contracts/FastEcMul.sol)  
	Library used internally by PREandCounter.sol for fast elliptic curve scalar multiplication via wNAF representation and scalar decomposition through the SECP256k1 endomorphism.

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
- stores the deployed Counter contract address in [data/count_contract_info.json](data/count_contract_info.json)
- records deployment gas in [data/gas_report.json](data/gas_report.json)

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

### Step 5: manage Service Providers dynamically

The contract now supports dynamic Service Provider lifecycle management without redeploying the PRE contract.

Supported operations:

- **check** — verify whether a wallet is currently authorized as a Service Provider
- **add** — onboard a new Service Provider
- **remove** — revoke an existing Service Provider
- **transfer-admin** — transfer SP administration to another wallet

Examples:

```powershell
python src/SPManager.py check 0xYourServiceProviderAddress
python src/SPManager.py add 0xYourServiceProviderAddress
python src/SPManager.py remove 0xYourServiceProviderAddress
python src/SPManager.py transfer-admin 0xNewAdminAddress
```

The admin account is the deployment wallet by default. These commands operate on the deployed Counter contract resolved through the PRE contract address.

Operational guidance:

- Use `check` before onboarding or revoking an address.
- Use `add` when a new Service Provider must be authorized to call `reEncrypt()`.
- Use `remove` immediately if a Service Provider is compromised or no longer trusted.
- Use `transfer-admin` only when you intentionally rotate governance of SP management.

All write operations performed through [src/SPManager.py](src/SPManager.py) are on-chain transactions and consume gas.

### Step 6: review gas usage

```powershell
python src/GasReporter.py
```

This script summarizes:

- deployment gas for the PRE deployment transaction
- the gas price used during deployment
- runtime gas consumed by `reEncrypt()` and SP admin operations
- the fact that read-only calls such as `getCount()` and `check` use `eth_call` and consume `0` on-chain gas

Important note:

- The Counter contract is created **internally** during PRE deployment.
- Because of that, Counter creation does **not** have a separate external deployment transaction or separate gas price.
- The PRE deployment transaction gas covers both PRE and Counter creation.

## Expected generated files

After a normal run, the following important files should exist or be updated:

- [data/system_parameters.json](data/system_parameters.json)
- [data/sp_proof_material.json](data/sp_proof_material.json)
- [data/encrypted_content.json](data/encrypted_content.json)
- [data/reencrypt_result.json](data/reencrypt_result.json)
- [data/contract_info.json](data/contract_info.json)
- [data/PRE_compData1.json](data/PRE_compData1.json)
- [contracts/compiled/compiler_info.json](contracts/compiled/compiler_info.json)
- [contracts/compiled/PRE.json](contracts/compiled/PRE.json)
- [contracts/compiled/Counter.json](contracts/compiled/Counter.json)
- [data/Counter_compData.json](data/Counter_compData.json)
- [data/count_contract_info.json](data/count_contract_info.json)
- [data/gas_report.json](data/gas_report.json)
- [benchmarks/increment_isolation_bench.csv](benchmarks/increment_isolation_bench.csv) — generated after running the increment isolation benchmark

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

### Increment isolation benchmark

Measures the gas cost attributable exclusively to `Counter.increment()` by deploying two PRE contract instances that are identical except for the `countingEnabled` flag, then computing the per-call gas delta. Also reports direct `estimate_gas` measurements for cold (0→1 storage slot) and warm (n→n+1) increment costs.

```powershell
python benchmarks/bench_increment_isolation.py [--iters N]
```

Output:

- [benchmarks/increment_isolation_bench.csv](benchmarks/increment_isolation_bench.csv) — columns: `iteration`, `gas_with_counting`, `gas_without_counting`, `delta_gas`

For benchmark-specific notes, see [benchmarks/README.md](benchmarks/README.md).

### Paper methodology conformance gate

To run the strict paper-track conformance checks in one command:

```powershell
python benchmarks/run_paper_conformance.py
```

This gate validates:

- VPRE commitment consistency (`scripts/vpre_offchain_demo.py`)
- SENSH contract conformance tests
- BloCyNfo contract + helper conformance tests
- Low-latency OABE contract + helper conformance tests

Outputs:

- [benchmarks/paper_methodology_conformance.json](benchmarks/paper_methodology_conformance.json)
- [benchmarks/paper_methodology_conformance.csv](benchmarks/paper_methodology_conformance.csv)

Release rule: treat the paper release as blocked if `overall_status` is `fail`.

## Recommended full workflow

```powershell
# activate your Python environment
python src/CODeployment.py
python src/SP.py
python src/CountChecker.py
python src/SPManager.py check 0xYourServiceProviderAddress
python src/GasReporter.py
python benchmarks/bench_offchain.py
python benchmarks/bench_reencrypt.py
python benchmarks/bench_increment_isolation.py
```

## Gas accounting by actor and operation

The project now reports or derives gas usage for blockchain-facing actions by role.

### Content Owner (CO)

- **Operation:** deploy PRE and Counter via [src/CODeployment.py](src/CODeployment.py)
- **Gas:** consumed on-chain
- **Reported in:** console output and [data/gas_report.json](data/gas_report.json)
- **Note:** one deployment transaction creates both PRE and Counter

### Service Provider (SP)

- **Operation:** call `reEncrypt()` via [src/SP.py](src/SP.py)
- **Gas:** consumed on-chain
- **Reported in:** console output and [data/gas_report.json](data/gas_report.json)
- **Note:** failed `reEncrypt()` transactions still consume gas and are also recorded

### SP Admin

- **Operations:** `add`, `remove`, `transfer-admin` via [src/SPManager.py](src/SPManager.py)
- **Gas:** consumed on-chain
- **Reported in:** console output and [data/gas_report.json](data/gas_report.json)

### User / Reader

- **Operation:** `getCount()` via [src/CountChecker.py](src/CountChecker.py)
- **Gas:** `0` on-chain because it uses `eth_call`

### Read-only SP checks

- **Operation:** `python src/SPManager.py check 0x...`
- **Gas:** `0` on-chain because it uses `eth_call`

## Troubleshooting

- If the block explorer does not show the contract immediately, wait for indexing and verify the address on the Sepolia network.
- If you redeploy using [src/CODeployment.py](src/CODeployment.py), rerun [src/SP.py](src/SP.py) and [src/CountChecker.py](src/CountChecker.py) against the new deployment.
- If you rotate or revoke a Service Provider, use [src/SPManager.py](src/SPManager.py) instead of redeploying the contracts.
- If you want a consolidated gas summary, run [src/GasReporter.py](src/GasReporter.py).
- If a script cannot find a JSON file, make sure the deployment step completed first.
- If transaction execution fails, verify `.env` values, wallet funding, and RPC connectivity.

## Purpose of the project

The project demonstrates how proxy re-encryption can be combined with smart contracts to enforce access control and maintain tamper-resistant usage accounting. It is suitable for experimentation, benchmarking, and reproduction of the ECC-PRE workflow described in the associated research context.
