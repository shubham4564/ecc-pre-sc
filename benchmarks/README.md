# PRE Benchmarks and Run Process

This folder contains scripts to measure the off-chain and on-chain performance of the PRE pipeline after the system has been deployed and initialized.

## Project run order

From the repository root, use the following sequence.

### 1. Activate the environment

```powershell
conda activate eccvenv
```

### 2. Deploy and initialize the system

```powershell
python src/CODeployment.py
```

This step:
- compiles [contracts/PREandCounter.sol](../contracts/PREandCounter.sol)
- writes aggregate compiled output to [data/PRE_compData1.json](../data/PRE_compData1.json)
- writes per-contract compiled artifacts to [contracts/compiled](../contracts/compiled)
- prints the Solidity compiler version
- generates and stores crypto parameters in [data/system_parameters.json](../data/system_parameters.json)
- deploys the PRE contract and stores the address in [data/contract_info.json](../data/contract_info.json)

Wait for the script to finish and confirm it prints:
- `Compiler version: 0.7.6`
- `Smart contract deployed at: ...`

### 3. Run re-encryption and re-decryption

```powershell
python src/SP.py
```

This step:
- loads [data/system_parameters.json](../data/system_parameters.json)
- loads [data/contract_info.json](../data/contract_info.json)
- loads [data/PRE_compData1.json](../data/PRE_compData1.json)
- calls `reEncrypt()` on-chain
- prints `C1'`, `C2'`, `C3'`, and `C4'`
- re-decrypts the returned values locally

Wait for the script to finish and confirm it prints:
- `reEncrypt() transaction successful!`
- the returned re-encrypted values
- the recovered decrypted key bytes

### 4. Check the download count

```powershell
python src/CountChecker.py
```

This step verifies that the counter contract was updated after successful re-encryption.

---

## Benchmark prerequisites

Before running the benchmark scripts, make sure:

- the environment is active: `conda activate eccvenv`
- [data/system_parameters.json](../data/system_parameters.json) exists
- [data/contract_info.json](../data/contract_info.json) exists
- [artifacts/PRE.json](../artifacts/PRE.json) exists
- `.env` in the repo root contains:

```env
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-key>
CHAIN_ID=11155111
PRIVATE_KEY=0x<your-private-key>
ALCHEMY_API=<your-alchemy-key>
WALLET_ADDRESS=0x<your-wallet-address>
```

## On-chain re-encryption benchmark

Runs multiple `reEncrypt()` transactions and records gas and latency.

```powershell
python benchmarks/bench_reencrypt.py
```

Output:
- [benchmarks/reencrypt_bench.csv](reencrypt_bench.csv)

Columns:
- `gas_used`
- `latency_ms`

The console also prints:
- average gas
- average latency
- latency percentiles
- approximate throughput

## Off-chain benchmark

Measures local CPU-bound parts of the PRE flow.

```powershell
python benchmarks/bench_offchain.py
```

Output:
- [benchmarks/offchain_bench.csv](offchain_bench.csv)

This benchmark uses the generated data in [data/system_parameters.json](../data/system_parameters.json), so run [src/CODeployment.py](../src/CODeployment.py) first.

## Recommended full workflow

```powershell
conda activate eccvenv
python src/CODeployment.py
python src/SP.py
python src/CountChecker.py
python benchmarks/bench_offchain.py
python benchmarks/bench_reencrypt.py
```

## Notes

- Always run commands from the repository root.
- If you redeploy with [src/CODeployment.py](../src/CODeployment.py), rerun [src/SP.py](../src/SP.py) and [src/CountChecker.py](../src/CountChecker.py) against the new deployment.
- If a block explorer does not immediately show the contract, wait for indexing and verify you are checking the Sepolia network.
