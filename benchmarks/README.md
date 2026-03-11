# PRE Benchmarks

This folder contains standalone scripts to measure on-chain and off-chain performance of the PRE pipeline without touching your core code.

## Prerequisites
- Python deps already in your venv (web3, python-dotenv).
- `artifacts/PRE.json` exists (ABI) and `contract_info.json` contains the deployed `contract_address`.
- `.env` in repo root with:
```
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-key>
CHAIN_ID=11155111
PRIVATE_KEY=0x<your-private-key>
```

## On-chain re-encryption benchmark
Runs N reEncrypt transactions and logs gas + latency to CSV.

```
python benchmarks/bench_reencrypt.py
```
- Output CSV: `benchmarks/reencrypt_bench.csv` with columns `gas_used,latency_ms`.
- Console prints averages, percentiles, and approximate throughput (tx/s).

Note: Replace the placeholder `params_template` in `bench_reencrypt.py` with real RK and proof inputs your contract expects.

## Off-chain microbench (optional)
Time CPU-bound parts (e.g., RK generation) without blockchain.

```
python benchmarks/bench_offchain.py
```
- Edit the script to import and call your real function(s) instead of the `_noop` placeholder.

## Tips
- Keep RPC/provider and environment stable during testing for comparable results.
- Use larger N (e.g., 50–200) for smoother statistics.
- Record your host machine specs alongside the CSVs.
