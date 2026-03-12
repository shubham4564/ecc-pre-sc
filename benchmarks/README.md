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

## Increment isolation benchmark
Measures the gas cost attributable exclusively to `Counter.increment()` by deploying two PRE contract instances — one with `countingEnabled=True` and one with `countingEnabled=False` — using an identical ciphertext, then computing the per-call gas delta. Also reports direct `estimate_gas` readings for cold (first call, 0→1 storage slot) and warm (subsequent calls, n→n+1) increment costs.

```
python benchmarks/bench_increment_isolation.py [--iters N]
```
- Output CSV: `benchmarks/increment_isolation_bench.csv` with columns `iteration,gas_with_counting,gas_without_counting,delta_gas`.
- Console prints cold gas, warm gas, mean reEncrypt gas, overhead percentages, and delta mean/stdev.
- Uses `estimate_gas` from the PRE contract address for deterministic cold/warm readings with zero ZKP noise.
- The differential mean and stdev serve as corroborating evidence; the `estimate_gas` values are the primary result.

## Comprehensive timing benchmark
Times every ECC-PRE process end-to-end using `perf_counter_ns` precision.

Off-chain processes (100 iterations default, 5 warmup):

```
python benchmarks/bench_timing.py
python benchmarks/bench_timing.py --offchain-iters 200
```

On-chain reEncrypt wall-clock latency (optional, requires `.env`):

```
python benchmarks/bench_timing.py --onchain --iters 5
```

- Output CSV: `benchmarks/timing_bench.csv` with columns `process,actor,category,iteration,time_ms`.
- Output plot: `benchmarks/timing_bench.png` — horizontal bar charts (mean ± stdev) with individual data points, color-coded by actor (CO=blue, SP=green, User=orange).
- Off-chain uses a log-scale x-axis (operations span ~0.05 ms to ~50 ms).
- The `key_generate` bench suppresses the `system_parameters.json` disk write per iteration; the initial write happens once during setup.

Processes timed:

| Process | Actor | What is measured |
|---|---|---|
| `key_generate` | CO | SECP256k1 keypair + ephemeral scalar generation |
| `encrypt` | CO | Full ECC-PRE encryption (c1–c5) of a 128-bit key |
| `rekey_generate` | SP | Re-encryption key derivation (rk1, rk2, rk3) |
| `zkp_proof_gen` | SP | Fiat-Shamir ZKP commitment + response |
| `redecrypt` | User | Local re-decryption to recover plaintext key |
| `reencrypt_tx` | SP | On-chain `reEncrypt()` tx round-trip (wall clock) |

## Tips
- Keep RPC/provider and environment stable during testing for comparable results.
- Use larger N (e.g., 50–200) for smoother statistics.
- Record your host machine specs alongside the CSVs.
