import json
from datetime import datetime, timezone
from pathlib import Path


def format_tx_gas_summary(w3, tx_hash, receipt, label, actor=None, extra=None):
    gas_used = int(receipt.get("gasUsed", 0))
    effective_gas_price = receipt.get("effectiveGasPrice")
    if effective_gas_price is None:
        effective_gas_price = receipt.get("gasPrice")
    effective_gas_price = int(effective_gas_price or 0)
    total_fee_wei = gas_used * effective_gas_price

    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "actor": actor,
        "tx_hash": tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
        "block_number": int(receipt.get("blockNumber", 0) or 0),
        "gas_used": gas_used,
        "effective_gas_price_wei": effective_gas_price,
        "effective_gas_price_gwei": float(w3.from_wei(effective_gas_price, "gwei")) if effective_gas_price else 0.0,
        "transaction_fee_wei": total_fee_wei,
        "transaction_fee_eth": float(w3.from_wei(total_fee_wei, "ether")) if total_fee_wei else 0.0,
        "status": int(receipt.get("status", 0) or 0),
    }
    if extra:
        summary.update(extra)
    return summary


def print_tx_gas_summary(summary):
    print(f"[{summary['label']}] actor={summary.get('actor') or 'N/A'}")
    print(f"  tx_hash: {summary['tx_hash']}")
    print(f"  block: {summary['block_number']}")
    print(f"  gas_used: {summary['gas_used']}")
    print(f"  effective_gas_price_wei: {summary['effective_gas_price_wei']}")
    print(f"  effective_gas_price_gwei: {summary['effective_gas_price_gwei']}")
    print(f"  transaction_fee_eth: {summary['transaction_fee_eth']}")


class GasReportStore:
    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def append(self, summary):
        existing = []
        if self.file_path.exists():
            try:
                existing = json.loads(self.file_path.read_text())
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []

        existing.append(summary)
        self.file_path.write_text(json.dumps(existing, indent=4))
