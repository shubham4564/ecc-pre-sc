import json
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3


_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "data"
_GAS_REPORT_FILE = _DATA_DIR / "gas_report.json"


def get_web3():
    load_dotenv()
    rpc = os.getenv("RPC_URL") or os.getenv("ALCHEMY_API")
    if not rpc:
        raise ValueError("Missing RPC_URL or ALCHEMY_API in .env")
    if not rpc.startswith("http"):
        rpc = f"https://eth-sepolia.g.alchemy.com/v2/{rpc}"
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise RuntimeError("Failed to connect to Sepolia")
    return w3


def load_address(file_name):
    with open(_DATA_DIR / file_name, "r") as f:
        return json.load(f)["contract_address"]


def find_pre_deployment(w3: Web3, pre_address: str, wallet_address: str, max_blocks: int = 5000):
    latest = w3.eth.block_number
    start = max(0, latest - max_blocks)
    for block_number in range(latest, start - 1, -1):
        block = w3.eth.get_block(block_number, full_transactions=True)
        for tx in block.transactions:
            if tx["from"] != wallet_address or tx["to"] is not None:
                continue
            receipt = w3.eth.get_transaction_receipt(tx["hash"])
            contract_address = receipt.get("contractAddress")
            if contract_address and Web3.to_checksum_address(contract_address) == pre_address:
                return tx, receipt, block_number
    return None, None, None


def print_deployment_summary(w3: Web3, tx, receipt, pre_address: str, counter_address: str):
    gas_price = int(tx.get("gasPrice", 0) or 0)
    effective_gas_price = int(receipt.get("effectiveGasPrice", gas_price) or 0)
    gas_used = int(receipt.get("gasUsed", 0) or 0)
    fee_wei = gas_used * effective_gas_price

    print("=== Contract Deployment Gas ===")
    print(f"PRE address: {pre_address}")
    print(f"Counter address: {counter_address}")
    print(f"Deployment tx hash: {tx['hash'].hex()}")
    print(f"Block: {receipt['blockNumber']}")
    print(f"Total gas used: {gas_used}")
    print(f"Gas price (wei): {gas_price}")
    print(f"Effective gas price (wei): {effective_gas_price}")
    print(f"Gas price (gwei): {w3.from_wei(effective_gas_price, 'gwei')}")
    print(f"Transaction fee (ETH): {w3.from_wei(fee_wei, 'ether')}")
    print("Note: Counter is created internally inside the PRE deployment transaction, so there is no separate external Counter deployment gas price.")
    print()


def print_runtime_report(entries):
    print("=== Runtime Blockchain Interactions ===")
    if not entries:
        print("No runtime gas entries recorded yet.")
        print("Read-only calls such as CountChecker.getCount() and SPManager check use eth_call and consume 0 on-chain gas.")
        return

    for entry in entries:
        print(f"[{entry.get('label')}] actor={entry.get('actor')}")
        print(f"  tx_hash: {entry.get('tx_hash')}")
        print(f"  block: {entry.get('block_number')}")
        print(f"  gas_used: {entry.get('gas_used')}")
        print(f"  effective_gas_price_gwei: {entry.get('effective_gas_price_gwei')}")
        print(f"  transaction_fee_eth: {entry.get('transaction_fee_eth')}")
        if entry.get("status_text"):
            print(f"  status_text: {entry.get('status_text')}")
        print()

    print("Read-only calls such as CountChecker.getCount() and SPManager check use eth_call and consume 0 on-chain gas.")


def main():
    w3 = get_web3()
    wallet_address = Web3.to_checksum_address(os.getenv("WALLET_ADDRESS"))
    pre_address = Web3.to_checksum_address(load_address("contract_info.json"))
    counter_address = Web3.to_checksum_address(load_address("count_contract_info.json"))

    tx, receipt, _ = find_pre_deployment(w3, pre_address, wallet_address)
    if tx and receipt:
        print_deployment_summary(w3, tx, receipt, pre_address, counter_address)
    else:
        print("=== Contract Deployment Gas ===")
        print("PRE deployment transaction not found in the recent scan range.")
        print()

    entries = []
    if _GAS_REPORT_FILE.exists():
        try:
            entries = json.loads(_GAS_REPORT_FILE.read_text())
        except Exception:
            entries = []
    print_runtime_report(entries)


if __name__ == "__main__":
    main()
