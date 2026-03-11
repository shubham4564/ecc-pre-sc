import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3
from gas_utils import GasReportStore, format_tx_gas_summary, print_tx_gas_summary


_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "data"
_GAS_REPORT_FILE = _DATA_DIR / "gas_report.json"


def load_pre_address():
	with open(_DATA_DIR / "contract_info.json", "r") as f:
		return json.load(f)["contract_address"]


def load_pre_abi():
	with open(_DATA_DIR / "PRE_compData1.json", "r") as f:
		return json.load(f)["PRE"]["abi"]


def load_counter_abi():
	with open(_DATA_DIR / "Counter_compData.json", "r") as f:
		return json.load(f)["abi"]


def get_web3():
	load_dotenv()
	rpc_url = os.getenv("RPC_URL") or os.getenv("ALCHEMY_API")
	if rpc_url and not rpc_url.startswith("http"):
		rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{rpc_url}"

	if not rpc_url:
		raise ValueError("Missing RPC_URL or ALCHEMY_API in .env")

	w3 = Web3(Web3.HTTPProvider(rpc_url))
	if not w3.is_connected():
		raise RuntimeError("Failed to connect to network")
	return w3


def get_counter_contract(w3: Web3):
	pre_address = Web3.to_checksum_address(load_pre_address())
	pre_contract = w3.eth.contract(address=pre_address, abi=load_pre_abi())
	counter_address = Web3.to_checksum_address(pre_contract.functions.countingContract().call())
	counter_contract = w3.eth.contract(address=counter_address, abi=load_counter_abi())
	return counter_contract, counter_address


def send_admin_transaction(w3: Web3, contract, function_name: str, *args):
	load_dotenv()
	private_key = os.getenv("PRIVATE_KEY")
	admin_address = os.getenv("WALLET_ADDRESS")
	chain_id = int(os.getenv("CHAIN_ID", "11155111"))

	if not private_key or not admin_address:
		raise ValueError("Missing PRIVATE_KEY or WALLET_ADDRESS in .env")

	function = getattr(contract.functions, function_name)(*args)
	tx = function.build_transaction(
		{
			"from": admin_address,
			"nonce": w3.eth.get_transaction_count(admin_address, "pending"),
			"gas": 300000,
			"gasPrice": w3.eth.gas_price,
			"chainId": chain_id,
		}
	)
	signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
	raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
	tx_hash = w3.eth.send_raw_transaction(raw_tx)
	receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
	if receipt.status != 1:
		raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
	summary = format_tx_gas_summary(
		w3,
		tx_hash,
		receipt,
		label=function_name,
		actor="SP admin",
		extra={
			"counter_contract_address": contract.address,
			"target_args": [str(arg) for arg in args],
		},
	)
	print_tx_gas_summary(summary)
	GasReportStore(_GAS_REPORT_FILE).append(summary)
	return tx_hash.hex()


def main():
	parser = argparse.ArgumentParser(description="Manage dynamic Service Provider allowlist")
	subparsers = parser.add_subparsers(dest="command", required=True)

	add_parser = subparsers.add_parser("add", help="Add an allowed service provider")
	add_parser.add_argument("address", help="Service provider wallet address")

	remove_parser = subparsers.add_parser("remove", help="Remove an allowed service provider")
	remove_parser.add_argument("address", help="Service provider wallet address")

	check_parser = subparsers.add_parser("check", help="Check whether an address is allowed")
	check_parser.add_argument("address", help="Service provider wallet address")

	proof_parser = subparsers.add_parser("set-proof-key", help="Register or update a service provider proof public key")
	proof_parser.add_argument("address", help="Service provider wallet address")
	proof_parser.add_argument("pubx", help="Proof public key X coordinate")
	proof_parser.add_argument("puby", help="Proof public key Y coordinate")

	admin_parser = subparsers.add_parser("transfer-admin", help="Transfer service-provider admin role")
	admin_parser.add_argument("address", help="New admin wallet address")

	args = parser.parse_args()

	w3 = get_web3()
	counter_contract, counter_address = get_counter_contract(w3)
	print(f"Counter contract: {counter_address}")

	if args.command == "check":
		target = Web3.to_checksum_address(args.address)
		allowed = counter_contract.functions.isAllowed(target).call()
		proof_key = counter_contract.functions.getProofPublicKey(target).call()
		print(f"Allowed: {allowed}")
		print(f"Proof key: x={proof_key[0]}, y={proof_key[1]}, registered={proof_key[2]}")
		return

	target = Web3.to_checksum_address(args.address)
	if args.command == "add":
		tx_hash = send_admin_transaction(w3, counter_contract, "addAllowedAddress", target)
		print(f"Added {target}. Tx hash: {tx_hash}")
	elif args.command == "remove":
		tx_hash = send_admin_transaction(w3, counter_contract, "removeAllowedAddress", target)
		print(f"Removed {target}. Tx hash: {tx_hash}")
	elif args.command == "transfer-admin":
		tx_hash = send_admin_transaction(w3, counter_contract, "transferAdmin", target)
		print(f"Transferred admin to {target}. Tx hash: {tx_hash}")
	elif args.command == "set-proof-key":
		tx_hash = send_admin_transaction(
			w3,
			counter_contract,
			"setProofPublicKey",
			Web3.to_checksum_address(args.address),
			int(args.pubx),
			int(args.puby),
		)
		print(f"Registered proof key for {Web3.to_checksum_address(args.address)}. Tx hash: {tx_hash}")


if __name__ == "__main__":
	main()
