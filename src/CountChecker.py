from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak
from web3 import Web3
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_ROOT     = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "data"


def get_pre_contract_info():
    """Load PRE contract address from JSON file."""
    try:
        with open(_DATA_DIR / 'contract_info.json', 'r') as f:
            contract_data = json.load(f)
            return contract_data['contract_address']
    except Exception as e:
        print(f"Error loading contract info: {str(e)}")
        raise


def load_pre_abi():
    with open(_DATA_DIR / 'PRE_compData1.json', 'r') as f:
        compdata = json.load(f)
        return compdata['PRE']['abi']


def load_counter_abi():
    with open(_DATA_DIR / 'Counter_compData.json', 'r') as f:
        compdata = json.load(f)
        return compdata['abi']

class CountChecker:

    def checkcount(self):
        """Resolve Counter from PRE and return the current count."""
        load_dotenv()
        ALCHEMY_API = os.getenv('ALCHEMY_API')
        WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')

        if not all([ALCHEMY_API, WALLET_ADDRESS]):
            raise ValueError("Missing environment variables. Please check .env file")
        
        # Connect to local Ethereum node
        web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))
        
        account = WALLET_ADDRESS

        # self.account = self.WALLET_ADDRESS
        if not web3.is_connected():
            raise Exception("Failed to connect to network")
    
        pre_contract_address = Web3.to_checksum_address(get_pre_contract_info())
        pre_contract = web3.eth.contract(address=pre_contract_address, abi=load_pre_abi())
        counter_contract_address = Web3.to_checksum_address(pre_contract.functions.countingContract().call())
        counter_contract = web3.eth.contract(address=counter_contract_address, abi=load_counter_abi())

        try:
            print("[getCount] actor=User/Reader")
            print("  tx_hash: N/A (eth_call)")
            print("  block: N/A")
            print("  gas_used: 0 on-chain (read-only call)")
            print("  effective_gas_price_wei: 0")
            print("  effective_gas_price_gwei: 0")
            print("  transaction_fee_eth: 0")
            return counter_contract.functions.getCount(account).call({'from': account})
        except Exception as e:
            print(f"Transaction failed: {str(e)}")
            raise

def main():

    cc = CountChecker()

    count = cc.checkcount()

    print("Count':", count)
if __name__ == "__main__":
    main()