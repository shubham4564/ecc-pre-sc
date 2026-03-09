from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak
from web3 import Web3
import os
import json
from dotenv import load_dotenv


def get_contract_info():
    """Load contract address from JSON file"""
    try:
        with open('count_contract_info.json', 'r') as f:
            contract_data = json.load(f)
            return contract_data['contract_address']
    except Exception as e:
        print(f"Error loading contract info: {str(e)}")
        raise

class CountChecker:

    def checkcount(self):
        """Setup web3 and contract instance"""
        load_dotenv()
        PRIVATE_KEY = os.getenv('PRIVATE_KEY')
        ALCHEMY_API = os.getenv('ALCHEMY_API')
        WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')

        if not all([PRIVATE_KEY, ALCHEMY_API, WALLET_ADDRESS]):
            raise ValueError("Missing environment variables. Please check .env file")
        
        # Connect to local Ethereum node
        web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))
        
        account = WALLET_ADDRESS

        # self.account = self.WALLET_ADDRESS
        if not web3.is_connected():
            raise Exception("Failed to connect to network")
    
        with open('Counter_compData.json', 'r') as f:
            compdata = json.load(f)
            contract_abi = compdata['abi']
     
        #contract_address = get_contract_info()  # Replace with your contract's address
        contract_address = get_contract_info()  # Replace with your contract's address
        contract_address = Web3.to_checksum_address(contract_address)  # Convert to checksum address


        contract = web3.eth.contract(address=contract_address, abi=contract_abi)

        # Build transaction
        try:
            result = contract.functions.getCount(account).build_transaction({
                'from': account,
                'nonce': web3.eth.get_transaction_count(account),
                'gas': 1000000,
                'gasPrice': web3.eth.gas_price
            })

            signed_txn = web3.eth.account.sign_transaction(result, private_key=PRIVATE_KEY)
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction')
            tx_hash = web3.eth.send_raw_transaction(raw_tx)
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

            if tx_receipt['status'] == 1:
                print(f"reEncrypt() transaction successful! Transaction hash: {tx_hash.hex()}")
  
                count = contract.functions.getCount(account).call({
                'from': account,
                'nonce': web3.eth.get_transaction_count(account),
                'gas': 1000000,
                'gasPrice': web3.eth.gas_price
            })

                # if len(cPrime) == 4:
                #     _c1prime, _c2prime, _c3, _c4prime = cPrime
                # else:
                #     print("Unexpected number of return values from reEncrypt function.")

                return count

            else:
                print(f"reEncrypt() transaction failed. Transaction hash: {tx_hash.hex()}")
                print(f"Transaction receipt: {tx_receipt}")
                

        except Exception as e:
            print(f"Transaction failed: {str(e)}")
            raise

def main():

    cc = CountChecker()

    count = cc.checkcount()

    print("Count':", count)
if __name__ == "__main__":
    main()