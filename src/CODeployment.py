import random
import sys
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak
from cryptography.fernet import Fernet
import base64
import hashlib
import random
from web3 import Web3
from TTP import TTP
import os
import json
from pathlib import Path
from dotenv import load_dotenv

import solcx
from solcx import compile_standard, install_solc


# ---------------------------------------------------------------------------
# Path constants (resolved relative to this file so the project runs correctly
# regardless of the working directory)
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "data"
_CONTRACTS_DIR = _ROOT / "contracts"
_COMPILED_CONTRACTS_DIR = _CONTRACTS_DIR / "compiled"




class CO:
    hash1 = TTP.hash1
    hash2 = TTP.hash2
    hash3 = TTP.hash3

    def __init__(self):
        self.curve = SECP256k1
        self.q = int(self.curve.order)
        self.p = self.curve.generator

        self.id_a = 1234
        self.a_x = None
        self.a_y = None
        self.a_xp = None
        self.a_yp = None

        self.id_b = 4321
        self.b_x = None
        self.b_y = None
        self.b_xp = None
        self.b_yp = None

        self.c = None
        self.l_bits = None
        self.n_bits = None
    
   
    def key_generate(self, nbits):
        """Generates the keys and ephemeral randomness. Do not use this to generate real keys."""
        # Person A (Content Owner)
        self.a_x = random.randint(0, self.q - 1)
        self.a_y = random.randint(0, self.q - 1)
        self.a_xp = self.a_x * self.p
        self.a_yp = self.a_y * self.p

        # Person B (User)
        self.b_x = random.randint(0, self.q - 1)
        self.b_y = random.randint(0, self.q - 1)
        self.b_xp = self.b_x * self.p
        self.b_yp = self.b_y * self.p

        # Ephemeral Randomness
        self.c = random.randint(0, self.q - 1)

        # Sigma Length (hard coded to 256 for this example)
        self.l_bits = 128
        self.n_bits = nbits
        self.save_key_parameters()



    # def key_to_binary(self, message):
    #     """Converts the message to proper binary"""
    #     utf8_bytes = message.encode('utf-8')
    #     binary_string = ''.join(format(byte, '08b') for byte in utf8_bytes)
    #     return binary_string
    def key_to_binary(self, k_i):
        """Converts the key to proper binary"""
        binary_string = ''.join(format(byte, '08b') for byte in k_i)
        return binary_string
    
    def bits_to_bytes(self, bit_string):
        byte_array = bytearray()
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i+8]
            byte_array.append(int(byte, 2))
        return bytes(byte_array)
    
    def hex_to_ascii(self, hex_string):
        """Converts the hexadecimal string to an ASCII string"""
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        ascii_str = ''
        for i in range(0, len(hex_string), 2):
            hex_pair = hex_string[i:i+2]
            char_code = int(hex_pair, 16)
            ascii_str += chr(char_code)
        return ascii_str

    def get_prefix(self, x, y, a, b, p):
        """Computes the parity for the x and y values"""
        y2_computed = self.compute_y_squared(x, a, b, p)
        y2 = (y * y) % p

        if y2 == y2_computed:
            if y % 2 == 0:
                return 0x02
            return 0x03
        raise ValueError("Something terrible happened!")

    def compute_y_squared(self, x, a, b, p):
        """Computes the y squared value"""
        x2 = (x * x) % p
        x3 = (x2 * x) % p
        y2 = (x3 + a *  x + b) % p
        return y2
    


    def encrypt(self, key):
        """Encrypt the key to elliptic curve points"""
        # Compute C1 = r * p
        sigma = random.randint(0, 2 ** 128)

        r = self.hash1(key, sigma, self.id_a, self.a_xp.x(), self.a_yp.x())
        c1 = r * self.p

        # Compute C2 = skA^-1 * c * r * (pk_a1 + pk_a2) * P = skA^-1 * fqa
        f = self.c * r
        qa = (self.a_xp.x() + self.a_yp.x()) * self.p
        fqa = f * qa
        c2 = inverse_mod(self.a_x, self.q) * fqa

        # Convert the key into binary
        key_in_binary = self.key_to_binary(key)
        self.n_bits = len(key_in_binary)

        # Convert sigma into binary
        sigma_in_binary = bin(sigma)[2:].zfill(self.l_bits)

        # Concatenate the key and sigma
        key_plus_sigma = key_in_binary + sigma_in_binary

        # Compute H2(fqa)
        hashed_fqa = self.hash2(self.l_bits + self.n_bits, fqa.x())

        # C3 = (key || sigma) ^ H2(fqa)
        c3 = ''.join(str(int(a) ^ int(b)) for a, b in zip(key_plus_sigma, hashed_fqa))

        # C4 = t * P
        t = random.randint(0, self.q - 1)
        c4 = t * self.p

        # C5 = t + c * r * (pk_a1 + pk_a2) * skA^-1
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        c5 = t + self.c * r * (self.a_xp.x() + self.a_yp.x()) * inverse_mod(self.a_x, self.q) * hash3

        return c1, c2, c3, c4, c5

    def decrypt(self, c1, c2, c3, c4, c5):
        """Decrypt the elliptic curve points to the message"""
        # Compute points for Decryption check
        c5p = c5 * self.p
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        verification_point = c4 + (hash3 * c2)

        # C5 * P must equal C4 + H3(C1, C2, C3, C4) * C2
        if c5p.x() != verification_point.x():
            print("Decrypt Check 1 failed!")
            sys.exit(0)

        # Compute H2(fqa)
        hash_input = self.a_x * c2
        hash2 = self.hash2(self.l_bits + self.n_bits, hash_input.x())

        # (key || sigma) = c3_prime ^ hash2
        key_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(c3, hash2))

        # Extract the message
        # message_in_binary = message_plus_sigma[:-self.l_bits]
        key_in_binary = key_plus_sigma[:len(key_plus_sigma) - self.l_bits]
        key = self.bits_to_bytes(key_in_binary)

        # key = self.hex_to_ascii(hex(int(key_in_binary, 2)))

        # Extract sigma
        # sigma_in_binary = message_plus_sigma[-self.l_bits:]
        sigma_in_binary = key_plus_sigma[len(key_plus_sigma) - self.l_bits:]

        # Compute point for Decryption check
        r = self.hash1(key, int(sigma_in_binary, 2), self.id_a, self.a_xp.x(), self.a_yp.x())
        added_points = self.a_xp.x() + self.a_yp.x()
        qa = added_points * self.p
        verification_point_2 = inverse_mod(self.a_x, self.q) * self.c * r * qa

        # C2 must equal skA^-1 * c * r * (pk_a1 + pk_a2) * P
        if c2.x() != verification_point_2.x():
            print("Decrypt Check 2 failed!")
            sys.exit(0)

        return key
    

    def save_key_parameters(self):
        """Save generated keys and parameters to JSON file"""
        key_info = {
            'parameters': {
                'a_x': str(self.a_x),
                'a_y': str(self.a_y),
                'a_xp_x': str(self.a_xp.x()),
                'a_xp_y': str(self.a_xp.y()),
                'a_yp_x': str(self.a_yp.x()),
                'a_yp_y': str(self.a_yp.y()),
                'b_x': str(self.b_x),
                'b_y': str(self.b_y),
                'b_xp_x': str(self.b_xp.x()),
                'b_xp_y': str(self.b_xp.y()),
                'b_yp_x': str(self.b_yp.x()),
                'b_yp_y': str(self.b_yp.y()),
                'c': str(self.c),
                'l_bits': self.l_bits,
                'n_bits': self.n_bits,
                'id_a': "1234",
                'id_b': "4321",
                'q': str(self.q),
                'p_x': str(self.p.x()),
                'p_y': str(self.p.y())
            }
        }
    
        with open(_DATA_DIR / 'system_parameters.json', 'w') as f:
            json.dump(key_info, f, indent=4)



def save_contract_address(contract_address):
    """Save contract address to JSON file.
    Args:
        contract_address (str): Ethereum contract address to save
    """
    try:
        contract_info = {
            'contract_address': contract_address
        }
        with open(_DATA_DIR / 'contract_info.json', 'w') as f:
            json.dump(contract_info, f, indent=4)
    except Exception as e:
        print(f"Error saving contract address: {str(e)}")
        raise



class CiphertextManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CiphertextManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        self.c1 = None
        self.c2 = None
        self.c3 = None
        self.c4 = None
        self.c5 = None
    
    def set_ciphertext(self, c1, c2, c3, c4, c5):
        self.c1 = c1
        self.c2 = c2
        self.c3 = c3
        self.c4 = c4
        self.c5 = c5
    
    def get_ciphertext(self):
        return self.c1, self.c2, self.c3, self.c4, self.c5
    



def keccak256_hex(address):
    """Hash an address with the Keccak-256 hash function"""
    # Validate input
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError("Invalid Ethereum address format.")

    # Convert hex string to bytes
    byte_data = bytes.fromhex(address[2:])

    # Compute the Keccak-256 hash
    hash_bytes = keccak(byte_data)

    return hash_bytes.hex()





def format_address_for_constructor(address_str):
        # Remove '0x' if present
    """Convert address to bytes32 array for constructor"""
    # Use existing keccak256_hex function
    hashed = keccak256_hex(address_str)
    
    # Return formatted as bytes32 array
    return [f"0x{hashed}"]


def _extract_pre_artifact(compiled_data):
    """Return the PRE contract artifact from normalized or legacy compiled JSON."""
    if not isinstance(compiled_data, dict):
        raise ValueError("Compiled contract data is not a JSON object.")

    pre_artifact = compiled_data.get("PRE")
    if isinstance(pre_artifact, dict) and "abi" in pre_artifact and "bytecode" in pre_artifact:
        return pre_artifact

    for _, artifact in compiled_data.items():
        if not isinstance(artifact, dict):
            continue

        abi = artifact.get("abi")
        bytecode = artifact.get("bytecode")
        if not abi or not bytecode:
            continue

        has_reencrypt = any(
            isinstance(item, dict) and item.get("type") == "function" and item.get("name") == "reEncrypt"
            for item in abi
        )
        if has_reencrypt:
            return artifact

    raise ValueError("Could not find PRE contract ABI/bytecode in the JSON file.")


def deploy_contract(c1, c2, c3, c4, c5p):

    with open(_DATA_DIR / 'PRE_compData1.json', 'r') as f:
        data = json.load(f)
        pre_artifact = _extract_pre_artifact(data)
        contract_abi = pre_artifact["abi"]
        contract_bytecode = pre_artifact["bytecode"]
    #     compdata = json.load(f)
    #   #  if compdata['contractName'] == 'PRE':
    #     contract_abi = compdata['abi']
    #     contract_bytecode = compdata['bytecode']

        # contract_abi = compdata['abi']
        # contract_bytecode = compdata['bytecode']

    if isinstance(contract_bytecode, dict):
        contract_bytecode = contract_bytecode.get('object', '')

    #address = input("Enter a Solidity address in hex: ")
    address = "0xf5ccca0b9a335ad37303d71517ad248987c60954bad2539f42bca292b2dbee19"
    load_dotenv()

    PRIVATE_KEY = os.getenv('PRIVATE_KEY')
    ALCHEMY_API = os.getenv('ALCHEMY_API')
    WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
        
    if not all([PRIVATE_KEY, ALCHEMY_API, WALLET_ADDRESS]):
        raise ValueError("Missing environment variables. Please check .env file")
        
    # Connect to local Ethereum node
    web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))
    
    account = WALLET_ADDRESS

    if not web3.is_connected():
        raise Exception("Failed to connect to network")

        
    # Format input parameters
    constructor_args = [
        int(c1.x()), 
        int(c1.y()),  # C1 coordinates
        int(c2.x()), 
        int(c2.y()),  # C2 coordinates
        "0x" + c3,                    # C3 value
        int(c4.x()), 
        int(c4.y()),  # C4 coordinates
        int(c5p.x()),                # C5 * P
        # ["0x" + str(keccak256_hex(address))]  # Address hash
        format_address_for_constructor(account)

    ]
    
    # Create contract instance
    Contract = web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    block = web3.eth.get_block('latest')
    block_gas_limit = block['gasLimit']
    
    # Build constructor transaction
    construct_txn = Contract.constructor(*constructor_args).build_transaction({
        'from': account,
        'nonce': web3.eth.get_transaction_count(account),
        'gas': min(7000000, block_gas_limit - 100000),
        'gasPrice': web3.eth.gas_price
    })
    
    # Sign transaction
    signed_txn = web3.eth.account.sign_transaction(construct_txn, private_key=PRIVATE_KEY)
    
    # Get raw transaction (handles both attribute names)
    raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction')
    
    try:
        # Send raw transaction
        tx_hash = web3.eth.send_raw_transaction(raw_tx)
        
        # Wait for receipt
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        return str(tx_receipt.contractAddress)
        
    except Exception as e:
        print(f"Error deploying contract: {str(e)}")
        raise



def compile_solidity(solidity_file, solidity_version):
    try:
        solcx.install_solc(solidity_version)
        solcx.set_solc_version(solidity_version)
        compiled_sol = solcx.compile_files([solidity_file], output_values=['abi', 'bin'], optimize=True)

        # Extract contract name (handles multiple contracts)
        compiled_data = {}
        for contract_path, contract_data in compiled_sol.items():
            contract_name = contract_path.rsplit(':', 1)[-1]
            if contract_name.endswith('.sol'):
                contract_name = Path(contract_name).stem
            compiled_data[contract_name] = {
                "abi": contract_data['abi'],
                "bytecode": contract_data['bin']
            }

        return compiled_data

    except solcx.exceptions.SolcError as e:
        print(f"Compilation error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None




def write_compiled_to_json(compiled_data, output_file):
    try:
        with open(output_file, "w") as f:
            json.dump(compiled_data, f, indent=4)
        print(f"Compiled data written to {output_file}")
    except Exception as e:
        print(f"Error writing to JSON file: {e}")


def write_compiled_contract_files(compiled_data, compiler_version, output_dir):
    """Write per-contract artifacts and compiler metadata under contracts/compiled/."""
    try:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        compiler_info = {
            "compiler_version": compiler_version,
            "contracts": sorted(compiled_data.keys())
        }
        with open(output_dir / "compiler_info.json", "w") as f:
            json.dump(compiler_info, f, indent=4)

        for contract_name, artifact in compiled_data.items():
            with open(output_dir / f"{contract_name}.json", "w") as f:
                json.dump(artifact, f, indent=4)

        print(f"Compiler version: {compiler_version}")
        print(f"Compiled contracts written to {output_dir}")
    except Exception as e:
        print(f"Error writing compiled contract artifacts: {e}")


def generate_128bit_symmetric_key():
    """Generates a 128-bit symmetric key using Fernet."""
    # key = Fernet.generate_key()  # Fernet handles key generation securely
    key = os.urandom(32) 
    return key

def encrypt_content(content, key):
    """Encrypts content using the provided symmetric key."""
    # f = Fernet(key)
    # encrypted_content = f.encrypt(content.encode())  # Encode message to bytes
    # return base64.b64encode(encrypted_content).decode() # Encode to base64 for safe transport
    base64_key = base64.urlsafe_b64encode(key)  # Encode the key in Base64
    f = Fernet(base64_key)
    encrypted_content = f.encrypt(content.encode())  # Encode message to bytes
    return base64.b64encode(encrypted_content).decode()  # Encode to Base64 for safe transport

def bytes_to_bits(byte_data):
    bit_string = ""
    for byte in byte_data:
        bit_string += bin(byte)[2:].zfill(8)  # [2:] removes "0b", zfill pads
    return bit_string

def main():
    solidity_file_path = str(_CONTRACTS_DIR / "PREandCounter.sol")
    solidity_version_to_use = "0.7.6"
    install_solc(solidity_version_to_use)
    output_json_file = str(_DATA_DIR / "PRE_compData1.json")

    if not os.path.exists(solidity_file_path):
        print(f"Error: Solidity file '{solidity_file_path}' not found.")
    else:
        compiled_data = compile_solidity(solidity_file_path, solidity_version_to_use)

        if compiled_data:
            compiler_version = str(solcx.get_solc_version())
            write_compiled_to_json(compiled_data, output_json_file)
            write_compiled_contract_files(compiled_data, compiler_version, _COMPILED_CONTRACTS_DIR)
        else:
            print("Compilation failed.")


    k_i = generate_128bit_symmetric_key()
    print("Symmetric Key:", k_i)
    C_m = encrypt_content("hello this is the content that needs to be decrypted by the User.", k_i)
    print("Encrypted Content:", C_m)

    
    """Encrypt, decrypt, re-encrypt, and re-decrypt a message"""
    #message = input("Enter a message to encrypt: ")

    #128
    # k_i = "hellothisisgreat"

    #192
    # k_i = "hellothisisgreatnewsandi"

    #256
    # k_i = "hellothisisgreatnewsandthisisgoo"
    
    k_i_in_bits = bytes_to_bits(k_i)
    n_bits = len(k_i_in_bits)
    co = CO()

    co.key_generate(n_bits)

    # bit_list = bytes_to_bits(k_i)
    # print(f"Key (bit list): {bit_list}")

    c1, c2, c3, c4, c5 = co.encrypt(k_i)

    ciphertext_manager = CiphertextManager()
    ciphertext_manager.set_ciphertext(c1, c2, c3, c4, c5)

    print("\nDecrypted Message:", co.decrypt(c1, c2, c3, c4, c5), "\n")

    c5p = c5 * co.p

    print("C1 x:", c1.x())
    print("C1 y:", c1.y())
    print("C2 x:", c2.x())
    print("C2 y:", c2.y())
    print("C3:", '"0x' + c3 + '"')
    print("C4 x:", c4.x())
    print("C4 y:", c4.y(), "\n")

    prefix_c1 = co.get_prefix(c1.x(), c1.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    prefix_c2 = co.get_prefix(c2.x(), c2.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    prefix_c4 = co.get_prefix(c4.x(), c4.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    
    full_parity = f"0x{prefix_c1:02x}{prefix_c2:02x}{prefix_c4:02x}"

    print("C5 times P:", c5p.x())
    print("Parity:", full_parity, "\n")

    contract_address = deploy_contract(c1, c2, c3, c4, c5p)
    print(f"Smart contract deployed at: {contract_address}")
    save_contract_address(contract_address)




if __name__ == "__main__":
    main()
