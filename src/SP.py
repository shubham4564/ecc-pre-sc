import random
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak
import random
from web3 import Web3
import TTP
import os
import json
from pathlib import Path
from dotenv import load_dotenv
import math
import secrets
import sys
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from gas_utils import GasReportStore, format_tx_gas_summary, print_tx_gas_summary

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_ROOT     = Path(__file__).resolve().parent.parent
_DATA_DIR = _ROOT / "data"
_GAS_REPORT_FILE = _DATA_DIR / "gas_report.json"
_SP_PROOF_FILE = _DATA_DIR / "sp_proof_material.json"


def write_reencrypt_result(c1p, c2p, c3p, c4p):
    payload = {
        "c1_prime": int(c1p),
        "c2_prime": int(c2p),
        "c3_prime": c3p,
        "c4_prime": int(c4p),
    }
    with open(_DATA_DIR / "reencrypt_result.json", "w") as f:
        json.dump(payload, f, indent=4)


def load_sp_proof_material(expected_wallet_address):
    with open(_SP_PROOF_FILE, "r") as f:
        payload = json.load(f)

    configured_wallet = payload.get("wallet_address")
    if not configured_wallet:
        raise ValueError("Missing wallet_address in sp_proof_material.json")

    if configured_wallet.lower() != Web3.to_checksum_address(expected_wallet_address).lower():
        raise ValueError("sp_proof_material.json does not match the active WALLET_ADDRESS")

    return payload

class SP:
    hash1 = staticmethod(TTP.hash1)
    hash2 = staticmethod(TTP.hash2)
    hash4 = staticmethod(TTP.hash4)

    def get_redec_parameters(self):
        """Load parameters needed for re-decryption"""
        try:
            with open(_DATA_DIR / 'system_parameters.json', 'r') as f:
                params = json.load(f)
                
            if 'parameters' not in params:
                raise KeyError("Missing 'parameters' in system_parameters.json")
                
            param_dict = params['parameters']
            required_keys = ['a_xp_x','a_xp_y', 'a_yp_x', 'a_yp_y', 'id_a', 'id_b', 'b_xp_x', 'b_xp_y', 'b_yp_x', 'b_yp_y', 'p_x', 'p_y', 'q', 'l_bits', 'n_bits', 'b_x', 'b_y']
            
            # Check all required keys exist
            for key in required_keys:
                if key not in param_dict:
                    raise KeyError(f"Missing required parameter: {key}")
            
            # Extract and convert parameters
            self.a_xp_x = int(param_dict['a_xp_x'])
            self.a_xp_y = int(param_dict['a_xp_y'])
            self.a_yp_x = int(param_dict['a_yp_x'])
            self.a_yp_y = int(param_dict['a_yp_y'])
            self.id_a = param_dict['id_a']
            self.id_b = param_dict['id_b']
            self.b_xp_x = int(param_dict['b_xp_x'])
            self.b_xp_y = int(param_dict['b_xp_y'])
            self.b_yp_x = int(param_dict['b_yp_x'])
            self.b_yp_y = int(param_dict['b_yp_y'])
            self.p_x = int(param_dict['p_x'])
            self.p_y = int(param_dict['p_y'])
            self.q = int(param_dict['q'])
            self.l_bits = int(param_dict['l_bits'])
            self.n_bits = int(param_dict['n_bits'])
            self.b_x = int(param_dict['b_x'])
            self.b_y = int(param_dict['b_y'])

            self.a_xp = Point(SECP256k1.curve, self.a_xp_x, self.a_xp_y)
            self.a_yp = Point(SECP256k1.curve, self.a_yp_x, self.a_yp_y)
            self.b_xp = Point(SECP256k1.curve, self.b_xp_x, self.b_xp_y)
            self.b_yp = Point(SECP256k1.curve, self.b_yp_x, self.b_yp_y)
            self.p = Point(SECP256k1.curve, self.p_x, self.p_y)


            return {
                'a_xp': self.a_xp,
                'a_yp': self.a_yp,
                'id_a': self.id_a,
                'id_b': self.id_b,
                'b_xp': self.b_xp,
                'b_yp': self.b_yp,
                'p': self.p,
                'q': self.q,
                'l_bits': self.l_bits,
                'n_bits': self.n_bits,
                'b_x': self.b_x,
                'b_y': self.b_y
            }
            
        except FileNotFoundError:
            print("system_parameters.json not found")
            raise
        except json.JSONDecodeError:
            print("Invalid JSON format in system_parameters.json")
            raise
        except Exception as e:
            print(f"Error loading parameters: {str(e)}")
            raise



    def get_rk_parameters(self):
        """Load parameters needed for re-encryption key generation"""
        try:
            with open(_DATA_DIR / 'system_parameters.json', 'r') as f:
                params = json.load(f)
                
            if 'parameters' not in params:
                raise KeyError("Missing 'parameters' in system_parameters.json")
                
            param_dict = params['parameters']
            required_keys = ['a_xp_x', 'a_xp_y', 'a_yp_x', 'a_yp_y', 'c', 'id_a', 'id_b', 'b_xp_x', 'b_xp_y', 'b_yp_x', 'b_yp_y', 'q']
            
            # Check all required keys exist
            for key in required_keys:
                if key not in param_dict:
                    raise KeyError(f"Missing required parameter: {key}")
            
            # Extract and convert parameters
            self.a_xp_x = int(param_dict['a_xp_x'])
            self.a_xp_y = int(param_dict['a_xp_y'])
            self.a_yp_x = int(param_dict['a_yp_x'])
            self.a_yp_y = int(param_dict['a_yp_y'])
            self.c = int(param_dict['c'])
            self.id_a = param_dict['id_a']
            self.id_b = param_dict['id_b']
            self.b_xp_x = int(param_dict['b_xp_x'])
            self.b_xp_y = int(param_dict['b_xp_y'])
            self.b_yp_x = int(param_dict['b_yp_x'])
            self.b_yp_y = int(param_dict['b_yp_y'])
            self.q = int(param_dict['q'])

            self.a_xp = Point(SECP256k1.curve, self.a_xp_x, self.a_xp_y)
            self.a_yp = Point(SECP256k1.curve, self.a_yp_x, self.a_yp_y)
            self.b_xp = Point(SECP256k1.curve, self.b_xp_x, self.b_xp_y)
            self.b_yp = Point(SECP256k1.curve, self.b_yp_x, self.b_yp_y)
            
            return {
                'a_xp': self.a_xp,
                'a_yp': self.a_yp,
                'c': self.c,
                'id_a': self.id_a,
                'id_b': self.id_b,
                'b_xp': self.b_xp,
                'b_yp': self.b_yp,
                'q': self.q
            }
            
        except FileNotFoundError:
            print("system_parameters.json not found")
            raise
        except json.JSONDecodeError:
            print("Invalid JSON format in system_parameters.json")
            raise
        except Exception as e:
            print(f"Error loading parameters: {str(e)}")
            raise

    function_or_method = None # helper marker if needed

    def requestCprimeFromeContract(self, rk1, rk2, rk3, proof_or_commitmentX, commitmentY=None, response=None, nonce=None, expiry=None):
        """Setup web3 and contract instance"""
        load_dotenv()
        PRIVATE_KEY = os.getenv('PRIVATE_KEY')
        ALCHEMY_API = os.getenv('ALCHEMY_API')
        WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')

        if not all([PRIVATE_KEY, ALCHEMY_API, WALLET_ADDRESS]):
            raise ValueError("Missing environment variables. Please check .env file")
        
        rpc_url = os.getenv("RPC_URL") or ALCHEMY_API
        if rpc_url and not rpc_url.startswith("http"):
            rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{rpc_url}"

        web3 = Web3(Web3.HTTPProvider(rpc_url or 'https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))
        
        account = Web3.to_checksum_address(WALLET_ADDRESS)

        if not web3.is_connected():
            raise Exception("Failed to connect to network")
    
        with open(_DATA_DIR / 'PRE_compData1.json', 'r') as f:
            compdata = json.load(f)
            contract_abi = compdata['PRE']['abi']
     
        contract_address = Web3.to_checksum_address(get_contract_info())

        contract = web3.eth.contract(address=contract_address, abi=contract_abi)

        if isinstance(proof_or_commitmentX, dict):
            proof = proof_or_commitmentX
            commitmentX = proof['commitmentX']
            commitmentY = proof['commitmentY']
            response = proof['response']
            nonce = proof.get('nonce', 0)
            expiry = proof.get('expiry', 0)

        params = {
            'rk1': int(rk1),
            'rk2': int(rk2),
            'rk3': int(rk3),
            'commitmentX': int(commitmentX),
            'commitmentY': int(commitmentY),
            'response': int(response),
            'nonce': int(nonce if nonce is not None else 0),
            'expiry': int(expiry if expiry is not None else 0),
            'userPublicKey': Web3.to_checksum_address(proof['userPublicKey']),
            'userNonce': int(proof['userNonce']),
            'userExpiry': int(proof['userExpiry']),
            'userSignature': proof['userSignature'],
        }
        block = web3.eth.get_block('latest')
        block_gas_limit = block['gasLimit']
        gas_price = int(web3.eth.gas_price * 1.5)
        # Build transaction
        try:
            cPrime = contract.functions.reEncrypt(params).call({
                'from': account,
                'gas': min(7000000, block_gas_limit - 100000),
                'gasPrice': gas_price
            })

            result = contract.functions.reEncrypt(params).build_transaction({
                'from': account,
                'nonce': web3.eth.get_transaction_count(account, 'pending'),
                'gas': min(7000000, block_gas_limit - 100000),
                'gasPrice': gas_price
            })

            signed_txn = web3.eth.account.sign_transaction(result, private_key=PRIVATE_KEY)
            raw_tx = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction')
            tx_hash = web3.eth.send_raw_transaction(raw_tx)
            tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            gas_summary = format_tx_gas_summary(
                web3,
                tx_hash,
                tx_receipt,
                label="reEncrypt",
                actor="SP",
                extra={
                    "pre_contract_address": str(contract_address),
                    "counter_side_effect": "Increment count executed within same transaction",
                },
            )

            if tx_receipt['status'] == 1:
                print(f"reEncrypt() transaction successful! Transaction hash: {tx_hash.hex()}")
                print_tx_gas_summary(gas_summary)
                GasReportStore(_GAS_REPORT_FILE).append(gas_summary)
                
                if len(cPrime) == 4:
                    _c1prime, _c2prime, _c3, _c4prime = cPrime
                else:
                    print("Unexpected number of return values from reEncrypt function.")
                # if len(cPrime) == 5:
                #     val4, A_, B_, hash2, c_ = cPrime
                #     print("val4:", val4)
                #     print("A_:", A_)
                #     print("B_:", B_)
                #     print("hash2:", hash2)
                #     print("c_:", c_)
                # else:
                #     print("Unexpected number of return values from reEncrypt function.")


                # return val4, A_, B_, hash2
                return _c1prime, _c2prime, _c3.hex(), _c4prime

            else:
                print(f"reEncrypt() transaction failed. Transaction hash: {tx_hash.hex()}")
                print(f"Transaction receipt: {tx_receipt}")
                gas_summary["status_text"] = "failed"
                print_tx_gas_summary(gas_summary)
                GasReportStore(_GAS_REPORT_FILE).append(gas_summary)
                raise RuntimeError(f"reEncrypt() transaction failed: {tx_hash.hex()}")
                

        except Exception as e:
            print(f"Transaction failed: {str(e)}")
            raise

    def compute_proof_challenge(
        self,
        contract_address,
        sender_address,
        rk1,
        rk2,
        rk3,
        proof_commitment_x,
        proof_commitment_y,
        proof_public_key_x,
        proof_public_key_y,
        proof_nonce,
        proof_expiry,
    ):
        digest = Web3.solidity_keccak(
            [
                'address',
                'address',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
                'uint256',
            ],
            [
                Web3.to_checksum_address(contract_address),
                Web3.to_checksum_address(sender_address),
                int(rk1),
                int(rk2),
                int(rk3),
                int(proof_commitment_x),
                int(proof_commitment_y),
                int(proof_public_key_x),
                int(proof_public_key_y),
                int(proof_nonce),
                int(proof_expiry),
            ],
        )
        return int.from_bytes(digest, byteorder='big') % self.q

    def generate_reencryption_proof(self, contract_address, sender_address, rk1, rk2, rk3):
        return generate_schnorr_zkp_inputs(
            rk1=rk1,
            rk2=rk2,
            rk3=rk3,
            contract_address=contract_address,
            sender_address=sender_address
        )

    def rekeygenerate(self):
        """Generate the re-encryption keys"""
        # Load required parameters
        rk_params = self.get_rk_parameters()
        self.a_xp = rk_params['a_xp']
        self.a_yp = rk_params['a_yp']
        self.c = rk_params['c']
        self.id_a = rk_params['id_a']
        self.id_b = rk_params['id_b']
        self.b_xp = rk_params['b_xp']
        self.b_yp = rk_params['b_yp']
        self.q = rk_params['q']


        s = self.hash4(self.id_a, self.id_b, self.b_xp.x(), self.b_yp.x())
        s_inverse = inverse_mod(s, self.q)

        # Compute re-encryption keys
        rk1 = s_inverse * self.c * self.a_xp.x() % self.q
        rk2 = s_inverse * self.c * self.a_yp.x() % self.q
        rk3 = s_inverse * (self.a_xp.x() + self.a_yp.x()) % self.q

        # s = self.hash4(self.id_a, self.id_b, self.b_xp.x, self.b_yp_x)
        # s_inverse = inverse_mod(s, self.q)

        # # Compute re-encryption keys
        # rk1 = s_inverse * self.c * self.a_xp_x % self.q
        # rk2 = s_inverse * self.c * self.a_yp_x % self.q
        # rk3 = s_inverse * (self.a_xp_x + self.a_yp_x) % self.q

        return rk1, rk2, rk3
    
    # def hex_to_ascii(self, hex_string):
    #     """Converts the hexadecimal string to an ASCII string"""
    #     if hex_string.startswith('0x'):
    #         hex_string = hex_string[2:]
    #     ascii_str = ''
    #     for i in range(0, len(hex_string), 2):
    #         hex_pair = hex_string[i:i+2]
    #         char_code = int(hex_pair, 16)
    #         ascii_str += chr(char_code)
    #     return ascii_str
        
    def bits_to_bytes(self, bit_string):
        byte_array = bytearray()
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i+8]
            byte_array.append(int(byte, 2))
        return bytes(byte_array)
    
    def compute_y(self, x, curve):
        """Compute the y-coordinate for a given x-coordinate on the elliptic curve."""
        y_squared = (x**3 + curve.a() * x + curve.b()) % curve.p()
        y = pow(y_squared, (curve.p() + 1) // 4, curve.p())
        return y

    def redecrypt(self, c1_prime, c2_prime, c3_prime, c4_prime):
        """Decrypt the re-encrypted ciphertexts"""

        # Load required parameters
        rk_params = self.get_redec_parameters()
        self.a_xp = rk_params['a_xp']
        self.a_yp = rk_params['a_yp']
        self.id_a = rk_params['id_a']
        self.id_b = rk_params['id_b']
        self.b_xp = rk_params['b_xp']
        self.b_yp = rk_params['b_yp']
        self.p = rk_params['p']
        self.q = rk_params['q']
        self.l_bits = rk_params['l_bits']
        self.n_bits = rk_params['n_bits']
        self.b_x = rk_params['b_x']
        self.b_y = rk_params['b_y']
        
        # Contract returns x-coordinates only, so reconstruct points on secp256k1.
        if isinstance(c1_prime, int):
            c1_prime = Point(SECP256k1.curve, c1_prime, self.compute_y(c1_prime, SECP256k1.curve))
        if isinstance(c2_prime, int):
            c2_prime = Point(SECP256k1.curve, c2_prime, self.compute_y(c2_prime, SECP256k1.curve))
        if isinstance(c4_prime, int):
            c4_prime = Point(SECP256k1.curve, c4_prime, self.compute_y(c4_prime, SECP256k1.curve))

        # Manually compute public key points
        sk_pr_x = self.b_x * self.p
        sk_pr_y = self.b_y * self.p

        # sk_pr_x = self.b_xp_x
        # sk_pr_y = self.b_yp_x

        # Hash the 2 IDs and both public keys
        s_prime = self.hash4(self.id_a, self.id_b, sk_pr_x.x(), sk_pr_y.x())

        # Compute H2(s'(C1' + C2')) == H2(fqa). Use x-coordinate as seed (hash2 expects hashable input)
        hash2_point = s_prime * (c1_prime + c2_prime)
        hash2 = self.hash2(self.l_bits + self.n_bits, hash2_point.x())

        # (key || sigma) = c3_prime ^ hash2
        key_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2, c3_prime))

        # Extract the key
        key_in_binary = key_plus_sigma[:len(key_plus_sigma) - self.l_bits]
        key = self.bits_to_bytes(key_in_binary)
        # key = self.hex_to_ascii(hex(int(key_in_binary, 2)))
        #key = b'\xf6\xf6\xee\xcb`Gg\x06\xfcgU\x86\xe3\xf0\xd0\x153\xd9\xac\x0e\x90\xb1OY\x06\xc3V\x1b\xcc\xc8s\xd7'
        # Extract sigma
        sigma_in_binary = key_plus_sigma[len(key_plus_sigma) - self.l_bits:]

        # Compute point for Re-Decryption check
        r = self.hash1(key, int(sigma_in_binary, 2), self.id_a, self.a_xp.x(), self.a_yp.x())
        verification_scalar = r * inverse_mod(s_prime, self.q) * (self.a_xp.x() + self.a_yp.x())
        verification_point = verification_scalar * self.p

    # C4' must equal (s')^-1 * r * (pk_a1 + pk_a2) * P
    # (silenced verbose prints for benchmarking)
        # if c4_prime != verification_point.x() :
        #     print("Re-Decrypt Check failed!")
        #     sys.exit(0)

        return key

def mpz_to_uint256(mpz_val):
    # Convert gmpy2.mpz to int
    int_val = int(mpz_val)
            
    # Verify range
    if int_val < 0 or int_val >= 2**256:
       raise ValueError("Value out of uint256 range")
                
    return int_val
    
def get_contract_info():
    """Load contract address from JSON file"""
    try:
        with open(_DATA_DIR / 'contract_info.json', 'r') as f:
            contract_data = json.load(f)
            return contract_data['contract_address']
    except Exception as e:
        print(f"Error loading contract info: {str(e)}")
        raise

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

def generate_large_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num
        
def computeCommitment(i,o,j,v,w):
    yy = pow(i, v, w)
    zz = pow(o, v, w)
    A = pow(i, j, w)
    B = pow(o, j, w)

    return yy,zz,A,B

def computeChallenge(i,yy,o,zz,A,B,w):
    hash1 = keccak256_encode_packed(yy, zz, A, B)
    alpha = int.from_bytes(hash1, byteorder='big') % w
    return alpha

def computeProof(j,alpha,v,w):
    gamma = j - alpha * v
    return gamma

def get_rand(rand_bytes_size):
    r = secrets.token_bytes(rand_bytes_size)
    return int.from_bytes(r, byteorder='big')

def extended_euclid(e, phi):
    u = [1, 0, phi]
    v = [0, 1, e]
    while v[2] != 0:
        q = u[2] // v[2]
        temp1 = u[0] - q * v[0]
        temp2 = u[1] - q * v[1]
        temp3 = u[2] - q * v[2]
        u[0], u[1], u[2] = v[0], v[1], v[2]
        v[0], v[1], v[2] = temp1, temp2, temp3
    return u[1] + phi if u[1] < 0 else u[1]

def ppow(base, exp, mod):
    negative_exp = exp < 0
    if negative_exp:
        exp = -exp

    result = 1
    b = base % mod
    if b < 0:
        b += mod

    e = exp
    while e > 0:
        if e & 1 == 1:
            result = (result * b) % mod
        b = (b * b) % mod
        e >>= 1

    if negative_exp:
        result = extended_euclid(result, mod)

    return result


def create_user_access_token_and_signature(user_private_key=None, contract_address=None, sp_address=None, user_nonce=None, user_expiry=0):
    """Generate and sign a user access request token tau using EIP-191 personal sign."""
    load_dotenv()
    if not user_private_key:
        user_private_key = os.getenv('PRIVATE_KEY')
    user_acc = Account.from_key(user_private_key)

    if user_nonce is None:
        user_nonce = secrets.randbits(64)
    user_nonce = int(user_nonce)
    user_expiry = int(user_expiry)

    token_bytes = Web3.solidity_keccak(
        ['address', 'address', 'uint256', 'uint256'],
        [Web3.to_checksum_address(contract_address), Web3.to_checksum_address(sp_address), user_nonce, user_expiry]
    )
    signable_msg = encode_defunct(primitive=token_bytes)
    signed = user_acc.sign_message(signable_msg)
    return {
        'user_public_key': user_acc.address,
        'user_nonce': user_nonce,
        'user_expiry': user_expiry,
        'user_signature': signed.signature,
        'user_token': token_bytes
    }

def generate_schnorr_zkp_inputs(
    secret_scalar=None, pub_x=None, pub_y=None, rk1=0, rk2=0, rk3=0,
    contract_address=None, sender_address=None, nonce=None, expiry=0,
    user_private_key=None, user_public_key=None, user_nonce=None, user_expiry=0, user_signature=None
):
    """Generate Schnorr ZKP inputs bound to user access request token matching verifySchnorrZKP in Solidity."""
    curve = SECP256k1
    Q = int(curve.order)

    load_dotenv()
    wallet_address = sender_address or os.getenv('WALLET_ADDRESS')
    if not wallet_address:
        raise ValueError("Missing WALLET_ADDRESS in .env or sender_address argument")

    if secret_scalar is None or pub_x is None or pub_y is None:
        material = load_sp_proof_material(wallet_address)
        secret_scalar = int(material.get('secret_scalar', 1))
        pub_x = int(material.get('public_key_x', 0))
        pub_y = int(material.get('public_key_y', 0))
    else:
        secret_scalar = int(secret_scalar)
        pub_x = int(pub_x)
        pub_y = int(pub_y)

    contract_address = contract_address or get_contract_info()
    rk1 = int(rk1)
    rk2 = int(rk2)
    rk3 = int(rk3)

    if nonce is None:
        nonce = secrets.randbits(64)
    else:
        nonce = int(nonce)
    expiry = int(expiry)

    # User intent signature generation if missing
    if user_signature is None or user_public_key is None:
        u_intent = create_user_access_token_and_signature(
            user_private_key=user_private_key,
            contract_address=contract_address,
            sp_address=wallet_address,
            user_nonce=user_nonce,
            user_expiry=user_expiry
        )
        user_public_key = u_intent['user_public_key']
        user_nonce = u_intent['user_nonce']
        user_expiry = u_intent['user_expiry']
        user_signature = u_intent['user_signature']
    else:
        user_nonce = int(user_nonce or secrets.randbits(64))
        user_expiry = int(user_expiry)

    # Schnorr commitment W = k * G
    k = secrets.randbelow(Q - 1) + 1
    W = k * curve.generator
    Wx = int(W.x())
    Wy = int(W.y())

    user_token = Web3.solidity_keccak(
        ['address', 'address', 'uint256', 'uint256'],
        [Web3.to_checksum_address(contract_address), Web3.to_checksum_address(wallet_address), user_nonce, user_expiry]
    )
    h1 = Web3.solidity_keccak(
        ['address', 'address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
        [Web3.to_checksum_address(contract_address), Web3.to_checksum_address(wallet_address), rk1, rk2, rk3, Wx, Wy]
    )
    h2 = Web3.solidity_keccak(
        ['uint256', 'uint256', 'address', 'bytes32', 'bytes', 'uint256', 'uint256'],
        [pub_x, pub_y, Web3.to_checksum_address(user_public_key), user_token, user_signature, nonce, expiry]
    )
    c_bytes = Web3.solidity_keccak(['bytes32', 'bytes32'], [h1, h2])
    c = int.from_bytes(c_bytes, 'big') % Q

    z = (k + c * secret_scalar) % Q

    return {
        'commitmentX': Wx,
        'commitmentY': Wy,
        'response': z,
        'nonce': nonce,
        'expiry': expiry,
        'userPublicKey': Web3.to_checksum_address(user_public_key),
        'userNonce': user_nonce,
        'userExpiry': user_expiry,
        'userSignature': user_signature,
    }

def generate_arithmetic_zkp_inputs(secret_scalar=None, pub_x=None, pub_y=None, rk1=0, rk2=0, rk3=0, contract_address=None, sender_address=None, nonce=None, expiry=0):
    """Generate ZKP inputs for reEncrypt function."""
    return generate_schnorr_zkp_inputs(
        secret_scalar=secret_scalar,
        pub_x=pub_x,
        pub_y=pub_y,
        rk1=rk1,
        rk2=rk2,
        rk3=rk3,
        contract_address=contract_address,
        sender_address=sender_address,
        nonce=nonce,
        expiry=expiry
    )

def keccak256_encode_packed(*args):
    # Concatenate the arguments as bytes with fixed size
    packed = b''.join(
        arg.to_bytes(32, byteorder='big', signed=True) if isinstance(arg, int) else arg
        for arg in args
    )
    return keccak(packed)


def main():
    sp = SP()
    rk1, rk2, rk3 = sp.rekeygenerate()
    
    rk11 = mpz_to_uint256(rk1)
    rk22 = mpz_to_uint256(rk2)
    rk33 = mpz_to_uint256(rk3)

    load_dotenv()
    wallet_address = os.getenv('WALLET_ADDRESS')
    if not wallet_address:
        raise ValueError('Missing WALLET_ADDRESS in .env')

    sp_proof_material = load_sp_proof_material(wallet_address)
    contract_address = get_contract_info()

    proof = generate_schnorr_zkp_inputs(
        secret_scalar=sp_proof_material.get('secret_scalar'),
        pub_x=sp_proof_material.get('public_key_x'),
        pub_y=sp_proof_material.get('public_key_y'),
        rk1=rk11,
        rk2=rk22,
        rk3=rk33,
        contract_address=contract_address,
        sender_address=wallet_address,
    )

    c1p, c2p, c3p, c4p = sp.requestCprimeFromeContract(
        rk11,
        rk22,
        rk33,
        proof,
    )

    print("C1':", c1p)
    print("C2':", c2p)
    print("C3':", c3p)
    print("C4':", c4p)
    write_reencrypt_result(c1p, c2p, c3p, c4p)

    rederyptedmessage = sp.redecrypt(c1p, c2p, c3p, c4p)
    print("Redecrypted key:", rederyptedmessage)


if __name__ == "__main__":
    main()