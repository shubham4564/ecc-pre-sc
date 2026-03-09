import random
import sys
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak

import hashlib
import random
from web3 import Web3


class TTP:
    """Class containing all our cryptographic valuess and functions"""
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

    def compute_y_squared(self, x, a, b, p):
        """Computes the y squared value"""
        x2 = (x * x) % p
        x3 = (x2 * x) % p
        y2 = (x3 + a *  x + b) % p
        return y2

    def get_prefix(self, x, y, a, b, p):
        """Computes the parity for the x and y values"""
        y2_computed = self.compute_y_squared(x, a, b, p)
        y2 = (y * y) % p

        if y2 == y2_computed:
            if y % 2 == 0:
                return 0x02
            return 0x03
        raise ValueError("Something terrible happened!")

    def hash1(self, message, sigma, id_a, pk_a1, pk_a2):
        """Implementation of the hash 1 function"""
        mega_string = str(message) + str(sigma) + str(id_a) + str(pk_a1) + str(pk_a2)
        hash_bytes = keccak(mega_string.encode())
        return int.from_bytes(hash_bytes, byteorder='big') % self.q

    def hash2(self, n, seed_value):
        """Implementation of the hash 2 function"""
        hash_value = hash((n, seed_value))
        result = hash_value & ((1 << n) - 1)
        if result < (1 << (n - 1)):
            result += (1 << (n - 1))
        return bin(result)[2:]

    def hash3(self, c1, c2, c3, c4):
        """Implementation of the hash 3 function"""
        mega_string = hex(c1)[2:] + hex(c2)[2:] + str(c3) + hex(c4)[2:]
        if len(mega_string) % 2 != 0:
            mega_string = mega_string[:-1]
        mega_bytes = bytes.fromhex(mega_string)
        hash_bytes = keccak(mega_bytes)
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        hash_mod = hash_int % self.q
        return hash_mod

    def hash4(self, id_a, id_b, pk_b1_x, pk_b1_y):
        """Implementation of the hash 4 function"""
        mega_string = str(id_a) + str(id_b) + str(pk_b1_x) + str(pk_b1_y)
        hash_bytes = keccak(mega_string.encode())
        return int.from_bytes(hash_bytes, byteorder='big') % self.q

    def message_to_binary(self, message):
        """Converts the message to proper binary"""
        utf8_bytes = message.encode('utf-8')
        binary_string = ''.join(format(byte, '08b') for byte in utf8_bytes)
        return binary_string

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

    def key_generate(self):
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


# def main():
#     """Encrypt, decrypt, re-encrypt, and re-decrypt a message"""
#     message = input("Enter a message to encrypt: ")
#     address = input("Enter a Solidity address in hex: ")

#     ec = EncryptedCommunication()

#     ec.key_generate()
#     c1, c2, c3, c4, c5 = ec.encrypt(message)

#     print("\nDecrypted Message:", ec.decrypt(c1, c2, c3, c4, c5), "\n")

#     rk1, rk2, rk3 = ec.rekeygenerate()
#     c5p = c5 * ec.p

#     print("C1 x:", c1.x())
#     print("C1 y:", c1.y())
#     print("C2 x:", c2.x())
#     print("C2 y:", c2.y())
#     print("C3:", '"0x' + c3 + '"')
#     print("C4 x:", c4.x())
#     print("C4 y:", c4.y(), "\n")

#     prefix_c1 = ec.get_prefix(c1.x(), c1.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
#     prefix_c2 = ec.get_prefix(c2.x(), c2.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
#     prefix_c4 = ec.get_prefix(c4.x(), c4.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
#     full_parity = f"0x{prefix_c1:02x}{prefix_c2:02x}{prefix_c4:02x}"

#     print("C5 times P:", c5p.x())
#     print("Address Hash:","[\"0x" + str(keccak256_hex(address)) + "\"]")
#     print("Parity:", full_parity, "\n")



#     c1_prime_py, c2_prime_py, c3_prime_py, c4_prime_py = ec.reencrypt(rk1, rk2, rk3, c1, c2, c3, c4, c5)
    
#     rk11 = mpz_to_uint256(rk1)
#     rk22 = mpz_to_uint256(rk2)
#     rk33 = mpz_to_uint256(rk3)

#     print("RK1py:", rk1)
#     print("RK1:", rk11)
#     print("RK2py:", rk2)
#     print("RK2:", rk22)    
#     print("RK3py:", rk3)   
#     print("RK3:", rk33, "\n")     



    
#     print("C'1py:", c1_prime_py.x())
#     print("C'2py:", c2_prime_py.x())
#     print("C'3py:", c3_prime_py)
#     print("C'4py:", c4_prime_py.x(), "\n")

#     # Connect to Ethereum node (e.g., Ganache or Infura)
#     web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))


#     # Contract ABI and address (replace with your contract's ABI and address)
#     contract_abi = [
#         {
#             "inputs": [],
#             "name": "getChallenge",
#             "outputs": [
#                 {
#                     "internalType": "uint256",
#                     "name": "",
#                     "type": "uint256"
#                 }
#             ],
#             "stateMutability": "nonpayable",
#             "type": "function"
#         },
#         {
#             "inputs": [
#                 {
#                     "internalType": "uint256",
#                     "name": "_rk1",
#                     "type": "uint256"
#                 },
#                 {
#                     "internalType": "uint256",
#                     "name": "_rk2",
#                     "type": "uint256"
#                 },
#                 {
#                     "internalType": "uint256",
#                     "name": "_rk3",
#                     "type": "uint256"
#                 }
#             ],
#             "name": "reEncrypt",
#             "outputs": [
#                 {
#                     "components": [
#                         {
#                             "internalType": "uint256",
#                             "name": "c1prime",
#                             "type": "uint256"
#                         },
#                         {
#                             "internalType": "uint256",
#                             "name": "c2prime",
#                             "type": "uint256"
#                         },
#                         {
#                             "internalType": "bytes",
#                             "name": "c3",
#                             "type": "bytes"
#                         },
#                         {
#                             "internalType": "uint256",
#                             "name": "c4prime",
#                             "type": "uint256"
#                         }
#                     ],
#                     "internalType": "struct PRE.ReEncryptionResult",
#                     "name": "",
#                     "type": "tuple"
#                 }
#             ],
#             "stateMutability": "nonpayable",
#             "type": "function"
#         },
#         {
#             "inputs": [],
#             "name": "countingContract",
#             "outputs": [
#                 {
#                     "internalType": "contract Counter",
#                     "name": "",
#                     "type": "address"
#                 }
#             ],
#             "stateMutability": "view",
#             "type": "function"
#         }
#     ]




#     contract_address = '0xbc217Fa3294Bc4345Bba28cDA141D6DB033cb181'  # Replace with your contract's address

#     # Create contract instance
#     contract = web3.eth.contract(address=contract_address, abi=contract_abi)


#     def clean_bytes(byte_data):
#         # Plan:
#         # 1. Convert bytes to hex string
#         # 2. Remove b' prefix and \x
#         # 3. Convert back to bytes
        
#         # Convert to hex
#         hex_str = byte_data.hex()
        
#         # Convert hex pairs back to bytes
#         cleaned_bytes = bytes.fromhex(hex_str)
        
#         return cleaned_bytes


#     try:
#         result = contract.functions.reEncrypt(rk11, rk22, rk33).call()
        
#         # Extract returned values
#         c1prime = result[0]  # First element is c1prime
#         c2prime = result[1]  # Second element is c2prime
#         c3prime = result[2]      # Third element is c3
#         c4prime = result[3]  # Fourth element is c4prime
#         print(f"c1prime: {type(c1prime)}")
#         print(f"c2prime: {type(c2prime)}")
#         print(f"c3: {type(c3prime)}")   
#         print(f"c4prime: {type(c4prime)}")
        
#         print(f"Re-encryption results:")
#         # if(mpz_to_uint256(c1_prime_py.x()) == c1prime):
#         print(f"c1prime: {c1prime}")
        
        
#         # if(mpz_to_uint256(c2_prime_py.x()) == c2prime):
#         print(f"c2prime: {c2prime}")

#         c3prime = clean_bytes(c3prime)
#         # if(mpz_to_uint256(c3_prime_py) == c3prime):
#         print(f"c3: {c3prime}")

        
#         # if(mpz_to_uint256(c4_prime_py.x()) == c4prime):
#         print(f"c4prime: {c4prime}")

#         print("Re-Decrypted Message:", ec.redecrypt(c1prime, c2prime, c3prime, c4prime))
#     except Exception as e:
#         print(f"Error calling result: {e}")

#     #print("Expected Output of ECC-PRE Contract:", c1_prime.x(),",",c2_prime.x(),",",c3_prime,",",c4_prime.x())
#     # print("C1':", c1_prime_py.x())
#     # print("C2':", c2_prime_py.x())
#     # print("C3':", c3_prime_py)
#     # print("C4':", c4_prime_py.x(), "\n")

# if __name__ == "__main__":
#     main()








# [
# 	{
# 		"inputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "_c1_x",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c1_y",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c2_x",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c2_y",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "bytes",
# 				"name": "_c3",
# 				"type": "bytes"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c4_x",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c4_y",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_c5_times_p",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "bytes32[]",
# 				"name": "_allowedAddresses",
# 				"type": "bytes32[]"
# 			}
# 		],
# 		"stateMutability": "nonpayable",
# 		"type": "constructor"
# 	},
# 	{
# 		"inputs": [],
# 		"name": "BETA",
# 		"outputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			}
# 		],
# 		"stateMutability": "view",
# 		"type": "function"
# 	},
# 	{
# 		"inputs": [],
# 		"name": "LAMBDA",
# 		"outputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			}
# 		],
# 		"stateMutability": "view",
# 		"type": "function"
# 	},
# 	{
# 		"inputs": [],
# 		"name": "NN",
# 		"outputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			}
# 		],
# 		"stateMutability": "view",
# 		"type": "function"
# 	},
# 	{
# 		"inputs": [],
# 		"name": "PP",
# 		"outputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			}
# 		],
# 		"stateMutability": "view",
# 		"type": "function"
# 	},
# 	{
# 		"inputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "_rk1",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_rk2",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "_rk3",
# 				"type": "uint256"
# 			}
# 		],
# 		"name": "ReEncrypt",
# 		"outputs": [
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			},
# 			{
# 				"internalType": "bytes",
# 				"name": "",
# 				"type": "bytes"
# 			},
# 			{
# 				"internalType": "uint256",
# 				"name": "",
# 				"type": "uint256"
# 			}
# 		],
# 		"stateMutability": "nonpayable",
# 		"type": "function"
# 	},
# 	{
# 		"inputs": [],
# 		"name": "countingContract",
# 		"outputs": [
# 			{
# 				"internalType": "contract Counter",
# 				"name": "",
# 				"type": "address"
# 			}
# 		],
# 		"stateMutability": "view",
# 		"type": "function"
# 	}
# ]