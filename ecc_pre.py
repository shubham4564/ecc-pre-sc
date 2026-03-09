import random
import sys
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from eth_hash.auto import keccak

import hashlib
import random
from web3 import Web3


class EncryptedCommunication:
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

    def encrypt(self, message):
        """Encrypt the message to elliptic curve points"""
        # Compute C1 = r * p
        sigma = random.randint(0, 2 ** 128)
        r = self.hash1(message, sigma, self.id_a, self.a_xp.x(), self.a_yp.x())
        c1 = r * self.p

        # Compute C2 = skA^-1 * c * r * (pk_a1 + pk_a2) * P = skA^-1 * fqa
        f = self.c * r
        qa = (self.a_xp.x() + self.a_yp.x()) * self.p
        fqa = f * qa
        c2 = inverse_mod(self.a_x, self.q) * fqa

        # Convert the message into binary
        message_in_binary = self.message_to_binary(message)
        self.n_bits = len(message_in_binary)

        # Convert sigma into binary
        sigma_in_binary = bin(sigma)[2:].zfill(self.l_bits)

        # Concatenate the message and sigma
        message_plus_sigma = message_in_binary + sigma_in_binary

        # Compute H2(fqa)
        hashed_fqa = self.hash2(self.l_bits + self.n_bits, fqa.x())

        # C3 = (message || sigma) ^ H2(fqa)
        c3 = ''.join(str(int(a) ^ int(b)) for a, b in zip(message_plus_sigma, hashed_fqa))

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

        # (message || sigma) = c3_prime ^ hash2
        message_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(c3, hash2))

        # Extract the message
        # message_in_binary = message_plus_sigma[:-self.l_bits]
        message_in_binary = message_plus_sigma[:len(message_plus_sigma) - self.l_bits]
        message = self.hex_to_ascii(hex(int(message_in_binary, 2)))

        # Extract sigma
        # sigma_in_binary = message_plus_sigma[-self.l_bits:]
        sigma_in_binary = message_plus_sigma[len(message_plus_sigma) - self.l_bits:]

        # Compute point for Decryption check
        r = self.hash1(message, int(sigma_in_binary, 2), self.id_a, self.a_xp.x(), self.a_yp.x())
        added_points = self.a_xp.x() + self.a_yp.x()
        qa = added_points * self.p
        verification_point_2 = inverse_mod(self.a_x, self.q) * self.c * r * qa

        # C2 must equal skA^-1 * c * r * (pk_a1 + pk_a2) * P
        if c2.x() != verification_point_2.x():
            print("Decrypt Check 2 failed!")
            sys.exit(0)

        return message

    def rekeygenerate(self):
        """Generate the re-encryption keys"""
        s = self.hash4(self.id_a, self.id_b, self.b_xp.x(), self.b_yp.x())
        s_inverse = inverse_mod(s, self.q)

        # Compute re-encryption keys
        rk1 = s_inverse * self.c * self.a_xp.x() % self.q
        rk2 = s_inverse * self.c * self.a_yp.x() % self.q
        rk3 = s_inverse * (self.a_xp.x() + self.a_yp.x()) % self.q

        return rk1, rk2, rk3

    def reencrypt(self, rk1, rk2, rk3, c1, c2, c3, c4, c5):
        """Re-encrypt the ciphertexts with the re-encryption keys"""
        # Compute points for Re-Encryption check
        c5p = c5 * self.p
        hash3 = self.hash3(c1.x(), c2.x(), c3, c4.x())
        temp = hash3 * c2
        verification_point = c4 + temp

        # C5 * P must equal C4 + H3(C1, C2, C3, C4) * C2
        if c5p.x() != verification_point.x():
            print("Re-Encrypt Check 1 failed!")
            sys.exit(0)

        # Compute re-encrypted ciphertexts
        c1_prime = c1 * rk1
        c2_prime = c1 * rk2
        c3_prime = c3
        c4_prime = c1 * rk3

        return c1_prime, c2_prime, c3_prime, c4_prime

    def redecrypt(self, c1_prime, c2_prime, c3_prime, c4_prime):
        """Decrypt the re-encrypted ciphertexts"""
        # Manually compute public key points
        sk_pr_x = self.b_x * self.p
        sk_pr_y = self.b_y * self.p

        # Hash the 2 IDs and both public keys
        s_prime = self.hash4(self.id_a, self.id_b, sk_pr_x.x(), sk_pr_y.x())

        # Compute H2(s'(C1' + C2')) == H2(fqa)
        hash2_input = s_prime * (c1_prime + c2_prime)
        hash2 = self.hash2(self.l_bits + self.n_bits, hash2_input.x())

        # (message || sigma) = c3_prime ^ hash2
        message_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2, c3_prime))

        # Extract the message
        message_in_binary = message_plus_sigma[:len(message_plus_sigma) - self.l_bits]

        message = self.hex_to_ascii(hex(int(message_in_binary, 2)))

        # Extract sigma
        sigma_in_binary = message_plus_sigma[len(message_plus_sigma) - self.l_bits:]

        # Compute point for Re-Decryption check
        r = self.hash1(message, int(sigma_in_binary, 2), self.id_a, self.a_xp.x(), self.a_yp.x())
        verification_scalar = r * inverse_mod(s_prime, self.q) * (self.a_xp.x() + self.a_yp.x())
        verification_point = verification_scalar * self.p

        # C4' must equal (s')^-1 * r * (pk_a1 + pk_a2) * P
        if c4_prime.x() != verification_point.x() :
            print("Re-Decrypt Check failed!")
            sys.exit(0)

        return message




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

def mpz_to_uint256(mpz_val):
    # Convert gmpy2.mpz to int
    int_val = int(mpz_val)
        
    # Verify range
    if int_val < 0 or int_val >= 2**256:
        raise ValueError("Value out of uint256 range")
            
    return int_val


def main():
    """Encrypt, decrypt, re-encrypt, and re-decrypt a message"""
    message = input("Enter a message to encrypt: ")
    address = input("Enter a Solidity address in hex: ")

    ec = EncryptedCommunication()

    ec.key_generate()
    c1, c2, c3, c4, c5 = ec.encrypt(message)

    print("\nDecrypted Message:", ec.decrypt(c1, c2, c3, c4, c5), "\n")

    rk1, rk2, rk3 = ec.rekeygenerate()
    c5p = c5 * ec.p

    print("C1 x:", c1.x())
    print("C1 y:", c1.y())
    print("C2 x:", c2.x())
    print("C2 y:", c2.y())
    print("C3:", '"0x' + c3 + '"')
    print("C4 x:", c4.x())
    print("C4 y:", c4.y(), "\n")

    prefix_c1 = ec.get_prefix(c1.x(), c1.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    prefix_c2 = ec.get_prefix(c2.x(), c2.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    prefix_c4 = ec.get_prefix(c4.x(), c4.y(), 0x0, 0x7, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    full_parity = f"0x{prefix_c1:02x}{prefix_c2:02x}{prefix_c4:02x}"

    print("C5 times P:", c5p.x())
    print("Address Hash:","[\"0x" + str(keccak256_hex(address)) + "\"]")
    print("Parity:", full_parity, "\n")



    c1_prime_py, c2_prime_py, c3_prime_py, c4_prime_py = ec.reencrypt(rk1, rk2, rk3, c1, c2, c3, c4, c5)
    
    rk11 = mpz_to_uint256(rk1)
    rk22 = mpz_to_uint256(rk2)
    rk33 = mpz_to_uint256(rk3)

    print("RK1py:", rk1)
    print("RK1:", rk11)
    print("RK2py:", rk2)
    print("RK2:", rk22)    
    print("RK3py:", rk3)   
    print("RK3:", rk33, "\n")     



    
    print("C'1py:", c1_prime_py.x())
    print("C'2py:", c2_prime_py.x())
    print("C'3py:", c3_prime_py)
    print("C'4py:", c4_prime_py.x(), "\n")

    # Connect to Ethereum node (e.g., Ganache or Infura)
    web3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6TCy-aXdMGmNp80ebxCB9CdETCjCgdV5'))


    # Contract ABI and address (replace with your contract's ABI and address)
    contract_abi = [
        {
            "inputs": [],
            "name": "getChallenge",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_rk1",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_rk2",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_rk3",
                    "type": "uint256"
                }
            ],
            "name": "reEncrypt",
            "outputs": [
                {
                    "components": [
                        {
                            "internalType": "uint256",
                            "name": "c1prime",
                            "type": "uint256"
                        },
                        {
                            "internalType": "uint256",
                            "name": "c2prime",
                            "type": "uint256"
                        },
                        {
                            "internalType": "bytes",
                            "name": "c3",
                            "type": "bytes"
                        },
                        {
                            "internalType": "uint256",
                            "name": "c4prime",
                            "type": "uint256"
                        }
                    ],
                    "internalType": "struct PRE.ReEncryptionResult",
                    "name": "",
                    "type": "tuple"
                }
            ],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "countingContract",
            "outputs": [
                {
                    "internalType": "contract Counter",
                    "name": "",
                    "type": "address"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]




    contract_address = '0xbc217Fa3294Bc4345Bba28cDA141D6DB033cb181'  # Replace with your contract's address

    # Create contract instance
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)


    def clean_bytes(byte_data):
        # Plan:
        # 1. Convert bytes to hex string
        # 2. Remove b' prefix and \x
        # 3. Convert back to bytes
        
        # Convert to hex
        hex_str = byte_data.hex()
        
        # Convert hex pairs back to bytes
        cleaned_bytes = bytes.fromhex(hex_str)
        
        return cleaned_bytes


    try:
        result = contract.functions.reEncrypt(rk11, rk22, rk33).call()
        
        # Extract returned values
        c1prime = result[0]  # First element is c1prime
        c2prime = result[1]  # Second element is c2prime
        c3prime = result[2]      # Third element is c3
        c4prime = result[3]  # Fourth element is c4prime
        print(f"c1prime: {type(c1prime)}")
        print(f"c2prime: {type(c2prime)}")
        print(f"c3: {type(c3prime)}")   
        print(f"c4prime: {type(c4prime)}")
        
        print(f"Re-encryption results:")
        # if(mpz_to_uint256(c1_prime_py.x()) == c1prime):
        print(f"c1prime: {c1prime}")
        
        
        # if(mpz_to_uint256(c2_prime_py.x()) == c2prime):
        print(f"c2prime: {c2prime}")

        c3prime = clean_bytes(c3prime)
        # if(mpz_to_uint256(c3_prime_py) == c3prime):
        print(f"c3: {c3prime}")

        
        # if(mpz_to_uint256(c4_prime_py.x()) == c4prime):
        print(f"c4prime: {c4prime}")

        print("Re-Decrypted Message:", ec.redecrypt(c1prime, c2prime, c3prime, c4prime))
    except Exception as e:
        print(f"Error calling result: {e}")

    #print("Expected Output of ECC-PRE Contract:", c1_prime.x(),",",c2_prime.x(),",",c3_prime,",",c4_prime.x())
    # print("C1':", c1_prime_py.x())
    # print("C2':", c2_prime_py.x())
    # print("C3':", c3_prime_py)
    # print("C4':", c4_prime_py.x(), "\n")

if __name__ == "__main__":
    main()
