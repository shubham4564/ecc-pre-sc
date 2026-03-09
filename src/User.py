import TTP
import json
import sys
from pathlib import Path
from ecdsa.numbertheory import inverse_mod
import SP
from cryptography.fernet import Fernet
import base64
import subprocess

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_ROOT     = Path(__file__).resolve().parent.parent
_SRC_DIR  = Path(__file__).resolve().parent
_DATA_DIR = _ROOT / "data"


class User:
    ttp = TTP.TTP()
    hash1 = ttp.hash1
    hash2 = ttp.hash2
    hash4 = ttp.hash4

    def get_redec_parameters(self):
        """Load parameters needed for re-decryption"""
        try:
            with open(_DATA_DIR / 'system_parameters.json', 'r') as f:
                params = json.load(f)
                
            if 'parameters' not in params:
                raise KeyError("Missing 'parameters' in system_parameters.json")
                
            param_dict = params['parameters']
            required_keys = ['a_xp_x', 'a_yp_x', 'id_a', 'id_b', 'b_xp_x', 'b_yp_x', 'p_x', 'q', 'l_bits', 'n_bits']
            
            # Check all required keys exist
            for key in required_keys:
                if key not in param_dict:
                    raise KeyError(f"Missing required parameter: {key}")
            
            # Extract and convert parameters
            self.a_xp_x = int(param_dict['a_xp_x'])
            self.a_yp_x = int(param_dict['a_yp_x'])
            self.id_a = param_dict['id_a']
            self.id_b = param_dict['id_b']
            self.b_xp_x = int(param_dict['b_xp_x'])
            self.b_yp_x = int(param_dict['b_yp_x'])
            self.p_x = int(param_dict['p_x'])
            self.q = int(param_dict['q'])
            self.l_bits = int(param_dict['l_bits'])
            self.n_bits = int(param_dict['n_bits'])


            return {
                'a_xp_x': self.a_xp_x,
                'a_yp_x': self.a_yp_x,
                'id_a': self.id_a,
                'id_b': self.id_b,
                'b_xp_x': self.b_xp_x,
                'b_yp_x': self.b_yp_x,
                'p_x': self.p_x,
                'q': self.q,
                'l_bits': self.l_bits,
                'n_bits': self.n_bits
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

    def decrypt_content(encrypted_content, key):
        """Decrypts a message using the provided symmetric key."""
        try:
            f = Fernet(key)
            decoded_content = base64.b64decode(encrypted_content.encode()) # Decode from base64
            decrypted_content = f.decrypt(decoded_content).decode() # Decode from bytes
            return decrypted_content
        except Exception as e: # Catch potential decryption errors (e.g., incorrect key)
            print(f"Decryption error: {e}")
            return None  # Or raise the exception if you prefer

    def redecrypt(self, c1_prime, c2_prime, c3_prime, c4_prime):
        """Decrypt the re-encrypted ciphertexts"""

        # Load required parameters
        rk_params = self.get_redec_parameters()
        self.a_xp_x = rk_params['a_xp_x']
        self.a_yp_x = rk_params['a_yp_x']
        self.id_a = rk_params['id_a']
        self.id_b = rk_params['id_b']
        self.b_xp_x = rk_params['b_xp_x']
        self.b_yp_x = rk_params['b_yp_x']
        self.p_x = rk_params['p_x']
        self.q = rk_params['q']
        self.l_bits = rk_params['l_bits']
        self.n_bits = rk_params['n_bits']
        
        
        # Manually compute public key points
        sk_pr_x = self.b_xp_x
        sk_pr_y = self.b_yp_x

        # Hash the 2 IDs and both public keys
        s_prime = self.hash4(self.id_a, self.id_b, sk_pr_x, sk_pr_y)

        # Compute H2(s'(C1' + C2')) == H2(fqa)
        hash2_input = s_prime * (c1_prime + c2_prime)
        hash2 = self.hash2(self.l_bits + self.n_bits, hash2_input)

        # (message || sigma) = c3_prime ^ hash2
        message_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2, c3_prime))

        # Extract the message
        message_in_binary = message_plus_sigma[:len(message_plus_sigma) - self.l_bits]

        message = self.hex_to_ascii(hex(int(message_in_binary, 2)))

        # Extract sigma
        sigma_in_binary = message_plus_sigma[len(message_plus_sigma) - self.l_bits:]

        # Compute point for Re-Decryption check
        r = self.hash1(message, int(sigma_in_binary, 2), self.id_a, self.a_xp_x, self.a_yp_x)
        verification_scalar = r * inverse_mod(s_prime, self.q) * (self.a_xp_x + self.a_yp_x)
        verification_point = verification_scalar * self.p_x

        # C4' must equal (s')^-1 * r * (pk_a1 + pk_a2) * P
        # if c4_prime != verification_point :
        #     print("Re-Decrypt Check failed!")
        #     sys.exit(0)

        return message

    def reqReEncContentKey(self):
        """Invoke SP.py and retrieve c1p, c2p, c3p, c4p"""
        result = subprocess.run(['python', str(_SRC_DIR / 'SP.py')], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error invoking SP.py: {result.stderr}")
            return None, None, None, None
        output = result.stdout.strip().split('\n')
        c1p, c2p, c3p, c4p = output[-4], output[-3], output[-2], output[-1]
        return c1p, c2p, c3p, c4p

    def reqEncContent(self):
        """Read content of encryptedcontent file"""
        try:
            with open(_ROOT / 'encryptedcontent', 'r') as f:
                enccontent = f.read()
            return enccontent
        except FileNotFoundError:
            print("encryptedcontent file not found")
            return None
        except Exception as e:
            print(f"Error reading encryptedcontent file: {e}")
            return None


def main():

    u = User()
    sp = SP()

  