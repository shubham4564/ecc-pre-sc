import TTP
import json
from pathlib import Path
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from cryptography.fernet import Fernet
import base64

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_ROOT     = Path(__file__).resolve().parent.parent
_SRC_DIR  = Path(__file__).resolve().parent
_DATA_DIR = _ROOT / "data"

class HardwareDRMSimulator:
    """
    Simulates a Hardware Trusted Execution Environment (TEE).
    This class isolates the decryption pipeline so that the untrusted OS
    never gains access to the raw symmetric key or the plaintext content.
    """
    hash1 = staticmethod(TTP.hash1)
    hash2 = staticmethod(TTP.hash2)
    hash4 = staticmethod(TTP.hash4)

    def __init__(self):
        # Initialize enclave-specific properties if any
        pass

    def _bits_to_bytes(self, bit_string):
        byte_array = bytearray()
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i+8]
            byte_array.append(int(byte, 2))
        return bytes(byte_array)

    def _compute_y(self, x, curve):
        """Compute the y-coordinate for a given x-coordinate on the elliptic curve."""
        y_squared = (x**3 + curve.a() * x + curve.b()) % curve.p()
        y = pow(y_squared, (curve.p() + 1) // 4, curve.p())
        return y

    def _get_redec_parameters(self):
        """Load parameters needed for re-decryption. 
        In a real TEE, these might be securely injected or provisioned."""
        try:
            with open(_DATA_DIR / 'system_parameters.json', 'r') as f:
                params = json.load(f)
                
            if 'parameters' not in params:
                raise KeyError("Missing 'parameters' in system_parameters.json")
                
            param_dict = params['parameters']
            required_keys = [
                'a_xp_x', 'a_xp_y',
                'a_yp_x', 'a_yp_y',
                'id_a', 'id_b',
                'b_xp_x', 'b_xp_y',
                'b_yp_x', 'b_yp_y',
                'p_x', 'p_y',
                'q', 'l_bits', 'n_bits',
                'b_x', 'b_y'
            ]
            
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
            
        except Exception as e:
            print(f"[TEE] Error loading parameters: {str(e)}")
            raise

    def _redecrypt(self, c1_prime, c2_prime, c3_prime, c4_prime):
        """Decrypt the re-encrypted ciphertexts internally inside the enclave."""
        rk_params = self._get_redec_parameters()
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
        
        if isinstance(c1_prime, int):
            c1_prime = Point(SECP256k1.curve, c1_prime, self._compute_y(c1_prime, SECP256k1.curve))
        if isinstance(c2_prime, int):
            c2_prime = Point(SECP256k1.curve, c2_prime, self._compute_y(c2_prime, SECP256k1.curve))
        if isinstance(c4_prime, int):
            c4_prime = Point(SECP256k1.curve, c4_prime, self._compute_y(c4_prime, SECP256k1.curve))

        sk_pr_x = self.b_x * self.p
        sk_pr_y = self.b_y * self.p

        s_prime = self.hash4(self.id_a, self.id_b, sk_pr_x.x(), sk_pr_y.x())

        hash2_input = s_prime * (c1_prime + c2_prime)
        hash2 = self.hash2(self.l_bits + self.n_bits, hash2_input.x())

        key_plus_sigma = ''.join(str(int(a) ^ int(b)) for a, b in zip(hash2, c3_prime))

        key_in_binary = key_plus_sigma[:len(key_plus_sigma) - self.l_bits]
        key = self._bits_to_bytes(key_in_binary)

        sigma_in_binary = key_plus_sigma[len(key_plus_sigma) - self.l_bits:]

        r = self.hash1(key, int(sigma_in_binary, 2), self.id_a, self.a_xp.x(), self.a_yp.x())
        verification_scalar = r * inverse_mod(s_prime, self.q) * (self.a_xp.x() + self.a_yp.x())
        verification_point = verification_scalar * self.p

        return key

    def _decrypt_content(self, encrypted_content, key):
        """Decrypts a message using the provided symmetric key internally."""
        try:
            key_padded = key.ljust(32, b'\0') if len(key) < 32 else key[:32]
            base64_key = base64.urlsafe_b64encode(key_padded)
            f = Fernet(base64_key)
            decoded_content = base64.b64decode(encrypted_content.encode())
            decrypted_content = f.decrypt(decoded_content).decode()
            return decrypted_content
        except Exception as e:
            import traceback; traceback.print_exc(); print(f"[TEE] Decryption error: {e}")
            return None

    def secure_consume(self, c1_prime, c2_prime, c3_prime, c4_prime, encrypted_content):
        """
        Public method exposed to the Untrusted OS.
        Takes the encrypted artifacts and securely renders the content.
        Does NOT return the key or the plaintext content.
        """
        print("[TEE] Enclave activated. Performing secure re-decryption...")
        recovered_key = self._redecrypt(c1_prime, c2_prime, c3_prime, c4_prime)
        
        if not recovered_key:
            print("[TEE] Failed to recover symmetric key.")
            return False

        print("[TEE] Key successfully recovered inside enclave (HIDDEN FROM OS).")
        
        print("[TEE] Decrypting content securely...")
        plaintext = self._decrypt_content(encrypted_content, recovered_key)

        if plaintext is None:
            print("[TEE] Failed to decrypt content.")
            return False

        # Simulate rendering to a secure display
        print("-" * 50)
        print("[SECURE DISPLAY BUFFER]")
        print("Rendering content...")
        print(f"--> {plaintext}")
        print("-" * 50)
        print("[TEE] Secure rendering complete. Wiping memory and exiting enclave.")
        
        # In python variables are garbage collected, but we can explicitly delete them
        # to simulate memory wiping of sensitive data.
        del recovered_key
        del plaintext
        
        return True
