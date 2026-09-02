import json
from pathlib import Path
from SecureEnclave import HardwareDRMSimulator

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_ROOT     = Path(__file__).resolve().parent.parent
_SRC_DIR  = Path(__file__).resolve().parent
_DATA_DIR = _ROOT / "data"

class User:
    def reqReEncContentKey(self):
        """Read structured re-encryption outputs produced by SP.py."""
        try:
            with open(_DATA_DIR / 'reencrypt_result.json', 'r') as f:
                payload = json.load(f)
            return payload['c1_prime'], payload['c2_prime'], payload['c3_prime'], payload['c4_prime']
        except Exception as e:
            print(f"Error reading reencrypt result: {e}")
            return None, None, None, None

    def reqEncContent(self):
        """Read encrypted content artifact produced by CODeployment."""
        try:
            with open(_DATA_DIR / 'encrypted_content.json', 'r') as f:
                payload = json.load(f)
            return payload['encrypted_content']
        except FileNotFoundError:
            print("encrypted_content.json not found")
            return None
        except Exception as e:
            print(f"Error reading encrypted content artifact: {e}")
            return None

def main():
    u = User()
    print("[Untrusted OS] Fetching encrypted content from SP...")
    encrypted_content = u.reqEncContent()
    if encrypted_content is None:
        print("Encrypted content is unavailable. Run CODeployment.py first.")
        return

    print("[Untrusted OS] Fetching re-encrypted key from Smart Contract...")
    c1p, c2p, c3p, c4p = u.reqReEncContentKey()
    if None in (c1p, c2p, c3p, c4p):
        print("Re-encrypted key material is unavailable. Run SP.py successfully first.")
        return

    print("[Untrusted OS] Encrypted artifacts obtained.")
    print("[Untrusted OS] NOTE: We cannot decrypt these natively. Passing them to the Secure Enclave (TEE)...")
    
    # Initialize the Trusted Execution Environment simulator
    enclave = HardwareDRMSimulator()
    
    # Pass encrypted artifacts to the enclave.
    # The enclave consumes them securely and never returns the raw key or plaintext.
    success = enclave.secure_consume(c1p, c2p, c3p, c4p, encrypted_content)
    
    if success:
        print("[Untrusted OS] Secure Enclave finished rendering the content successfully.")
    else:
        print("[Untrusted OS] Secure Enclave reported a failure.")

if __name__ == "__main__":
    main()
