import random

class ZKPVerifier:
    def __init__(self):
        self._alpha = None
    
    def getalpha(self):
        """Generates and stores a random challenge alpha (0 or 1)."""
        if self._alpha is None:
            self._alpha = random.randint(0, 1)
        return self._alpha
    
    def verify(self, v, n):
        """Verifies the zero-knowledge proof using stored alpha."""
        x = int(input("Prover sends x: "))
        
        # Use stored alpha or generate if not exists
        alpha = self.getalpha()
        print("Verifier sends alpha:", alpha)
        
        gamma = int(input("Prover sends gamma: "))
        if (gamma ** 2) % n == (x * (v ** alpha)) % n:
            print("Verifier accepts the proof.")
            return True
        else:
            print("Verifier rejects the proof.")
            return False
    
    def reset(self):
        """Reset stored alpha for new proof."""
        self._alpha = None

# Example usage
if __name__ == "__main__":
    verifier = ZKPVerifier()
    
    v = int(input("Enter the value of v: "))
    n = int(input("Enter the value of n: "))
    
    # Prover can get alpha
    alpha = verifier.getalpha()
    
    # Verifier verifies proof with same alpha
    verifier.verify(v, n)