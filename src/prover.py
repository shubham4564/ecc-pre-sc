# --- prover.py ---
import random
from verifier import ZKPVerifier

def generate_primes(n):
    """Generates two distinct n-bit prime numbers."""
    # p = random.getrandbits(n)
    p = 17
    while not is_prime(p):
        p = random.getrandbits(n)
    # q = random.getrandbits(n)
    q = 13
    while not is_prime(q) or p == q:
        q = random.getrandbits(n)
    return p, q

def is_prime(n):
    """Checks if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def prover(s, n, verifier):
    """Generates a zero-knowledge proof that the prover knows s."""
    v = (s ** 2) % n
    r = random.randint(1, n - 1)
    x = (r ** 2) % n
    print("Prover sends x:", x)

    # Get alpha from verifier instance
    alpha = verifier.getalpha()
    print("Prover receives alpha:", alpha)

    if alpha == 0:
        gamma = r
    else:
        gamma = (r * s) % n
    print("Prover sends gamma:", gamma)
    
    # Verify the proof using same verifier instance
    return verifier.verify(v, n)

if __name__ == "__main__":
    # Initialize verifier
    verifier = ZKPVerifier()
    
    # Generate parameters
    n_bits = 512
    p, q = generate_primes(n_bits)
    n = p * q
    s = random.randint(int(n ** 0.5), n - 1)
    v = (s ** 2) % n

    print("Public information: v =", v, "n =", n)

    # Generate and verify proof using same verifier instance
    prover(s, n, verifier)