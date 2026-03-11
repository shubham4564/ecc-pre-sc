import hashlib
import secrets

# Use Keccak256 as the hash method
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


bytesize = 16
x = get_rand(bytesize)
g = 5
h = 3
k = get_rand(bytesize)
p = 2**255 - 19

Y = ppow(g, x, p)
Z = ppow(h, x, p)
A = ppow(g, k, p)
B = ppow(h, k, p)

# Use Keccak256 for hashing
cval = f"{Y}{Z}{A}{B}"
hash1 = hashlib.sha3_256(cval.encode('utf-8')).digest()
c = int.from_bytes(hash1, byteorder='big') % p

s = k - c * x

if s < 0:
    val1 = ppow(g, -s, p)
    val2 = ppow(h, -s, p)
    val1 = extended_euclid(val1, p)
    val2 = extended_euclid(val2, p)
else:
    val1 = ppow(g, s, p)
    val2 = ppow(h, s, p)

if c < 0:
    val3 = ppow(Y, -c, p)
    val4 = ppow(Z, -c, p)
    val3 = extended_euclid(val3, p)
    val4 = extended_euclid(val4, p)
else:
    val3 = ppow(Y, c, p)
    val4 = ppow(Z, c, p)

A_ = (val1 * val3) % p
B_ = (val2 * val4) % p

cval2 = f"{Y}{Z}{A_}{B_}"
hash2 = hashlib.sha3_256(cval2.encode('utf-8')).digest()
c_ = int.from_bytes(hash2, byteorder='big') % p

print("== Peggy and Victor agree on some parameters ==")
print(f"g={g}")
print(f"h={h}")
print(f"p={p}")
print("\n== Peggy generates a secret ==")
print(f"x={x}")
print("\n== Peggy sends to Victor ==")
print(f"Y=g^x (mod p)={Y}")
print(f"Z=h^x (mod p)={Z}")
print("\n== To prove proof of x, Peggy generates a random value ==")
print(f"k={k}")
print("\n== To prove Peggy computes  ==")
print(f"A=g^k (mod p)={A}")
print(f"B=h^k (mod p)={B}")
print("\n== Peggy sends  ==")
print(f"c=H(Y || Z || A || B)={c}")
print(f"s={s}")
print("\n== Victor computes  ==")
print(f"A'=g^s * Y^c={A_}")
print(f"B'=h^s * Z^c={B_}")
print(f"c'=H(Y || Z || A' || B')={c_}")
print("Proven" if c == c_ else "Not Proven!")