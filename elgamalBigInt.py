import sympy
import random

def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

def generate_keys(bits):
    p = sympy.randprime(2**(bits-1), 2**bits)
    g = random.randint(2, p-1)
    x = random.randint(1, p-2)
    y = mod_exp(g, x, p)
    return (p, g, y, x)

def encrypt(p, g, y, message):
    k = random.randint(1, p-2)
    c1 = mod_exp(g, k, p)
    c2 = (message * mod_exp(y, k, p)) % p
    return (c1, c2)

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def decrypt(p, x, c1, c2):
    s = mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    message = (c2 * s_inv) % p
    return message

def display_public_key(p, g, y):
    print("Public key components:")
    print("p (prime number) = {}".format(p))
    print("g (generator) = {}".format(g))
    print("y (g^x mod p) = {}".format(y))

# Example usage:
bits = 1000
(p, g, y, x) = generate_keys(bits)
display_public_key(p, g, y)
print("Private key: x = {}".format(x))

message = sympy.randprime(2**(bits-1), 2**bits)  # A random large message
print("Original message: {}".format(message))

(c1, c2) = encrypt(p, g, y, message)
print("Encrypted message: (c1, c2) = ({}, {})".format(c1, c2))

decrypted_message = decrypt(p, x, c1, c2)
print("Decrypted message: {}".format(decrypted_message))

assert message == decrypted_message, "Decryption failed"
