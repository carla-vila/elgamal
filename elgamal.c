#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

// MODULAR EXPONENT
unsigned long long mod_exp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// KEY GENERATION 
unsigned long long rand_range(unsigned long long min, unsigned long long max) {
    return min + rand() % (max - min + 1);
}

// EXTENDED EUCLIDEAN ALGORITHM, PART OF FINDING THE MODULAR INVERSE
unsigned long long gcd_extended(unsigned long long a, unsigned long long b, long long *x, long long *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    long long x1, y1;
    unsigned long long gcd = gcd_extended(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd;
}

// MODULAR INVERSE
unsigned long long mod_inverse(unsigned long long a, unsigned long long m) {
    long long x, y;
    unsigned long long g = gcd_extended(a, m, &x, &y);
    if (g != 1) {
        return 0; // Inverse doesn't exist
    } else {
        unsigned long long res = (x % m + m) % m;
        return res;
    }
}

// GENERATE THE KEY 
void generate_keys(unsigned long long *p, unsigned long long *g, unsigned long long *x, unsigned long long *y) {
    *p = 23; 
    *g = 5; 
    *x = rand_range(1, *p - 2);
    *y = mod_exp(*g, *x, *p);
}

//MESSAGE ENCRYPTION -> MODULAR EXPONENTIATION
void encrypt(unsigned long long p, unsigned long long g, unsigned long long y, unsigned long long m, unsigned long long *c1, unsigned long long *c2) {
    unsigned long long k = rand_range(1, p - 2); // Random ephemeral key
    *c1 = mod_exp(g, k, p); // c1 = g^k % p
    *c2 = (m * mod_exp(y, k, p)) % p; // c2 = (m * y^k) % p
}

// MESSAGE ENCRYPTION -> MODULAR EXPONENTIATION + MODULAR INVERSE
unsigned long long decrypt(unsigned long long p, unsigned long long x, unsigned long long c1, unsigned long long c2) {
    unsigned long long s = mod_exp(c1, x, p); // s = c1^x % p
    unsigned long long s_inv = mod_inverse(s, p); // s_inv = s^-1 % p
    unsigned long long m = (c2 * s_inv) % p; // m = (c2 * s_inv) % p
    return m;
}

int main() {
    srand(time(NULL));

    //Key generation
    unsigned long long p, g, x, y;
    generate_keys(&p, &g, &x, &y);

    printf("Public key: (p = %llu, g = %llu, y = %llu)\n", p, g, y);
    printf("Private key: x = %llu\n", x);

    //Definicion de el mesage que se quiere transmitir
    unsigned long long message = 15;
    printf("Original message: %llu\n", message);


    //Alices uses Bob's public key to encrypt the message 
    unsigned long long c1, c2;
    encrypt(p, g, y, message, &c1, &c2);
    printf("Encrypted message: (c1 = %llu, c2 = %llu)\n", c1, c2);

    unsigned long long decrypted_message = decrypt(p, x, c1, c2);
    printf("Decrypted message: %llu\n", decrypted_message);

    return 0;
}