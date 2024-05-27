#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#define NUM_WORDS 16  // 1024 bits / 64 bits per word

// Function prototypes
void mod_exp_1024(uint64_t res[], uint64_t base[], uint64_t exp[], uint64_t mod[], uint32_t n);
void generate_keys(uint64_t p[], uint64_t g[], uint64_t x[], uint64_t y[], uint32_t n);
void encrypt(uint64_t c1[], uint64_t c2[], uint64_t p[], uint64_t g[], uint64_t y[], uint64_t m[], uint32_t n);
void mod_inverse_1024(uint64_t res[], uint64_t a[], uint64_t mod[], uint32_t n);
void decrypt(uint64_t m[], uint64_t p[], uint64_t x[], uint64_t c1[], uint64_t c2[], uint32_t n);
void rand_1024(uint64_t res[], uint32_t n);

bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n);
bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[], uint32_t n);
bool modbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);
bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);
uint32_t bit_length(uint64_t op[], uint32_t n);
int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n);

// Function to calculate the modular exponentiation: base^exp % mod for 1024-bit numbers
void mod_exp_1024(uint64_t res[], uint64_t base[], uint64_t exp[], uint64_t mod[], uint32_t n) {
    uint64_t result[NUM_WORDS] = {0}, temp_exp[NUM_WORDS] = {0};
    uint64_t mod_base[NUM_WORDS] = {0};
    memcpy(temp_exp, exp, n * sizeof(uint64_t));
    memcpy(mod_base, base, n * sizeof(uint64_t));
    result[0] = 1;

    while (bit_length(temp_exp, n) > 0) {
        if (temp_exp[0] & 1) {
            modmult1024(result, result, mod_base, mod, n);
        }
        modmult1024(mod_base, mod_base, mod_base, mod, n);
        srnbignum(temp_exp, temp_exp, n, 1);
    }

    memcpy(res, result, n * sizeof(uint64_t));
}

// Function to generate ElGamal key pairs
void generate_keys(uint64_t p[], uint64_t g[], uint64_t x[], uint64_t y[], uint32_t n) {
    // Prime number (p)
    p[0] = 0xFFFFFFFFFFFFFFFF;  // Example large prime number (256 bits here, expand for 1024)
    p[1] = 0xFFFFFFFFFFFFFFFF;
    p[2] = 0xFFFFFFFFFFFFFFFF;
    p[3] = 0xFFFFFFFFFFFFFFFF;
    // Initialize remaining bits to 0
    memset(&p[4], 0, (n-4) * sizeof(uint64_t));

    // Generator (g)
    g[0] = 2;
    memset(&g[1], 0, (n-1) * sizeof(uint64_t));

    // Private key (x)
    rand_1024(x, n);

    // Public key (y = g^x % p)
    mod_exp_1024(y, g, x, p, n);
}

// Function to encrypt a message
void encrypt(uint64_t c1[], uint64_t c2[], uint64_t p[], uint64_t g[], uint64_t y[], uint64_t m[], uint32_t n) {
    uint64_t k[NUM_WORDS] = {0};
    rand_1024(k, n);  // Random ephemeral key
    mod_exp_1024(c1, g, k, p, n);  // c1 = g^k % p
    uint64_t temp[NUM_WORDS] = {0};
    mod_exp_1024(temp, y, k, p, n);  // temp = y^k % p
    modmult1024(c2, m, temp, p, n);  // c2 = (m * temp) % p
}

// Function to compute modular inverse of a number for 1024-bit numbers
void mod_inverse_1024(uint64_t res[], uint64_t a[], uint64_t mod[], uint32_t n) {
    int64_t x0 = 1, x1 = 0, m0 = (int64_t)mod[0], a0 = (int64_t)a[0];
    while (a0 > 1) {
        int64_t q = a0 / m0, t = m0;
        m0 = a0 % m0;
        a0 = t;
        t = x1;
        x1 = x0 - q * x1;
        x0 = t;
    }
    if (x0 < 0) x0 += mod[0];
    res[0] = (uint64_t)x0;
}

// Function to decrypt a message
void decrypt(uint64_t m[], uint64_t p[], uint64_t x[], uint64_t c1[], uint64_t c2[], uint32_t n) {
    uint64_t s[NUM_WORDS] = {0};
    mod_exp_1024(s, c1, x, p, n);  // s = c1^x % p
    uint64_t s_inv[NUM_WORDS] = {0};
    mod_inverse_1024(s_inv, s, p, n);  // s_inv = s^-1 % p
    modmult1024(m, c2, s_inv, p, n);  // m = (c2 * s_inv) % p
}

// Function to generate random 1024-bit number
void rand_1024(uint64_t res[], uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        res[i] = ((uint64_t)rand() << 32) | rand();
    }
}

// Main function
int main() {
    srand(time(NULL));

    uint64_t p[NUM_WORDS] = {0}, g[NUM_WORDS] = {0}, x[NUM_WORDS] = {0}, y[NUM_WORDS] = {0};
    generate_keys(p, g, x, y, NUM_WORDS);

    printf("Public key: (p = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", p[i]);
    printf(", g = %llu, y = ", g[0]);
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", y[i]);
    printf(")\n");

    printf("Private key: x = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", x[i]);
    printf("\n");

    uint64_t message[NUM_WORDS] = {0x1234567890ABCDEF};  // Example message
    printf("Original message: ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", message[i]);
    printf("\n");

    uint64_t c1[NUM_WORDS] = {0}, c2[NUM_WORDS] = {0};
    encrypt(c1, c2, p, g, y, message, NUM_WORDS);
    printf("Encrypted message: (c1 = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", c1[i]);
    printf(", c2 = ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", c2[i]);
    printf(")\n");

    uint64_t decrypted_message[NUM_WORDS] = {0};
    decrypt(decrypted_message, p, x, c1, c2, NUM_WORDS);
    printf("Decrypted message: ");
    for (int i = NUM_WORDS - 1; i >= 0; i--) printf("%016llx", decrypted_message[i]);
    printf("\n");

    return 0;
}

// Helper functions

bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n) {
    uint32_t i;
    uint64_t carry = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = op1[i] + carry;
        carry = (temp < op1[i]);
        res[i] = temp + op2[i];
        carry |= (res[i] < temp);
    }
    return carry;
}

bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n) {
    uint32_t i;
    uint64_t borrow = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = op1[i] - op2[i];
        res[i] = temp - borrow;
        borrow = (op1[i] < op2[i]) || (temp < borrow);
    }
    return borrow;
}

bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n) {
    uint32_t i;
    uint64_t carry = 0;
    for (i = 0; i < n; i++) {
        uint64_t temp = (op1[i] & 0xFFFFFFFF) * op2 + carry;
        uint64_t high = (op1[i] >> 32) * op2 + (temp >> 32);
        res[i] = (high << 32) | (temp & 0xFFFFFFFF);
        carry = high >> 32;
    }
    res[n] = carry;
    return 0;
}

bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[], uint32_t n) {
    uint64_t mult1[NUM_WORDS] = {0}, mult2[NUM_WORDS] = {0}, result[NUM_WORDS] = {0}, xmod[NUM_WORDS] = {0};
    memcpy(xmod, mod, n * sizeof(uint64_t));

    for (uint32_t i = 0; i < n; i++) {
        memset(mult1, 0, NUM_WORDS * sizeof(uint64_t));
        memset(mult2, 0, NUM_WORDS * sizeof(uint64_t));

        multbignum(mult1, op1, (op2[i] & 0xFFFFFFFF), n);
        multbignum(mult2, op1, (op2[i] >> 32), n);
        slnbignum(mult2, mult2, n + 1, 32);
        addbignum(mult2, mult2, mult1, n + 1);
        slnbignum(mult2, mult2, n + 1, 64 * i);
        addbignum(result, result, mult2, n + 1);
    }

    modbignum(result, result, xmod, n + 1);
    memcpy(res, result, n * sizeof(uint64_t));
    return 0;
}

bool modbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n) {
    uint32_t len_op1 = bit_length(op1, n), len_op2 = bit_length(op2, n), len_dif = len_op1 - len_op2;
    if (len_dif < 0) {
        memcpy(res, op1, n * sizeof(uint64_t));
        return 1;
    }

    memcpy(res, op1, n * sizeof(uint64_t));
    if (len_dif == 0) {
        while (compare(res, op2, n) >= 0) {
            subbignum(res, res, op2, n);
        }
        return 1;
    }

    slnbignum(op2, op2, n, len_dif);
    for (uint32_t i = 0; i < len_dif; i++) {
        srnbignum(op2, op2, n, 1);
        while (compare(res, op2, n) >= 0) {
            subbignum(res, res, op2, n);
        }
    }
    return 1;
}

bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n) {
    uint32_t x = n / 64, y = n % 64;
    for (uint32_t i = len; i > x; i--) {
        res[i - 1] = op[i - 1 - x];
    }
    for (uint32_t i = x; i > 0; i--) {
        res[i - 1] = 0;
    }

    uint64_t carry = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint64_t temp = res[i];
        res[i] = (temp << y) | carry;
        carry = temp >> (64 - y);
    }
    return 1;
}

bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n) {
    uint32_t x = n / 64, y = n % 64;
    for (uint32_t i = 0; i + x < len; i++) {
        res[i] = op[i + x];
    }
    for (uint32_t i = len - x; i < len; i++) {
        res[i] = 0;
    }

    uint64_t carry = 0;
    for (uint32_t i = len; i > 0; i--) {
        uint64_t temp = res[i - 1];
        res[i - 1] = (temp >> y) | carry;
        carry = temp << (64 - y);
    }
    return 1;
}

uint32_t bit_length(uint64_t op[], uint32_t n) {
    uint32_t len = 0;
    for (uint32_t i = n; i > 0; i--) {
        if (op[i - 1] != 0) {
            len = (i - 1) * 64;
            uint64_t temp = op[i - 1];
            while (temp) {
                temp >>= 1;
                len++;
            }
            break;
        }
    }
    return len;
}

int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n) {
    for (uint32_t i = n; i > 0; i--) {
        if (op1[i - 1] > op2[i - 1]) return 1;
        if (op1[i - 1] < op2[i - 1]) return -1;
    }
    return 0;
}
