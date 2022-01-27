#include "ssc.h"

#include "numtheory.h"

void ssc_key_gen(mpz_t N, mpz_t d, mpz_t n, uint64_t bits, uint64_t k) {
    uint64_t bitsz = bits / 2;

    mpz_t p, q, p_min_1, q_min_1, pm1_mod_q, qm1_mod_q;
    mpz_inits(p, q, p_min_1, q_min_1, pm1_mod_q, qm1_mod_q, NULL);
    make_prime(p, bitsz, k);
    make_prime(q, bitsz, k);

    mpz_sub_ui(p_min_1, p, 1);
    mpz_sub_ui(q_min_1, q, 1);
    mpz_mod(pm1_mod_q, p_min_1, q);
    mpz_mod(qm1_mod_q, q_min_1, p);

    while (!mpz_cmp(p, q) || !mpz_cmp_ui(pm1_mod_q, 0) || !mpz_cmp_ui(qm1_mod_q, 0)) {
        make_prime(q, bitsz, k);
        mpz_sub_ui(q_min_1, q, 1);
        mpz_mod(pm1_mod_q, p_min_1, q);
        mpz_mod(qm1_mod_q, q_min_1, p);
    }

    mpz_clears(p_min_1, q_min_1, pm1_mod_q, qm1_mod_q, NULL);

    mpz_t λ;
    mpz_init(λ);
    mpz_mul(n, p, q);          // decrypt modulus
    mpz_mul(N, p, n);          // public key
    lcm(λ, p_min_1, q_min_1);  // Carmichael's λ function
    mod_inverse(d, N, λ);      // private key

    mpz_clear(λ);
}

void ssc_encrypt(mpz_t c, mpz_t m, mpz_t N) {
    pow_mod(c, m, N, N);
}

void ssc_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}
