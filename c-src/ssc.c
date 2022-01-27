#include "ssc.h"

#include "numtheory.h"


pubkey_t init_pubkey() {
    struct pubkey_t pubk;
    mpz_init(pubk.N);
    return pubk;
}

privkey_t init_privkey() {
    struct privkey_t privk;
    mpz_inits(privk.d, privk.n, NULL);
    return privk;
}

void ssc_key_gen(pubkey_t *pub, privkey_t *priv, uint64_t bits, uint64_t k) {
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
    mpz_mul(priv->n, p, q); // decrypt modulus
    mpz_mul(pub->N, p, priv->n); // public key
    lcm(λ, p_min_1, q_min_1); // Carmichael's λ function
    mod_inverse(priv->d, pub->N, λ); // private key

    mpz_clear(λ);
}

void ssc_encrypt(mpz_t c, mpz_t m, pubkey_t *pub) {
    pow_mod(c, m, pub->N, pub->N);
}

void ssc_decrypt(mpz_t m, mpz_t c, privkey_t *priv) {
    pow_mod(m, c, priv->d, priv->n);
}
