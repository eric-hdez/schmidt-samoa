#include "ssc.h"

#include "numtheory.h"

#include <math.h>

pubkey_t init_pubkey(void) {
    pubkey_t pub = { 0 };
    mpz_init(pub.N);
    return pub;
}

privkey_t init_privkey(void) {
    privkey_t priv = { 0 };
    mpz_inits(priv.d, priv.n, NULL);
    return priv;
}

void delete_keys(pubkey_t *pub, privkey_t *priv) {
    mpz_clears(pub->N, priv->d, priv->n, NULL);
}

void ssc_key_gen(pubkey_t *pub, privkey_t *priv, uint64_t bits, uint64_t k) {
    uint64_t pbits = (random() % (bits / 2)) + (bits / 4);
    uint64_t qbits = bits - pbits;

    mpz_t p, q, p_min_1, q_min_1, pm1_mod_q, qm1_mod_q;
    mpz_inits(p, q, p_min_1, q_min_1, pm1_mod_q, qm1_mod_q, NULL);

    make_prime(p, pbits, k);
    make_prime(q, qbits, k);

    mpz_sub_ui(p_min_1, p, 1);
    mpz_sub_ui(q_min_1, q, 1);
    mpz_mod(pm1_mod_q, p_min_1, q);
    mpz_mod(qm1_mod_q, q_min_1, p);

    while (!mpz_cmp(p, q) || !mpz_cmp_ui(pm1_mod_q, 0) || !mpz_cmp_ui(qm1_mod_q, 0)) {
        make_prime(q, qbits, k);

        mpz_sub_ui(q_min_1, q, 1);
        mpz_mod(pm1_mod_q, p_min_1, q);
        mpz_mod(qm1_mod_q, q_min_1, p);
    }

    mpz_clears(pm1_mod_q, qm1_mod_q, NULL);

    mpz_t λ;
    mpz_init(λ);
    mpz_mul(priv->n, p, q); // decrypt modulus
    mpz_mul(pub->N, p, priv->n); // public key
    lcm(λ, p_min_1, q_min_1); // Carmichael's λ function
    mod_inverse(priv->d, pub->N, λ); // private key

    pub->rlen = bits - 1;
    priv->rlen = pub->rlen;

    mpz_clears(λ, p_min_1, q_min_1, NULL);
}

void ssc_encrypt(mpz_t c, mpz_t m, pubkey_t *pub) {
    pow_mod(c, m, pub->N, pub->N);
}

void ssc_decrypt(mpz_t m, mpz_t c, privkey_t *priv) {
    pow_mod(m, c, priv->d, priv->n);
}

void ssc_encrypt_file(FILE *infile, FILE *outfile, pubkey_t *pub) {
    mpz_t m, c;
    mpz_inits(m, c, NULL);
    size_t k = (pub->rlen) / 8;
    uint8_t *block = calloc(k, sizeof(uint8_t));
    block[0] = 0xFF;

    while (!feof(infile)) {
        size_t nbytes = 0;

        if ((nbytes = fread(block + 1, sizeof(uint8_t), k - 1, infile)) > 0) {
            mpz_import(m, nbytes + 1, 1, sizeof(uint8_t), 1, 0, block);
            ssc_encrypt(c, m, pub);
            gmp_fprintf(outfile, "%Zx\n", c);
        }
    }

    free(block);
    mpz_clears(m, c, NULL);
}

void ssc_decrypt_file(FILE *infile, FILE *outfile, privkey_t *priv) {
    mpz_t c, m;
    mpz_inits(c, m, NULL);
    size_t k = (priv->rlen) / 8;
    uint8_t *block = calloc(k, sizeof(uint8_t));

    while (!feof(infile)) {
        size_t nbytes = 0;

        if (gmp_fscanf(infile, "%Zx\n", c) > 0) {
            ssc_decrypt(m, c, priv);
            mpz_export(block, &nbytes, 1, sizeof(uint8_t), 1, 0, m);
            fwrite(block + 1, sizeof(uint8_t), nbytes - 1, outfile);
        }
    }

    free(block);
    mpz_clears(c, m, NULL);
}
