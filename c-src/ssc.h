#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

typedef struct pubkey_t {
    mpz_t N;
    uint64_t rlen;
} pubkey_t;

typedef struct privkey_t {
    mpz_t d, n;
    uint64_t rlen;
} privkey_t;

pubkey_t init_pubkey(void);

privkey_t init_privkey(void);

void delete_keys(pubkey_t *pub, privkey_t *priv);

void ssc_key_gen(pubkey_t *pub, privkey_t *priv, uint64_t bits, uint64_t k);

void ssc_encrypt(mpz_t c, mpz_t m, pubkey_t *pub);

void ssc_decrypt(mpz_t m, mpz_t c, privkey_t *priv);

void ssc_encrypt_file(FILE *infile, FILE *outfile, pubkey_t *pub);

void ssc_decrypt_file(FILE *infile, FILE *outfile, privkey_t *priv);

void ssc_write_pub(pubkey_t *pub, mpz_t s, char username[], FILE *pubfile);

void ssc_read_pub(pubkey_t *pub, mpz_t s, char username[], FILE *pubfile);

void ssc_write_priv(privkey_t *priv, FILE *privfile);

void ssc_read_priv(privkey_t *priv, FILE *privfile);

void ssc_sign(mpz_t s, mpz_t m, pubkey_t *pub, privkey_t *priv);

bool ssc_verify(mpz_t m, mpz_t s, pubkey_t *pub);
