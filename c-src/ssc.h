#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

void ssc_key_gen(mpz_t N, mpz_t d, mpz_t n, uint64_t bits, uint64_t k);

void ssc_encrypt(mpz_t c, mpz_t m, mpz_t N);

void ssc_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n);

void ssc_encrypt_file(FILE *infile, FILE *outfile, mpz_t N);

void ssc_decrypt_file(FILE *infile, FILE *outfile, mpz_t d, mpz_t n);

void ssc_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n);

bool ssc_verify(mpz_t m, mpz_t s, mpz_t n);
