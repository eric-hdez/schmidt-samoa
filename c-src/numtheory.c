#include "numtheory.h"

#include "randstate.h"

void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t tmp_a, tmp_b, t;
    mpz_init_set(tmp_a, a);
    mpz_init_set(tmp_b, b);
    mpz_init(t);

    while (mpz_cmp_ui(tmp_b, 0)) {
        mpz_set(t, tmp_b);
        mpz_mod(tmp_b, tmp_a, tmp_b);
        mpz_set(tmp_a, t);
    }

    mpz_set(d, tmp_a);
    mpz_clears(tmp_a, tmp_b, t, NULL);
}

void lcm(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t prod_ab, gcd_ab;
    mpz_inits(prod_ab, gcd_ab, NULL);

    mpz_mul(prod_ab, a, b);
    gcd(gcd_ab, a, b);

    mpz_fdiv_q(d, prod_ab, gcd_ab);
    mpz_clears(prod_ab, gcd_ab, NULL);
}

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, t, r_prime, t_prime, tmp_r, tmp_t, q;
    mpz_init_set(r, n);
    mpz_init_set(r_prime, a);
    mpz_init_set_ui(t, 0);
    mpz_init_set_ui(t_prime, 1);
    mpz_inits(tmp_r, tmp_t, q, NULL);

    while (mpz_cmp_ui(r_prime, 0)) {
        mpz_fdiv_q(q, r, r_prime);

        mpz_set(tmp_r, r);
        mpz_set(r, r_prime);
        mpz_mul(r_prime, q, r_prime);
        mpz_sub(r_prime, tmp_r, r_prime);

        mpz_set(tmp_t, t);
        mpz_set(t, t_prime);
        mpz_mul(t_prime, q, t_prime);
        mpz_sub(t_prime, tmp_t, t_prime);
    }

    if (mpz_cmp_ui(r, 1) > 0) {
        mpz_set_ui(t, 0);
    }

    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n);
    }

    mpz_set(i, t);
    mpz_clears(r, t, r_prime, t_prime, tmp_r, tmp_t, q, NULL);
}

void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {
    mpz_t v, p, tmp_d;
    mpz_init_set_ui(v, 1);
    mpz_init_set(p, a);
    mpz_init_set(tmp_d, d);

    while (mpz_cmp_ui(tmp_d, 0) > 0) {
        if (mpz_odd_p(tmp_d)) {
            mpz_mul(v, v, p);
            mpz_mod(v, v, n);
        }

        mpz_mul(p, p, p);
        mpz_mod(p, p, n);

        mpz_fdiv_q_ui(tmp_d, tmp_d, 2);
    }

    mpz_set(o, v);
    mpz_clears(v, p, tmp_d, NULL);
}

bool is_prime(mpz_t n, uint64_t k) {
    if (mpz_cmp_ui(n, 1) <= 0 || mpz_cmp_ui(n, 4) == 0) {
        return false;
    }

    if (mpz_cmp_ui(n, 3) <= 0) {
        return true;
    }

    mpz_t r, s, a, y, j, two, n_min_1, n_min_3, s_min_1;
    mpz_inits(r, s, a, y, j, two, n_min_1, n_min_3, s_min_1, NULL);

    mpz_sub_ui(n_min_1, n, 1);
    mpz_set(r, n_min_1);
    mpz_set_ui(s, 0);
    while (mpz_even_p(r)) {
        mpz_add_ui(s, s, 1);
        mpz_fdiv_q_ui(r, r, 2);
    }

    for (uint64_t i = 0; i < k; i++) {
        mpz_set_ui(two, 2);
        mpz_sub_ui(n_min_3, n, 3);

        mpz_urandomm(a, state, n_min_3);
        mpz_add_ui(a, a, 2);

        pow_mod(y, a, r, n);

        if (mpz_cmp_ui(y, 1) && mpz_cmp(y, n_min_1)) {
            mpz_set_ui(j, 1);
            mpz_sub_ui(s_min_1, s, 1);

            while (mpz_cmp(j, s_min_1) <= 0 && mpz_cmp(y, n_min_1)) {
                pow_mod(y, y, two, n);

                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, s, a, y, j, two, n_min_1, n_min_3, s_min_1, NULL);
                    return false;
                }

                mpz_add_ui(j, j, 1);
            }

            if (mpz_cmp(y, n_min_1)) {
                mpz_clears(r, s, a, y, j, two, n_min_1, n_min_3, s_min_1, NULL);
                return false;
            }
        }
    }

    mpz_clears(r, s, a, y, j, two, n_min_1, n_min_3, s_min_1, NULL);
    return true;
}

void make_prime(mpz_t p, uint64_t bits, uint64_t k) {
    mpz_t lower, upper, one, normalize;
    mpz_inits(lower, upper, one, normalize, NULL);

    mpz_set_ui(one, 1);
    mpz_mul_2exp(lower, one, bits - 1);
    mpz_mul_2exp(upper, one, bits);
    mpz_sub(normalize, upper, lower);

    do {
        do {
            mpz_urandomb(p, state, bits - 1);
            mpz_add(p, p, normalize);
        } while (mpz_even_p(p));
    } while (!is_prime(p, k));

    mpz_clears(lower, upper, one, normalize, NULL);
}
