#include "ssc.h"
#include "randstate.h"

#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_BITS      512
#define DEFAULT_K         100
#define DEFAULT_PUB_FILE  "ssc.pub"
#define DEFAULT_PRIV_FILE "ssc.priv"

void program_usage(FILE *stream, char *exec) {
    fprintf(stream, "%s: will print usage later\n", exec);
}

int main(int argc, char *argv[]) {
    int opt;

    uint64_t bits = DEFAULT_BITS;
    uint64_t k = DEFAULT_K;
    char *pubname = DEFAULT_PUB_FILE;
    char *privname = DEFAULT_PRIV_FILE;
    uint64_t seed = time(NULL);
    bool verbose = false;

    while ((opt = getopt(argc, argv, "b:k:s:n:d:vh")) != -1) {
        switch (opt) {
        case 'b': bits = strtoull(optarg, NULL, 10); break;
        case 'k': k = strtoull(optarg, NULL, 10); break;
        case 's': seed = strtoull(optarg, NULL, 10); break;
        case 'n': pubname = optarg; break;
        case 'd': privname = optarg; break;
        case 'v': verbose = true; break;
        case 'h': program_usage(stderr, argv[0]); exit(EXIT_SUCCESS);
        default: program_usage(stderr, argv[0]); exit(EXIT_FAILURE);
        }
    }

    FILE *pubfile = NULL; 
    FILE *privfile = NULL;

    if (!(pubfile = fopen(pubname, "w"))) {
        fprintf(stderr, "error: failed to open public key file\n");
        exit(EXIT_FAILURE);
    }

    if (!(privfile = fopen(privname, "w"))) {
        fprintf(stderr, "error: failed to open private key file\n");
        exit(EXIT_FAILURE);
    }

    fchmod(fileno(privfile), 0600);
    randstate_init(seed);

    pubkey_t pub = init_pubkey();
    privkey_t priv  = init_privkey();
    ssc_key_gen(&pub, &priv, bits, k);

    char *username = getenv("USER");
    if (!username) {
        username = "default";
    }

    mpz_t user, signature;
    mpz_inits(user, signature, NULL);
    mpz_set_str(user, username, 62);

    ssc_sign(signature, user, &pub, &priv);
    ssc_write_pub(&pub, signature, username, pubfile);
    ssc_write_priv(&priv, privfile);

    if (verbose) {
        gmp_fprintf(stderr, "user = %s\n", username);
        gmp_fprintf(stderr, "s (%zu bits) = %Zd\n", mpz_sizeinbase(signature, 2), signature);
        gmp_fprintf(stderr, "N (%zu bits) = %Zd\n", mpz_sizeinbase(pub.N, 2), pub.N);
        gmp_fprintf(stderr, "n (%zu bits) = %Zd\n", mpz_sizeinbase(priv.n, 2), priv.n);
        gmp_fprintf(stderr, "d (%zu bits) = %Zd\n", mpz_sizeinbase(priv.d, 2), priv.d);
    }

    mpz_clears(user, signature, NULL);
    randstate_clear();
    fclose(pubfile);
    fclose(privfile);

    return EXIT_SUCCESS;
}
