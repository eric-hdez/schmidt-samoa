#include "ssc.h"

#include <unistd.h>

#define DEFAULT_PUB_FILE "ssc.pub"
#define KB               1024

void program_usage(FILE *stream, char *exec) {
    fprintf(stream, "%s: will print usage later\n", exec);
}

int main(int argc, char *argv[]) {
    int opt;

    char *pubname = DEFAULT_PUB_FILE;
    char *inname = NULL;
    char *outname = NULL;
    bool verbose = false;

    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (opt) {
        case 'i': inname = optarg; break;
        case 'o': outname = optarg; break;
        case 'n': pubname = optarg; break;
        case 'v': verbose = true; break;
        case 'h': program_usage(stderr, argv[0]); exit(EXIT_SUCCESS);
        default: program_usage(stderr, argv[0]); exit(EXIT_FAILURE);
        }
    }

    FILE *pubfile = NULL;
    FILE *infile = stdin;
    FILE *outfile = stdout;

    if (!(pubfile = fopen(pubname, "r"))) {
        fprintf(stderr, "error: failed to open public key file\n");
        exit(EXIT_FAILURE);
    }

    if (!(infile = fopen(inname, "r"))) {
        fprintf(stderr, "error: failed to open input file\n");
        fclose(pubfile);
        exit(EXIT_FAILURE);
    }

    if (!(outfile = fopen(outname, "w"))) {
        fprintf(stderr, "error: failed to open output file\n");
        fclose(pubfile);
        fclose(infile);
        exit(EXIT_FAILURE);
    }

    mpz_t user, signature;
    mpz_inits(user, signature, NULL);
    char username[KB] = { 0 };

    pubkey_t pub = init_pubkey();
    ssc_read_pub(&pub, signature, username, pubfile);

    if (verbose) {
        gmp_fprintf(stderr, "user = %s\n", username);
        gmp_fprintf(stderr, "s (%zu bits) = %Zd\n", mpz_sizeinbase(signature, 2), signature);
        gmp_fprintf(stderr, "N (%zu bits) = %Zd\n", mpz_sizeinbase(pub.N, 2), pub.N);
    }

    /*mpz_set_str(user, username, 62);
    if (!ssc_verify(user, signature, &pub)) {
        fprintf(stderr, "error: invalid ssc key\n");
        mpz_clears(user, signature, NULL);
        fclose(pubfile);
        fclose(infile);
        fclose(outfile);
        exit(EXIT_FAILURE);
    }*/

    ssc_encrypt_file(infile, outfile, &pub);

    delete_pubkey(&pub);
    mpz_clears(user, signature, NULL);
    fclose(pubfile);
    fclose(infile);
    fclose(outfile);

    return EXIT_SUCCESS;
}
