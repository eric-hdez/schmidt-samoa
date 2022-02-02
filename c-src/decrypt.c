#include "ssc.h"

#include <unistd.h>

#define DEFAULT_PRIV_FILE "ssc.priv"

void program_usage(FILE *stream, char *exec) {
    fprintf(stream, "%s: will print usage later\n", exec);
}

int main(int argc, char *argv[]) {
    int opt;

    char *privname = DEFAULT_PRIV_FILE;
    char *inname = NULL;
    char *outname = NULL;
    bool verbose = false;

    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (opt) {
        case 'i': inname = optarg; break;
        case 'o': outname = optarg; break;
        case 'n': privname = optarg; break;
        case 'v': verbose = true; break;
        case 'h': program_usage(stderr, argv[0]); exit(EXIT_SUCCESS);
        default: program_usage(stderr, argv[0]); exit(EXIT_FAILURE);
        }
    }

    FILE *privfile = NULL;
    FILE *infile = stdin;
    FILE *outfile = stdout;

    if (!(privfile = fopen(privname, "r"))) {
        fprintf(stderr, "error: failed to open public key file\n");
        exit(EXIT_FAILURE);
    }

    if (!(infile = fopen(inname, "r"))) {
        fprintf(stderr, "error: failed to open input file\n");
        fclose(privfile);
        exit(EXIT_FAILURE);
    }

    if (!(outfile = fopen(outname, "w"))) {
        fprintf(stderr, "error: failed to open output file\n");
        fclose(privfile);
        fclose(infile);
        exit(EXIT_FAILURE);
    }

    privkey_t priv = init_privkey();
    ssc_read_priv(&priv, privfile);

    if (verbose) {
        gmp_fprintf(stderr, "d (%zu bits) = %Zd\n", mpz_sizeinbase(priv.d, 2), priv.d);
        gmp_fprintf(stderr, "n (%zu bits) = %Zd\n", mpz_sizeinbase(priv.n, 2), priv.n);
    }

    ssc_decrypt_file(infile, outfile, &priv);

    delete_privkey(&priv);
    fclose(privfile);
    fclose(infile);
    fclose(outfile);

    return EXIT_SUCCESS;
}
