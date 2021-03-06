#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fileutils.h"

#include <sodium.h>

#include "keyfiles.h"


int fileno(FILE *);





struct parameters {
    short int benchmark;
    int benchmark_count;
    char *filename;
    char *pk_fname;
    char *out_name;
};

void print_usage(FILE * stream, int exit_code, char *prog)
{
    fprintf(stream, "Usage: %s [options] FILENAME PUBLICKEY\n", prog);
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, --help        Show this help\n");
    fprintf(stream,
            "  --bench COUNT     Run the encryption COUNT times and\n"
            "                    print only benchmarks to stdout\n");
    fprintf(stream, "  -o, --out FNAME   Output ciphertext to FNAME\n");
    exit(exit_code);
}

int parse_opt(int argc, char **argv, struct parameters *opts)
{
    int option_index;
    int c;
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"bench", required_argument, NULL, 0},
        {"out", required_argument, NULL, 'o'},
        {NULL, 0, NULL, 0}
    };
    char *program_name = argv[0];
    while (1) {
        option_index = 0;
        c = getopt_long(argc, argv, "ho:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:                /* long option without a short arg */
            if (strcmp("bench", long_options[option_index].name) == 0) {
                opts->benchmark = 1;
                if (!sscanf(optarg, "%d", &opts->benchmark_count)) {
                    fprintf(stderr, "'%s' is not a valid integer\n",
                            optarg);
                    return 2;
                }
                if (opts->benchmark_count < 1) {
                    fprintf(stderr, "-b must be >= 1, got %d instead\n",
                            opts->benchmark_count);
                    return 2;
                }
            }
            break;
        case 'h':
            print_usage(stdout, 0, program_name);
            break;
        case 'o':
            opts->out_name = calloc(strlen(optarg) + 1, sizeof(char));
            strncpy(opts->out_name, optarg, strlen(optarg));
            break;
        case '?':
            break;
        default:
            break;
        }
    }
    if (argc - optind != 2) {
        fprintf(stderr, "Wrong number of arguments\n");
        return 2;
    }
    if(!(opts->out_name || opts->benchmark)) {
        fprintf(stderr, "Either --bench or --out is required\n");
        return 2;
    }
    if(opts->out_name && opts->benchmark) {
        fprintf(stderr, "--bench and --out are mutually exclusive\n");
        return 2;
    }
    if (optind < argc) {
        int argnumber = 0;
        while (optind + argnumber < argc) {
            switch (argnumber) {
            case 0:
                opts->filename = argv[optind + argnumber++];
                break;
            case 1:
                opts->pk_fname = argv[optind + argnumber++];
                break;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (sodium_init() == -1) {
        return 11;
    }
    unsigned char *c;
    int cipher_fd = fileno(stdout);
    unsigned char *plain = NULL;
    long plain_len;
    struct parameters params;
    params.benchmark = 0;
    params.benchmark_count = 1;
    params.pk_fname = NULL;
    params.out_name = NULL;


    int parse_ret = parse_opt(argc, argv, &params);
    if (parse_ret) {
        print_usage(stderr, parse_ret, argv[0]);
    }
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    if (pk_read(params.pk_fname, pk)) {
        fprintf(stderr, "Error reading public key\n");
        return 1;
    }

    plain_len = file_mmapwhole(params.filename, &plain);
    if (plain_len < 0 || !plain) {
        if (plain) {
            munmap(plain, plain_len);
        }
        fprintf(stderr, "Error reading file\n");
        return 1;
    }

    if (!params.benchmark) {
        if (params.out_name != NULL) {
            cipher_fd = open(params.out_name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR);
            free(params.out_name);
            if(cipher_fd == -1) {
                fprintf(stderr, "Error opening output file (%s)", strerror(errno));
                munmap(plain, plain_len);
                return 1;
            }
        }
        lseek(cipher_fd, plain_len + crypto_box_SEALBYTES - 1, SEEK_SET);
        write(cipher_fd, "", 1);
        lseek(cipher_fd, 0, SEEK_SET);
        c = mmap(0, plain_len + crypto_box_SEALBYTES, PROT_READ | PROT_WRITE, MAP_SHARED, cipher_fd, 0);
        if(c == MAP_FAILED) {
            fprintf(stderr, "Error opening output buffer: %s\n", strerror(errno));
            munmap(plain, plain_len);
            return 1;
        }
        memset(c, '\0', plain_len + crypto_box_SEALBYTES);

        const int r = crypto_box_seal(c, plain, plain_len, pk);
        munmap(c, plain_len + crypto_box_SEALBYTES);
        if (r != 0) {
            fprintf(stderr, "Error %d occured\n", r);
            munmap(plain, plain_len);
            return 1;
        }
    } else {
        time_t starttime = time(NULL);
        c = calloc(plain_len + crypto_box_SEALBYTES, sizeof(char));
        for (int i = 0; i < params.benchmark_count; i++) {
            crypto_box_seal(c, plain, plain_len, pk);
        }
        free(c);
        fprintf(stderr, "Time per cycle: %.3f\n",
                (double) (time(NULL) -
                          starttime) / params.benchmark_count);
    }
    return 0;
}
