#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>

//char string[] = "The quick brown fox jumped over the lazy dog's back";

int main(int argc, char **argv) {
    // read command line input
    FILE *fp;
    int opt;
    int algo;
    char* t;
    while ((opt = getopt(argc, argv, "i:t:")) != -1) {
        switch (opt) {
            case 'i':
                fp = fopen(optarg, "r");
                break;
            case 't':
                t = optarg;
                if (!strcmp(t, "md5")) {
                    algo = 1;
                } else if (!strcmp(t, "sha")) {
                    algo = 2;
                } else if (!strcmp(t, "sha256")) {
                    algo = 3;
                } else {
                    fprintf(stderr, "Invalid argument for -t. Options: md5, sha, sha256\n");
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input file] [-t hashing algorithm]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // read the whole file
    fseek(fp, 0, SEEK_END);
    long lSize = ftell(fp);
    rewind(fp);
    char* buffer = (char*) malloc(sizeof (char)*lSize);
    size_t length = fread(buffer, 1, lSize, fp);
    // handle errors
    if (length != lSize) {
        fputs("Reading error", stderr);
        exit(3);
    }

    if (buffer == NULL) {
        fputs("Memory error", stderr);
        exit(2);
    }
    int i;
    time_t begin;
    unsigned char result[MD5_DIGEST_LENGTH];
    time_t end;
    time_t total;
    begin = time(NULL);
    switch (algo) {
        case 1:
            // calculate md5
            MD5((unsigned char*) buffer, length, result);
            for (i = 0; i < MD5_DIGEST_LENGTH; i++)
                printf("%02x", result[i]);
            break;
        case 2:
            // calculate sha
            SHA((unsigned char*) buffer, length, result);
            total = end - begin;
            for (i = 0; i < SHA_DIGEST_LENGTH; i++)
                printf("%02x", result[i]);
            break;
        case 3:
            // calculate sha256
            SHA256((unsigned char*) buffer, length, result);
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
                printf("%02x", result[i]);
            break;

    }
    end = time(NULL);
    total = end - begin;
    printf("\nAlgorithm used: %s\n", t);
    printf("Time consumed: %d\n", total);


    // output



    return 0;
}