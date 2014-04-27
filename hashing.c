#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

//char string[] = "The quick brown fox jumped over the lazy dog's back";

int main(int argc, char **argv) {
    // read command line input
    FILE *fp;

    if (argc == 2) {
        fp = fopen(argv[1], "r");
    } else {
        printf("***ERROR: Please provide 1 file.\n");
        exit(1);
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

    // calculate md5
    time_t md5begin = time(NULL);
    unsigned char md5result[MD5_DIGEST_LENGTH];
    MD5((unsigned char*) buffer, length, md5result);
    time_t md5end = time(NULL);
    time_t md5total = md5end - md5begin;

    // calculate sha
    time_t shabegin = time(NULL);
    unsigned char sharesult[SHA_DIGEST_LENGTH];
    SHA((unsigned char*) buffer, length, sharesult);
    time_t shaend = time(NULL);
    time_t shatotal = shaend - shabegin;

    // calculate sha256
    time_t sha256begin = time(NULL);
    unsigned char sha256result[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*) buffer, length, sha256result);
    time_t sha256end = time(NULL);
    time_t sha256total = sha256end - sha256begin;

    int i;
    // output
    printf("md5:\t");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        printf("%02x", md5result[i]);
    printf("md5 time:\t%d\n", (int) md5total);

    printf("sha:\t");
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        printf("%02x", sharesult[i]);
    printf("sha time\t%d\n", (int) shatotal);

    printf("sha256: ");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", sha256result[i]);
    printf("sha256 time\t%d\n", (int) sha256total);
    
    return 0;
}