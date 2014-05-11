/* 
 * File:   main.c
 * Author: wsl
 *
 * Created on April 28, 2014, 11:58 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <getopt.h>
#include <ftw.h>
#include <unistd.h>

/*
 * 
 */
int forceRecalc, decompress, verbose, recursive;
const char* WARC_HEADER = "WARC/1.0\r";
const char* CONTENT_LENGTH = "Content-Length";
const char* WARC_TYPE = "WARC-Type";
const char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
const char* WARC_TARGET_URI = "WARC-Target-URI";
const char* WARC_DATE = "WARC-Date";
char* manifestFileName;

void hash(unsigned char* buffer, int hash, unsigned char* computedDigest) {
    // read the whole file

    long lSize = strlen((const char*) buffer);

    int i;
    unsigned char result[SHA256_DIGEST_LENGTH];
    int j = 0;


    switch (hash) {
        case 1:
            // calculate md5
            MD5(buffer, lSize, result);
            for (i = 0; i < MD5_DIGEST_LENGTH; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            computedDigest[j] = '\0';
            if (verbose) {
                printf("Hash: MD5 \n");
            }
            break;
        case 2:
            // calculate sha1
            SHA1(buffer, lSize, result);
            for (i = 0; i < SHA_DIGEST_LENGTH; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            computedDigest[j] = '\0';
            if (verbose) {
                printf("Hash: SHA1 \n");
            }
            break;
        case 3:
            // calculate sha256
            SHA256(buffer, lSize, result);
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            if (verbose) {
                printf("Hash: SHA256 \n");
            }
            computedDigest[j] = '\0';
            break;
        default:
            exit(EXIT_FAILURE);
    }
}

char Base16EncodeNibble(char value) {
    if (value >= 0 && value <= 9)
        return value + 48;
    else if (value >= 10 && value <= 15)
        return (value - 10) + 65;
    else //assert(0);
    {
        printf("Error: trying to convert value: %s\n", value);
    }

    return 42; // sentinal for error condition
}

char* Base32DecodeBase16Encode(char* input) {
    // Here's the base32 decoding:

    // The "Base 32 Encoding" section of http://tools.ietf.org/html/rfc4648#page-8
    // shows that every 8 bytes of base32 encoded data must be translated back into 5 bytes
    // of original data during a decoding process. The following code does this.
    char output[50];
    int input_len = strlen(input);
    assert(input_len == 32);
    char input_str[50];
    strcpy(input, input_str);
    int output_len = (input_len * 5) / 8;
    assert(output_len == 20);
    // Because input strings are assumed to be SHA1 hash values in base32, it is also assumed
    // that they will be 32 characters (and bytes in this case) in length, and so the output
    // string should be 20 bytes in length.
    char *output_str = (char*) malloc(output_len);

    char curr_char, temp_char;
    long long temp_buffer = 0; //formerly: __int64 temp_buffer = 0;
    int i = 0;
    for (i = 0; i < input_len; i++) {
        curr_char = input_str[i];
        if (curr_char >= 'A' && curr_char <= 'Z')
            temp_char = curr_char - 'A';
        if (curr_char >= '2' && curr_char <= '7')
            temp_char = curr_char - '2' + 26;

        if (temp_buffer)
            temp_buffer <<= 5; //temp_buffer = (temp_buffer << 5);
        temp_buffer |= temp_char;

        // if 8 encoded characters have been decoded into the temp location,
        // then copy them to the appropriate section of the final decoded location
        if ((i > 0) && !((i + 1) % 8)) {
            char * source = (char*) (&temp_buffer);
            //strncpy(output_str+(5*(((i+1)/8)-1)), source, 5);
            int start_index = 5 * (((i + 1) / 8) - 1);
            int copy_index = 4;
            int x;
            for (x = start_index; x < (start_index + 5); x++, copy_index--)
                output_str[x] = source[copy_index];
            temp_buffer = 0;

            // I could be mistaken, but I'm guessing that the necessity of copying
            // in "reverse" order results from temp_buffer's little endian byte order.
        }
    }

    // Here's the base16 encoding (for human-readable output and the chosen validation tests):

    // The "Base 16 Encoding" section of http://tools.ietf.org/html/rfc4648#page-10
    // shows that every byte original data must be encoded as two characters from the
    // base16 alphabet - one charactor for the original byte's high nibble, and one for
    // its low nibble.

    char out_temp, chr_temp;
    int y;
    for (y = 0; y < output_len; y++) {
        out_temp = Base16EncodeNibble(output_str[y] >> 4); //encode the high nibble
        output[y] = out_temp;
        //        output.append(1, static_cast<char> (out_temp));
        out_temp = Base16EncodeNibble(output_str[y] & 0xF); //encode the low nibble
        output[y] = out_temp;
        //        output.append(1, static_cast<char> (out_temp));
    }
    //    int i;
    for (i = 0; i < strlen(output); i++) {
        if (output[i] >= 'A' && output[i] <= 'Z') {
            output[i] = output[i] - 'A' + 'a';
        }

    }

    free(output_str);
    output_str = NULL;
    return output;
}

char* gunzip(char* warcGzFileName) { // to be changes to use unpack function in gzmulti
    //    string cmd = "gunzip -cd " + warcGzFileName + " > " + warcGzFileName + ".warc";
    char cmd[512];
    sprintf(cmd, "gunzip -cd %s > %s.warc", warcGzFileName, warcGzFileName);
    sprintf(warcGzFileName, "%s.warc", warcGzFileName);

    //    warcGzFileName = warcGzFileName + ".warc";
    return warcGzFileName;
}

short algo;
char* t;

int manifest(char* warcFileName, char* manifestFileName) {
    FILE* warcFile;
    FILE* manifestFile;
    char FINAL_HASH[128];
    char * FILENAME = "FILE_NAME"; // to be changed when integrated with gzmulti
    char * OFFSET = "OFFSET"; // to be changed when integrated with gzmulti
    char * C_SIZE = "SIZE"; // to be changed when integrated with gzmulti
    char URI[1024];
    char DATE[1024];
    char* str = (char *) malloc(1024);
    int lSize;
    char precomputed_digest[20];
    char precomputed_hash[20];
    char type[10];
    if (decompress) {
        warcFileName = gunzip(warcFileName);
    }
    warcFile = fopen(warcFileName, "r");
    //    warcFile.open(warcFileName.c_str(), ifstream::in);
    size_t line_L = 1024;
    getline(&str, &line_L, warcFile);

    if (strcmp(str, WARC_HEADER)) {
        printf("Not a WARC file!!");
    }
    while (getline(&str, &line_L, warcFile) && strcmp(str, "\r\n")) { // WARC Header
        //        stringstream ss(str);
        char *key, *value;
        char * pch;
        key = (char*) malloc(128);
        value = (char*) malloc(1024);
        pch = strtok(str, " \r\n");
        int i;
        for (i = 0; pch != NULL; i++) {
            if (i == 0) {
                memcpy(key, pch, strlen(pch) - 1);
//                strcpy(key, pch);
            } else if (strcmp(pch, "")) {
                strcpy(value, pch);
            }
            pch = strtok(NULL, " \n\r");
        }

        //        string key, value;
        //        ss >> key >> value;
        //        key = (string) key.substr(0, key.length() - 1);
        if (!strcmp(key, CONTENT_LENGTH)) {
            if (verbose) {
                printf("WARC content length: %s \n", value);
            }
        } else if (!strcmp(key, WARC_PAYLOAD_DIGEST)) {
            char * pch;
            pch = strtok(key, ":");
            int i;
            for (i = 0; pch != NULL; i++) {
                if (i == 0) {
                    strcpy(precomputed_hash, pch);
                } else if (strcmp(pch, "")) {
                    strcpy(precomputed_digest, pch);
                }
                pch = strtok(NULL, ":");
            }

            if (verbose) {
                printf("WARC payload digest: %s \n", value);
            }
        } else if (!strcmp(key, WARC_TYPE)) {
            strcpy(type, value);
            if (verbose) {
                printf("WARC type: %s \n", value);
            }
        } else if (!strcmp(key, WARC_DATE)) {
            strcpy(DATE, value);
            if (verbose) {
                printf("WARC date: %s \n", value);
            }
        } else if (!strcmp(key, WARC_TARGET_URI)) {
            strcpy(URI, value);
            if (verbose) {
                printf("WARC target uri: %s \n", value);
            }
        }
    }
    if (strcmp(type, "response")) {
        if (verbose) {
            printf("%s WARC-Type is not \"response\" \n", warcFileName);
        }
        return 0;
    } else {
        char *fixedDigest = (char*) malloc(20);
        if (strcmp(precomputed_digest, "") && algo == 2 && !forceRecalc) {
            fixedDigest = Base32DecodeBase16Encode(precomputed_digest);
            printf("Stored hash:\tsha1:%s \n", fixedDigest);
            strcpy(FINAL_HASH, fixedDigest);
        } else {
            while (getline(&str, &line_L, warcFile) && strcmp(str, "\r\n")) { // HTTP Header
                char key[128], value[1024];
                char* pch;
                pch = strtok(str, " :\r\n");
                int i;
                for (i = 0; pch != NULL; i++) {
                    if (i == 0) {
                        strcpy(key, pch);
                    } else if (strcmp(pch, "")) {
                        strcpy(value, pch);
                    }
                    pch = strtok(NULL, " :\r\n");
                }
                if (!strcmp(key, CONTENT_LENGTH)) {
                    strcpy(type, value);
                    if (verbose) {
                        printf("HTTP content length: %s \n", value);
                    }
                }
                //                stringstream ss(str);
                //                string key, value;
                //                ss >> key >> value;
                //                key = (string) key.substr(0, key.length() - 1);
                //                if (!key.compare(CONTENT_LENGTH)) {
                //                    lSize = atoi(value.c_str());
                //                    if (verbose) {
                //                        printf("HTTP content length: %s \n", value.c_str());
                //                    }
                //                }
            }
            //            cout << warcFileName << " " << lSize << endl;
            lSize = 100;
            char *buffer = (char*) malloc(lSize);
            size_t temp_size = fread(buffer, 1, lSize, warcFile);
            assert(temp_size == lSize);
            if (verbose) {
                printf("Content read \n");
            }

            char computedDigest[50];
            hash((unsigned char*) buffer, algo, (unsigned char*) computedDigest);
            if (verbose) {
                printf("Calculated digest:\t%s:%s \n", t, computedDigest);
            }
            strcpy(FINAL_HASH, computedDigest);
            //            delete []buffer;
            free(buffer);
            buffer = NULL;
            //            delete t;
        }
    }
    manifestFile = fopen(manifestFileName, "a");
    //    manifestFile.open(manifestFileName.c_str(), ofstream::out | ofstream::app);
    //    string manifest = FILENAME + " " + warcFileName + " " + URI + " " + DATE + " " + FINAL_HASH + " \n";
    char manifest[10240];
    sprintf(manifest, "%s %s %s %s %s %s %s\n", FILENAME, OFFSET, C_SIZE, URI, DATE, FINAL_HASH);
    if (verbose) {
        printf("Manifest written \n");
    }
    if (decompress) { // to be changes to use unpack function in gzmulti
        char cmd[1024];
        sprintf(cmd, "rm %s");
        system(cmd);
    }
    fwrite(manifest, 1, strlen(manifest), manifestFile);
    //    manifestFile << manifest;
    if (verbose) {
        printf("Manifest: %s \n", manifest);
    }
    return 0;
}

static int find_files(const char *fpath, const struct stat *sb,
        int tflag, struct FTW *ftwbuf) {
    if (tflag == FTW_D) {
        return 0;
    }
    //    string stfpath(fpath);
    if (verbose) {
        printf(" \n \nProcessing %s \n", fpath);
    }
    manifest((char *) fpath, manifestFileName);
    //    printf("%-3s %2d %7jd   %-40s %d %s \n",
    //            (tflag == FTW_D) ? "d" : (tflag == FTW_DNR) ? "dnr" :
    //            (tflag == FTW_DP) ? "dp" : (tflag == FTW_F) ? "f" :
    //            (tflag == FTW_NS) ? "ns" : (tflag == FTW_SL) ? "sl" :
    //            (tflag == FTW_SLN) ? "sln" : "???",
    //            ftwbuf->level, (intmax_t) sb->st_size,
    //            fpath, ftwbuf->base, fpath + ftwbuf->base);
    return 0; /* To tell nftw() to continue */
}

int main(int argc, char **argv) {
    forceRecalc = 0;
    decompress = 0;
    verbose = 0;
    recursive = 0;

    //    bool forceRecalc = 0, decompress = 0, verbose = 0;
    int opt;
    char warcFileName[1024] = "";
    //    string warcFileName = "";
    manifestFileName = (char*) malloc(10240);
    while ((opt = getopt(argc, argv, "o:i:t:fxvr")) != -1) {
        switch (opt) {
            case 'i':
                strcpy(warcFileName, optarg);
                break;
            case 't':
                t = (char*) malloc(20);
                strcpy(t, optarg);
                if (!strcmp(t, "md5")) {
                    algo = 1;
                } else if (!strcmp(t, "sha1")) {
                    algo = 2;
                } else if (!strcmp(t, "sha256")) {
                    algo = 3;
                } else {
                    fprintf(stderr, "Invalid argument %s for -t. Options: md5, sha1, sha256 \n", t);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'f':
                forceRecalc = 1;
                break;
            case 'x':
                decompress = 1;
                break;
            case 'o':
                strcpy(manifestFileName, optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'r':
                recursive = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input file | required] [-t hashing algorithm | required] [-o output file | required] [-f force digest calculation] [-x decompress][-r recursive] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!strcmp(manifestFileName, "") || !strcmp(warcFileName, "") || algo == 0) {
        fprintf(stderr, "Usage: %s [-i input file | required] [-t hashing algorithm | required] [-o output file | required] [-f force digest calculation] [-x decompress] \n",
                argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!recursive) {
        manifest(warcFileName, manifestFileName);
    } else {
        int flags = 0;
        if (nftw(warcFileName, find_files, 20, flags) == -1) {
            perror("nftw");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

