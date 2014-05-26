/*
 *
 * Created on April 28, 2014, 11:58 AM
 */
#include "warcsum.h"

int forceRecalc, decompress, verbose, recursive;
char* WARC_HEADER = "WARC/1.0\r";
char* CONTENT_LENGTH = "Content-Length";
char* WARC_TYPE = "WARC-Type";
char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
char* WARC_TARGET_URI = "WARC-Target-URI";
char* WARC_DATE = "WARC-Date";
char* CONTENT_TYPE = "Content-Type";

short algo;
char t[20];
int curOff;


const char * const b32_to_bin[] = {
    "00000",
    "00001",
    "00010",
    "00011",
    "00100",
    "00101",
    "00110",
    "00111",
    "01000",
    "01001",
    "01010",
    "01011",
    "01100",
    "01101",
    "01110",
    "01111",
    "10000",
    "10001",
    "10010",
    "10011",
    "10100",
    "10101",
    "10110",
    "10111",
    "11000",
    "11001",
    "11010",
    "11011",
    "11100",
    "11101",
    "11110",
    "11111"
};


const char const bin_to_hex[] = {
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f'
};

void hash(unsigned char* buffer, int hash, unsigned char* computedDigest, int lSize) {
    // read the whole file
    //    long lSize = z->total_out;

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

void base32_to_hex(char* in, char* out) {
    /* TEST */
    //    FILE* base32File;
    //    base32File = fopen("base32", "a");
    //    char base32[FILE_NAME_LENGTH];
    //    sprintf(base32, "%s\n", in);
    //    fwrite(base32, 1, strlen(base32), base32File);
    //    fclose(base32File);
    /* END of TEST */

    char binary[160];
    assert(strlen(in) == 32);
    int i;
    for (i = 0; i < strlen(in); i++) {
        if ((in[i] >= 'A' && in[i] <= 'Z')) {
            strcpy(&binary[i * 5], b32_to_bin[in[i] - 'A']);
        } else if (in[i] >= '2' && in[i] <= '7') {
            strcpy(&binary[i * 5], b32_to_bin[in[i] - ('2' - 26)]);
        } else {
            assert(0);
        }
    }
    //    char out[41];
    assert(strlen(binary) == 160);
    // Deal with commonly mistyped characters
    int s = 0;
    for (i = 0; i < strlen(binary); i += 4, s++) {
        char temp[4];
        memcpy(temp, &binary[i], 4);
        int j;
        int t = 0;
        for (j = 3; j >= 0; j--) {
            if (temp[j] == '1') {
                t |= (1 << (3 - j));
            }
        }
        out[s] = bin_to_hex[t];
    }
    out[40] = '\0';
    /* TEST */
    //    FILE* hexFile;
    //    hexFile = fopen("hex", "a");
    //    char hex[FILE_NAME_LENGTH];
    //    sprintf(hex, "%s\n", out);
    //    fwrite(hex, 1, strlen(hex), hexFile);
    //    fclose(hexFile);
    /* END of TEST */

}

short strcmp_case_insensitive(char* a, char* b) {
    if (strlen(a) != strlen(b)) {
        return 1;
    } else {
        int i = 0;
        while (a[i]) {
            if (tolower(a[i]) != tolower(b[i])) {
                return 1;
            }
            i++;
        }
        return 0;
    }
}

int process_member(char* member, char* manifest, z_stream *z) {
    char FINAL_HASH[SHA256_DIGEST_LENGTH];
    char URI[URL_LENGTH];
    char DATE[DATE_LENGTH];
    int lSize;
    char precomputed_digest[50];
    char precomputed_hash[10];
    char type[10];
    char content_type[20];
    char* str;
    char* member_end;
    short content_length_set = 0;
    short payload_digest_set = 0;

    str = strtok_r(member, "\n", &member_end);
    if (str != NULL && strcmp_case_insensitive(str, WARC_HEADER)) {
        //        printf("--Instead of Warc header, found:\n%s\n", str);
        if (verbose) {
            printf("Not a WARC file!!\n");
        }
        /* TEST */
        //        FILE* errorFile;
        //        errorFile = fopen("errorFile", "a");
        //        char fileN[FILE_NAME_LENGTH];
        //        sprintf(fileN, "%d\n", curOff);
        //        fwrite(fileN, 1, strlen(fileN), errorFile);
        //        fclose(errorFile);
        /* END of TEST */
        return 1;
    }

    str = strtok_r(NULL, "\n", &member_end);
    while (str != NULL && strcmp_case_insensitive(str, "\r")) { // WARC Header
        char key[KEY_LENGTH], value[WARC_HEADER_SIZE];
        char *pch;
        char *pch_end;
        pch = strtok_r(str, " \n", &pch_end);
        int i;

        for (i = 0; pch != NULL; i++) {
            if (i == 0) {
                memcpy(key, pch, strlen(pch) - 1);
                key[strlen(pch) - 1] = '\0';
            } else if (i == 1) {
                strcpy(value, pch);
            }
            pch = strtok_r(NULL, " \n\r", &pch_end);
        }

        free(pch);
        if (!strcmp_case_insensitive(key, CONTENT_LENGTH)) {
            if (verbose) {
                printf("WARC content length: %s \n", value);

            }
            lSize = atoi(value);
            content_length_set = 1;
        } else if (!strcmp_case_insensitive(key, WARC_PAYLOAD_DIGEST)) {
            payload_digest_set = 1;
            char* pch;
            char* pch_end;
            pch = strtok_r(value, ":\r\n ", &pch_end);
            int i;
            for (i = 0; pch != NULL; i++) {
                if (i == 0) {
                    memcpy(precomputed_hash, pch, strlen(pch));
                    precomputed_hash[strlen(pch)] = '\0';
                } else if (strcmp_case_insensitive(pch, "")) {
                    memcpy(precomputed_digest, pch, strlen(pch));
                    precomputed_digest[strlen(pch)] = '\0';
                }
                pch = strtok_r(NULL, ":", &pch_end);
            }


            if (verbose) {
                printf("WARC payload digest: %s:%s \n", precomputed_hash, precomputed_digest);
            }
            free(pch);
        } else if (!strcmp_case_insensitive(key, WARC_TYPE)) {
            strcpy(type, value);
            if (verbose) {
                printf("WARC type: %s \n", value);
            }
        } else if (!strcmp_case_insensitive(key, WARC_DATE)) {
            strcpy(DATE, value);
            if (verbose) {
                printf("WARC date: %s \n", value);
            }
        } else if (!strcmp_case_insensitive(key, WARC_TARGET_URI)) {
            strcpy(URI, value);
            if (verbose) {
                printf("WARC target uri: %s \n", value);
            }
        } else if (!strcmp_case_insensitive(key, CONTENT_TYPE)) {
            char* pch;
            char* pch_end;
            pch = strtok_r(value, ";\r\n ", &pch_end);
            memcpy(content_type, pch, strlen(pch));
            content_type[strlen(pch)] = '\0';

            if (verbose) {
                printf("Content-Type: %s \n", content_type);
            }
        }

        str = strtok_r(NULL, "\n", &member_end);
    }


    //    str = strtok_r(NULL, "\n", &member_end);
    //    member[lSize] = '\0';
    if (strcmp_case_insensitive(type, "response")) {
        if (verbose) {
            printf("WARC-Type is not \"response\" \n");
        }
        return 1;
    } else if (strcmp_case_insensitive(content_type, "application/http")) {
        if (verbose) {
            printf("Response is not HTTP. \n");
        }
        return 1;
    } else {

        if (payload_digest_set && algo == 2 && !forceRecalc) {
            char fixedDigest[SHA256_DIGEST_LENGTH];
            base32_to_hex(precomputed_digest, fixedDigest);
            strcpy(FINAL_HASH, fixedDigest);
            //            free(fixedDigest);
        } else {
            str = strtok_r(NULL, "\n", &member_end);
            while (str != NULL && strcmp_case_insensitive(str, "\r") && member_end[0] != '\n') { // HTTP Header
                str = strtok_r(NULL, "\n", &member_end);
            }
            int lSize = member_end - member;
            char computedDigest[50];
            /* TEST */
            //            FILE* testout;
            //            char filename[10];
            //            sprintf(filename, "SentToHash");
            //            testout = fopen(filename, "w");
            //            fwrite(member_end, 1, z->total_out, testout);
            //            fclose(testout);
            /* END OF TEST */
            hash((unsigned char*) member_end, algo, (unsigned char*) computedDigest, z->total_out - lSize);
            if (verbose) {
                printf("Calculated digest:\t%s:%s \n", t, computedDigest);
            }
            strcpy(FINAL_HASH, computedDigest);

        }

    }


    sprintf(manifest, "%s %s %s", URI, DATE, FINAL_HASH);

    member_end = NULL;
    /* TEST */
    //    FILE* doneFile;
    //    doneFile = fopen("doneFile", "a");
    //    char fileN[FILE_NAME_LENGTH];
    //    sprintf(fileN, "%d\n", curOff);
    //    fwrite(fileN, 1, strlen(fileN), doneFile);
    //    fclose(doneFile);
    /* END of TEST */
    return 0;
}

int manifest(char* warcFileName, char* manifestFileName) {

    //int manifest(void) {
    char temp_FILENAME[FILE_NAME_LENGTH];
    strcpy(temp_FILENAME, warcFileName);
    printf("%s\n%s\n", temp_FILENAME, manifestFileName);

    FILE* warcFile;
    FILE* manifestFile;
    warcFile = fopen(temp_FILENAME, "r");
    if (warcFile == NULL) {
        printf("ERROR opening file!!");
        exit(1);
    }
    /* Inflate Member to member */
    long int START = 0, END = 0, C_SIZE = 0;
    char FILENAME[FILE_NAME_LENGTH];
    char* pch;
    char* pch_end;
    pch = strtok_r(temp_FILENAME, "/\\", &pch_end);
    int i;
    for (i = 0; pch != NULL; i++) {
        strcpy(FILENAME, pch);
        pch = strtok_r(NULL, "/\\", &pch_end);
    }
    pch_end = NULL;
    fseek(warcFile, 0, SEEK_END);
    long fsize = ftell(warcFile);
    fseek(warcFile, 0, SEEK_SET);
    z_stream z;

    START = ftell(warcFile);
    while (ftell(warcFile) != fsize) {
        unsigned char member[MEMBER_SIZE];

        START = ftell(warcFile);
        curOff = START;
        gzmInflateInit(&z);

        inflateMember(warcFile, &z, member, MEMBER_SIZE);

        (void) inflateEnd(&z);

        END = ftell(warcFile);
        if (END == fsize) {
            END--;
        }
        //        printf("length before *** %d\n", strlen(member));
        C_SIZE = END - START;
        //        curOff = END;
        if (verbose) {
            printf("Member inflated at %d through %d\n", START, END);
        }
        //        printf("%s", member);
        //        exit(1);
        z.total_out -= 4;
        /* TEST */
        //        FILE* testout;
        //        char filename[10];
        //        sprintf(filename, "mem/%d", START);
        //        testout = fopen(filename, "w");
        //        fwrite(member, 1, z.total_out, testout);
        //        fclose(testout);
        /* END OF TEST */

        //strcpy(memberBak, member);



        char manifest[MANIFEST_LINE_SIZE];
        int status = process_member(member, manifest, &z);

        if (status) {
            continue;

        }
        if (verbose) {
            printf("Manifest1: %s \n", manifest);
        }

        char manifest2[MANIFEST_LINE_SIZE];
        sprintf(manifest2, "%s %ld %ld %s\n", FILENAME, START, C_SIZE, manifest);
        if (verbose) {
            printf("Manifest written \n");
        }


        manifestFile = fopen(manifestFileName, "a");
        fwrite(manifest2, 1, strlen(manifest2), manifestFile);

        if (verbose) {
            printf("Manifest: %s \n", manifest2);
        }
        fclose(manifestFile);
    }

    return 0;
}

void list_directory(char *input_dir, int *number, char*** file_names) {
    struct dirent **files;
    char new_path[1000];
    struct stat st;
    int i;
    *number = scandir(input_dir, &files, 0, versionsort);
    *file_names = malloc(*number);
    if (*number < 0) {
        perror(input_dir);
    } else {
        for (i = 0; i < *number; i++) {
            (*file_names)[i] = malloc(FILE_NAME_LENGTH);
            // new_path contains relative path from the directory
            sprintf(new_path, "%s/%s", input_dir, files[i]->d_name);
            if (!strcmp(files[i]->d_name, ".")
                    || !strcmp(files[i]->d_name, "..") || S_ISDIR(st.st_mode)) {
                (*file_names)[i] = ".";
                continue;
            }
            strcpy((*file_names)[i], new_path);
        }
    }
}

int main(int argc, char **argv) {
    forceRecalc = 0;
    decompress = 0;
    verbose = 0;
    recursive = 0;

    int opt;
    char warcFileName[FILE_NAME_LENGTH];
    char manifestFileName[FILE_NAME_LENGTH];

    while ((opt = getopt(argc, argv, "o:i:t:fxvr")) != -1) {
        switch (opt) {
            case 'i':
                strcpy(warcFileName, optarg);
                break;
            case 't':
                strcpy(t, optarg);
                if (!strcmp_case_insensitive(t, "md5")) {
                    algo = 1;
                } else if (!strcmp_case_insensitive(t, "sha1")) {
                    algo = 2;
                } else if (!strcmp_case_insensitive(t, "sha256")) {
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
    if (!recursive) {
        printf("%s\n%s\n", warcFileName, manifestFileName);
        //manifest(warcFileName, manifestFileName);
        manifest(warcFileName, manifestFileName);
    } else {
        int n;
        char** file_names;
        list_directory(warcFileName, &n, &file_names);
        int i;

        for (i = 0; i < n; i++) {
            if (strcmp(file_names[i], ".")) {
                manifest(file_names[i], manifestFileName);
            }
        }
        //        for (i = 0; i < n; i++) {
        //            free(files[i]);
        //        }

    }
    return 0;
}
