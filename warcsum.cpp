/* 
 * File:   main.c
 * Author: wsl
 *
 * Created on April 28, 2014, 11:58 AM
 */

#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <getopt.h>
#include <ftw.h>
using namespace std;

/*
 * 
 */
bool forceRecalc, decompress, verbose, recursive;
const string WARC_HEADER = "WARC/1.0\r";
const string CONTENT_LENGTH = "Content-Length";
const string WARC_TYPE = "WARC-Type";
const string WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
const string WARC_TARGET_URI = "WARC-Target-URI";
const string WARC_DATE = "WARC-Date";
string manifestFileName;

void hash(char* buffer, int hash, char* computedDigest) {
    // read the whole file

    long lSize = strlen(buffer);

    int i;
    unsigned char result[50];
    int j = 0;


    switch (hash) {
        case 1:
            // calculate md5
            MD5((unsigned char*) buffer, lSize, result);
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            computedDigest[j] = '\0';
            if (verbose) {
                printf("Hash: MD5\n");
            }
            break;
        case 2:
            // calculate sha1
            SHA1((unsigned char*) buffer, lSize, result);
            for (int i = 0; i < SHA_DIGEST_LENGTH; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            computedDigest[j] = '\0';
            if (verbose) {
                printf("Hash: SHA1\n");
            }
            break;
        case 3:
            // calculate sha256
            SHA256((unsigned char*) buffer, lSize, result);
            for (int i = 0; i < 50; i++, j += 2) {
                char temp[2];
                sprintf(temp, "%02x", result[i]);
                computedDigest[j] = temp[0];
                computedDigest[j + 1] = temp[1];
            }
            if (verbose) {
                printf("Hash: SHA256\n");
            }
            computedDigest[j] = '\0';
            break;
        default:
            exit(EXIT_FAILURE);
    }
}

unsigned char Base16EncodeNibble(unsigned char value) {
    if (value >= 0 && value <= 9)
        return value + 48;
    else if (value >= 10 && value <= 15)
        return (value - 10) + 65;
    else //assert(false);
    {
        cout << "Error: trying to convert value: " << value << endl;
    }

    return 42; // sentinal for error condition
}

string Base32DecodeBase16Encode(string input) {
    // Here's the base32 decoding:

    // The "Base 32 Encoding" section of http://tools.ietf.org/html/rfc4648#page-8
    // shows that every 8 bytes of base32 encoded data must be translated back into 5 bytes
    // of original data during a decoding process. The following code does this.
    string output;
    int input_len = input.length();
    assert(input_len == 32);
    const char * input_str = input.c_str();
    int output_len = (input_len * 5) / 8;
    assert(output_len == 20);
    // Because input strings are assumed to be SHA1 hash values in base32, it is also assumed
    // that they will be 32 characters (and bytes in this case) in length, and so the output
    // string should be 20 bytes in length.
    unsigned char *output_str = new unsigned char[output_len];

    char curr_char, temp_char;
    long long temp_buffer = 0; //formerly: __int64 temp_buffer = 0;
    for (int i = 0; i < input_len; i++) {
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
            unsigned char * source = reinterpret_cast<unsigned char*> (&temp_buffer);
            //strncpy(output_str+(5*(((i+1)/8)-1)), source, 5);
            int start_index = 5 * (((i + 1) / 8) - 1);
            int copy_index = 4;
            for (int x = start_index; x < (start_index + 5); x++, copy_index--)
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

    unsigned char out_temp, chr_temp;
    for (int y = 0; y < output_len; y++) {
        out_temp = Base16EncodeNibble(output_str[y] >> 4); //encode the high nibble
        output.append(1, static_cast<char> (out_temp));
        out_temp = Base16EncodeNibble(output_str[y] & 0xF); //encode the low nibble
        output.append(1, static_cast<char> (out_temp));
    }
    for (int i = 0; i < output.length(); i++) {
        if (output[i] >= 'A' && output[i] <= 'Z') {
            output[i] = output[i] - 'A' + 'a';
        }

    }

    delete []output_str;
    return output;
}

string gunzip(string warcGzFileName) { // to be changes to use unpack function in gzmulti
    string cmd = "gunzip -cd " + warcGzFileName + " > " + warcGzFileName + ".warc";
    system(cmd.c_str());
    warcGzFileName = warcGzFileName + ".warc";
    return warcGzFileName;
}

short algo;
char* t;

int manifest(string warcFileName, string manifestFileName) {
    ifstream warcFile;
    ofstream manifestFile;
    string FINAL_HASH;
    string FILENAME = "jan_BLA_BLA"; // to be changed when integrated with gzmulti
    string OFFSET = "101010"; // to be changed when integrated with gzmulti
    string URI;
    string DATE;
    string str;
    unsigned long lSize;
    string precomputed_digest = "";
    string precomputed_hash;
    string type;
    if (decompress) {
        warcFileName = gunzip(warcFileName);
    }
    warcFile.open(warcFileName.c_str(), ifstream::in);
    getline(warcFile, str);

    if (str.compare(WARC_HEADER)) {
        printf("Not a WARC file!!");
    }
    while (getline(warcFile, str) && str.compare("\r")) { // WARC Header
        stringstream ss(str);
        string key, value;
        ss >> key >> value;
        key = (string) key.substr(0, key.length() - 1);
        if (!key.compare(CONTENT_LENGTH)) {
            lSize = atoi(value.c_str());
            if (verbose) {
                printf("WARC content length: %s\n", value.c_str());
            }
        } else if (!key.compare(WARC_PAYLOAD_DIGEST)) {
            precomputed_hash = value.substr(0, value.find(":"));
            precomputed_digest = value.substr(value.find(":") + 1);
            if (verbose) {
                printf("WARC payload digest: %s\n", value.c_str());
            }
        } else if (!key.compare(WARC_TYPE)) {
            type = value;
            if (verbose) {
                printf("WARC type: %s\n", value.c_str());
            }
        } else if (!key.compare(WARC_DATE)) {
            DATE = value;
            if (verbose) {
                printf("WARC date: %s\n", value.c_str());
            }
        } else if (!key.compare(WARC_TARGET_URI)) {
            URI = value;
            if (verbose) {
                printf("WARC target uri: %s\n", value.c_str());
            }
        }
    }
    if (type.compare("response")) {
        printf("%s WARC-Type is not \"response\"\n", warcFileName.c_str());
        return 0;
    } else {
        string fixedDigest;
        if (precomputed_digest.compare("") && algo == 2 && !forceRecalc) {
            fixedDigest = Base32DecodeBase16Encode(precomputed_digest);
            printf("Stored hash:\tsha1:%s\n", fixedDigest.c_str());
            FINAL_HASH = fixedDigest;
        } else {
            while (getline(warcFile, str) && str.compare("\r")) { // HTTP Header
                stringstream ss(str);
                string key, value;
                ss >> key >> value;
                key = (string) key.substr(0, key.length() - 1);
                if (!key.compare(CONTENT_LENGTH)) {
                    lSize = atoi(value.c_str());
                    if (verbose) {
                        printf("HTTP content length: %s\n", value.c_str());
                    }
                }
            }
            char *buffer = new char[lSize];
            warcFile.read(buffer, lSize);
            if (verbose) {
                printf("Content read\n");
            }

            char computedDigest[50];
            hash(buffer, algo, computedDigest);
            if (verbose) {
                printf("Calculated digest:\t%s:%s\n", t, computedDigest);
            }
            FINAL_HASH = computedDigest;
            delete []buffer;
            //            delete t;
        }
    }
    manifestFile.open(manifestFileName.c_str(), ofstream::out | ofstream::app);
    string manifest = FILENAME + " " + warcFileName + " " + URI + " " + DATE + " " + FINAL_HASH + "\n";
    if (verbose) {
        printf("Manifest written\n");
    }
    if (decompress) { // to be changes to use unpack function in gzmulti
        string cmd = "rm " + warcFileName;
        system(cmd.c_str());
    }
    manifestFile << manifest;
    if (verbose) {
        printf("Manifest: %s\n", manifest.c_str());
    }
    return 0;
}

static int find_files(const char *fpath, const struct stat *sb,
        int tflag, struct FTW *ftwbuf) {
    if (tflag == FTW_D) {
        return 0;
    }
    string stfpath(fpath);
    if (verbose) {
        printf("\n\nProcessing %s\n", fpath);
    }
    manifest(fpath, manifestFileName);
    //    printf("%-3s %2d %7jd   %-40s %d %s\n",
    //            (tflag == FTW_D) ? "d" : (tflag == FTW_DNR) ? "dnr" :
    //            (tflag == FTW_DP) ? "dp" : (tflag == FTW_F) ? "f" :
    //            (tflag == FTW_NS) ? "ns" : (tflag == FTW_SL) ? "sl" :
    //            (tflag == FTW_SLN) ? "sln" : "???",
    //            ftwbuf->level, (intmax_t) sb->st_size,
    //            fpath, ftwbuf->base, fpath + ftwbuf->base);
    return 0; /* To tell nftw() to continue */
}

int main(int argc, char **argv) {
    forceRecalc = false;
    decompress = false;
    verbose = false;
    recursive = false;

    //    bool forceRecalc = false, decompress = false, verbose = false;
    int opt;
    string warcFileName = "";
    manifestFileName = "";
    while ((opt = getopt(argc, argv, "o:i:t:fxvr")) != -1) {
        switch (opt) {
            case 'i':
                warcFileName = optarg;
                break;
            case 't':
                t = new char[20];
                strcpy(t, optarg);
                if (!strcmp(t, "md5")) {
                    algo = 1;
                } else if (!strcmp(t, "sha1")) {
                    algo = 2;
                } else if (!strcmp(t, "sha256")) {
                    algo = 3;
                } else {
                    fprintf(stderr, "Invalid argument %s for -t. Options: md5, sha1, sha256\n", t);
                    exit(EXIT_FAILURE);
                }
                delete []t;
                break;
            case 'f':
                forceRecalc = true;
                break;
            case 'x':
                decompress = true;
                break;
            case 'o':
                manifestFileName = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'r':
                recursive = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input file | required] [-t hashing algorithm | required] [-o output file | required] [-f force digest calculation] [-x decompress][-r recursive]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!manifestFileName.compare("") || !warcFileName.compare("") || algo == 0) {
        fprintf(stderr, "Usage: %s [-i input file | required] [-t hashing algorithm | required] [-o output file | required] [-f force digest calculation] [-x decompress]\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!recursive) {
        manifest(warcFileName, manifestFileName);
    } else {
        int flags = 0;
        if (nftw(warcFileName.c_str(), find_files, 20, flags) == -1) {
            perror("nftw");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}


