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
using namespace std;

/*
 * 
 */
const string WARC_HEADER = "WARC/1.0\r";
const string CONTENT_LENGTH = "Content-Length";
const string WARC_TYPE = "WARC-Type";
const string WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";

void hash(char* buffer, int algo, char* computedDigest) {
    // read the whole file
    long lSize = strlen(buffer);
    int i;
    unsigned char result[50];
    int j = 0;
    //        if (algo == 1)
    //            computedDigest = new char[MD5_DIGEST_LENGTH];
    //        else if (algo == 2)
    //            computedDigest = new char[SHA_DIGEST_LENGTH];
    //        else if (algo == 3)
    //            computedDigest = new char[50];

    switch (algo) {
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

    delete [] output_str;
    return output;
}

int main(int argc, char **argv) {
    ifstream warcFile;
    bool forceRecalc = false, decompress = false;
    int opt;
    int algo;
    char* t = new char[20];
    string fileName;
    while ((opt = getopt(argc, argv, "i:t:fx")) != -1) {
        switch (opt) {
            case 'i':
                fileName = optarg;
                break;
            case 't':
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
                break;
            case 'f':
                forceRecalc = true;
                break;
            case 'x':
                decompress = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input file] [-t hashing algorithm] [-f force digest calculation] [-x decompress]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (decompress) {
        string cmd = "gunzip -cd " + fileName + " > " + fileName + ".warc";
        system(cmd.c_str());
        fileName = fileName + ".warc";
    }
    warcFile.open(fileName.c_str(), ifstream::in);
    string str;
    unsigned long lSize;
    string precomputed_digest = "";
    string precomputed_hash;
    string type;
    getline(warcFile, str);
    assert(!str.compare(WARC_HEADER));
    while (getline(warcFile, str) && str.compare("\r")) { // Header
        stringstream ss(str);
        string key, value;
        ss >> key >> value;
        key = (string) key.substr(0, key.length() - 1);
        if (!key.compare(CONTENT_LENGTH)) {
            lSize = atoi(value.c_str());
        } else if (!key.compare(WARC_PAYLOAD_DIGEST)) {
            precomputed_hash = value.substr(0, value.find(":"));
            precomputed_digest = value.substr(value.find(":") + 1);
        } else if (!key.compare(WARC_TYPE)) {
            type = value;
        }
    }
    if (type.compare("response")) {
        printf("WARC-Type is not \"response\"");
    } else {
        string fixedDigest;
        if (precomputed_digest.compare("") && algo == 2) {
            fixedDigest = Base32DecodeBase16Encode(precomputed_digest);
            printf("Stored hash:\tsha1:%s\n", fixedDigest.c_str());
        } else {
            while (getline(warcFile, str) && str.compare("\r")) { // Header
                stringstream ss(str);
                string key, value;
                ss >> key >> value;
                key = (string) key.substr(0, key.length() - 1);
                if (!key.compare(CONTENT_LENGTH)) {
                    lSize = atoi(value.c_str());
                }
            }
            char *buffer = new char[lSize];
            warcFile.read(buffer, lSize);
            char computedDigest[50];
            hash(buffer, algo, computedDigest);
            printf("Calculated digest:\t%s:%s\n", t, computedDigest);
            delete []buffer;
            delete []t;
        }
    }
    if (decompress) {
        string cmd = "rm " + fileName;
        system(cmd.c_str());
    }
    return 0;
}
