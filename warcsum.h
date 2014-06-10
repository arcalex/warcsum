/* 
 * 
 * Copyright (C) 2014 Bibliotheca Alexandrina
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * This program acts as the first step in arcalex project.
 * 
 * Given a multimember warc.gz file, this program calculates its 
 * manifest and appends it to given manifest file.
 * 
 * Manifest contains following data:
 *      1. Warc file name
 *      2. Offset (compressed)
 *      3. Length (compressed)
 *      4. URI
 *      5. Date
 *      6. Digest
 * 
 */


#ifndef __WARCSUM_H_
#define	__WARCSUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <getopt.h>
#include <ftw.h>
#include <unistd.h>
#include <zlib.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/dir.h>
#include <gzmulti.h>

#include <time.h>
//#define _SVID_SOURCE
//#define _BSD_SOURCE


#define MEMBER_SIZE 128*1024*1024
#define WARC_HEADER_SIZE 10*1024
#define WARC_TYPE_LENGTH 10
#define CONTENT_TYPE_LENGTH 20
#define HTTP_HEADER_SIZE 10*1024
#define MANIFEST_LINE_SIZE 4*1024
#define HEADER_LINE_SIZE 4*1024
#define FILE_NAME_LENGTH 1024
#define URL_LENGTH 4*1024
#define DATE_LENGTH 32
#define KEY_LENGTH 32
#define DIGEST_LENGTH 64
#define BINARY_SHA1_LENGTH 160

int hash_init(void** hash_ctx, int hash);

int hash_final(void* hash_ctx, int hash, char* computed_digest);

/*
 * Hashes input char* using algo (1: md5, 2:sha1, 3:sha256) and 
 * sets output with the digest
 */
int hash_update(unsigned char* input, int algo, int lSize, void* hash_ctx);

/*
 * Converts base32 numbers following RFC 4648 to hexadecimal numbers
 */
void base32_to_hex(char* input, char* output);

/*
 * Compares 2 char*s and returns 0 if equal, 1 otherwise 
 */
short strcmp_case_insensitive(char* a, char* b);

/*
 * Processes a single char* member and gets part of its manifest (URI, DATE,
 * FINAL_HASH) 
 */
int process_member(char* member, char* manifest_output, z_stream *z);

/*
 * Processes a multi-member warc.gz and produces manifest foreach member
 */
int process_multimember(char* warcFileName, char* manifestFileName);

/*
 * Processes a directory of multi-member warc.gz 
 * and produces manifest foreach member
 */
int process_directory(char* input_dir, char* manifest_filename);

/*
 * Processes warc member header
 * @return read bytes count if succeded, else -1
 */
int process_header(char* buffer, int length, char* URI, char* DATE,
        char* fixed_digest);

extern int versionsort();
#endif	/* WARCSUM_H */


