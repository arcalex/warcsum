/* 
 * 
 * Copyright (C) 2015 Bibliotheca Alexandrina
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
 * Given a compressed multimember warc.gz (or a singlemember warc.gz) file,
 * this program calculates its digest and appends it to given digests file.
 * 
 * Manifest contains following data:
 *      1. Warc file name
 *      2. Offset (compressed)
 *      3. End (compressed)
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
#include <sys/stat.h>
#include <sys/types.h>
#include <gzmulti.h>
#include <math.h>
#include <time.h>
#include <limits.h>

#define WARC_TYPE_LENGTH 10
#define CONTENT_TYPE_LENGTH 64
#define MANIFEST_LINE_SIZE 4*1024
#define FILE_NAME_LENGTH 1024
#define DATE_LENGTH 32
#define KEY_LENGTH 32
#define DIGEST_LENGTH 130
#define BINARY_SHA1_LENGTH 160

const char* WARC_HEADER = "WARC/1.0\r";
const char* CONTENT_LENGTH = "Content-Length";
const char* WARC_TYPE = "WARC-Type";
const char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
const char* WARC_TARGET_URI = "WARC-Target-URI";
const char* WARC_DATE = "WARC-Date";
const char* CONTENT_TYPE = "Content-Type";

/*
 * Structure that holds command line arguments
 */
struct cli_args
{
  int force_recalculate_digest;
  int verbose;
  int recursive;
  int hash_code;
  int skip_empty;
  char hash_char[KEY_LENGTH];
  char f_input[FILE_NAME_LENGTH];
  char f_output[FILE_NAME_LENGTH];
  unsigned int real_in;
  unsigned int real_out;
  int append;
};

/*
 * Structure that holds variables to be passed accross functions
 */
struct warcsum_struct
{
  struct cli_args args;
  FILE* f_in;
  void* hash_ctx;
  int response;
  int hash_algo;
  unsigned int START;
  unsigned int END;
  unsigned int effective_in;
  unsigned int effective_out;
  int need_double;
  char last_4[4];
  int size_last_4;
  char WARCFILE_NAME[FILE_NAME_LENGTH];
  char *URI;
  char DATE[DATE_LENGTH];
  char fixed_digest[DIGEST_LENGTH];
  char computed_digest[DIGEST_LENGTH];
  char manifest[MANIFEST_LINE_SIZE];
};

/*
 *  Initializes hash_ctx struct 
 */
int hash_init (void** hash_ctx, int hash);

/*
 * Finalize hash and produce digest in hex
 */
int hash_final (void* hash_ctx, int hash,
                char* computed_digest, struct cli_args args);

/*
 * Update hash struct with input buffer
 */
int hash_update (unsigned char* input, int algo, int lSize, void* hash_ctx);

/*
 * Converts base32 numbers following RFC 4648 to hexadecimal numbers
 */
int base32_to_hex (char* input, char* output);

/*
 * Compares 2 char*s and returns 0 if equal, 1 otherwise 
 */
short strcmp_case_insensitive (char* a, const char* b);

/*
 * Processes a directory of multi-member warc.gz 
 * and produces manifest foreach member
 */
int process_directory (char* input_dir, FILE* f_out,
                       z_stream* z, struct warcsum_struct* ws);

/*
 * Processes a multi-member warc.gz and produces manifest foreach member
 */
int process_file (char *in, FILE* f_out, z_stream* z, struct warcsum_struct* ws);

/*
 * Processes next member from warc.gz file pointer
 */
int process_member (FILE* in, FILE* out, z_stream *z, struct warcsum_struct *m);

/*
 * if provided chunk is at beginning of member,
 *    process header then hash payload
 * else hash payload.
 * Used as callback function by inflate member.
 */
void process_chunk (z_stream* z, int chunk, void* vp);

/* 
 * Process WARC header 
 */
int process_header (z_stream *z, void* vp);

/* 
 * Process warcheader to check if http response, then extract DATE and URI
 */
int process_warcheader (z_stream *z, void* vp);

/* 
 * Read the httpheader and skip it
 */
int process_httpheader (z_stream *z, void *vp, int header_offset);

/*
 * Parse and process command arguments and set cli_args struct
 */
int process_args (int argc, char **argv, struct cli_args* args);

/*
 * if provided chunk is at beginning of member, process header then hash payload
 * else hash payload.
 * Used as callback function by inflate member.
 * @param1: z_stream* holds inflated data and metadata
 * @param2: chuck to know if chunk is first, middle, last or first and last chunk
 * @param3: user defined struct or variable passed to inflate member to be used in process_chunk for general purposes
 */
void process_chunk (z_stream* z, int chunk, void* vp);


/*
 * Initialize z_stream and warcsum_struct
 */
void init (z_stream* z, struct warcsum_struct* m);

/*
 * Reset z_stream and warcsum_struct
 */
void reset (z_stream* z, struct warcsum_struct* m);

/*
 * Destroy z_stream 
 */
void end (z_stream* z);

/*
 * Display version
 */
void version ();

/*
 * Display help page
 */
void help ();

extern int versionsort ();
#endif	/* WARCSUM_H */

