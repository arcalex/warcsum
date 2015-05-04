/*
 * Copyright (C) 2014 Bibliotheca Alexandrina <archive.bibalex.org>
 * 
 * warccollres is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * warccollres is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * warccollres is part of the warcsum project.
 *
 * waccollres uses the digests manifest generated from warcsum sorted on the
 * digests column, and compares the content of the WARC members with the same
 * digest byte-by-byte to decide whether they are duplicates or collisions from
 * the hashing alogrithm that was used.
 * 
 * warccollres fetches the compressed WARC members from HTTP server(s), and the
 * URL for each WARC file is fetched from mySQL database containing the WARC
 * file name and the URL to download that file.
 * 
 * The digests manifest file contains following data:
 *     1. Warc file name
 *     2. Offset (compressed)
 *     3. End (compressed)
 *     4. URI
 *     5. Date
 *     6. Digest
 * 
 * The extended digest file contains following data:
 *     1. Warc file name
 *     2. Offset (compressed)
 *     3. End (compressed)
 *     4. URI
 *     5. Date
 *     6. Digest
 *     7. Digest extension
 * 
 * If the --proc was used, the extended digests manifest file will include:
 *     8. Copy number
 *     9. Reference member URI
 *     10. Reference member date
 * 
 * The digests manifest line should be in the format:
 * <WARC filename> <member offset> <member end> <URI> <date> <hash digest>
 * 
 * The extended digests manifest line should be in the format:
 * <WARC filename> <member offset> <member end> <URI> <date> <hash digest>
 * <hash extension>
 * 
 * The extended digests manifest with additional fields should be in the format:
 * <WARC filename> <member offset> <member end> <URI> <date> <hash digest>
 * <hash extension> <copy number> <reference uri> <reference date>
 */

#ifndef WARCCOLLRES_H
#define	WARCCOLLRES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <mysql/mysql.h>
#include <curl/curl.h>
#include <libconfig.h>
#include <gzmulti.h>
#include <time.h>
#include <errno.h>

#define true 1
#define false 0
#define bool _Bool

static struct options {
    size_t verbose;
    bool memory;
    bool proc;
    
    unsigned int input_buffer, output_buffer;

    char *iFile, *oFile, *dbFile;
} options;

static struct option long_options[] = {
    {"input", required_argument, 0, 'i'},
    {"output", required_argument, 0, 'o'},
    {"db-settings", required_argument, 0, 's'},
    {"proc", no_argument, 0, 'p'},
    {"input-buffer", required_argument, 0, 'I'},
    {"output-buffer", required_argument, 0, 'O'},
    {"memory-only", no_argument, 0, 'm'},
    {"quite", no_argument, 0, 'q'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

typedef struct MemoryStruct {
    char *memory;
    size_t size;
} MemoryStruct;

typedef struct Record {
    char *filename, *uri, *date, *hash;
    size_t offset, length, ext, copy_no, member_size;
    MemoryStruct *member_memory, *compressed_member_memory;
    struct Record *next, *next_collision;
    FILE *member_file, *compressed_member_file;
} Record;

void
version();

void
usage();

void
help();

int
process_args(int argc, char** argv);

Record*
create_record(char * line);

void
destroy_record(Record *object);

void
dump_hash_cluster(FILE* output, Record *recList);

MYSQL*
mySQL_connect(config_t *db_cfg, MYSQL *conn);

size_t
get_url_from_db(MYSQL *conn, char *filename, char ***url);

bool
compare_records(Record *first, Record *second);

bool
compare_records_file(Record *first, Record *second);

static size_t
write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp);

bool
http_download_file(char **url, size_t url_count, Record *record);

bool
download_record(Record *record, MYSQL *conn, size_t *lineNo);

bool
inflate_record_member(Record *record);

void
process_chunk(z_stream *z, int chunk, void *vp);

#endif	/* WARCCOLLRES_H */