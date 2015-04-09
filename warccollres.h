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
 */

#ifndef WARCCOLLRES_H
#define	WARCCOLLRES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <mysql/mysql.h>
#include <curl/curl.h>
#include <gzmulti.h>
#include <time.h>
#include <errno.h>

#define true 1
#define false 0
#define bool _Bool

bool quite = false, verbose = false;

char tmpFilenameTemplate [] = "warccollres-tmp-XXXXXXXXX";

static struct options {
    bool quite;
    bool verbose;
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

int
process_args(int argc, char** argv);

Record*
create_record(char * line);

void
destroy_record(Record *object);

void
dump_hash_cluster(FILE* output, Record *recList);

MYSQL*
mySQL_connect(FILE *dbSet, MYSQL *conn);

char*
get_url_from_db(MYSQL *conn, char* filename);

bool
compare_records(Record *first, Record *second);

bool
compare_records_file(Record *first, Record *second);

static size_t
write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp);

bool
http_download_file(char *url, Record *record);

bool
download_record(Record *record, MYSQL *conn, size_t *lineNo);

bool
inflate_record_member(Record *record);

void
process_chunk(z_stream *z, int chunk, void *vp);

#endif	/* WARCCOLLRES_H */