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

#define true 1
#define false 0
#define bool _Bool

bool quite = false, verbose = false;

typedef struct MemoryStruct
{
  char *memory;
  size_t size;
} MemoryStruct;

typedef struct Record
{
  char *filename, *uri, *date, *hash;
  size_t offset, length, ext, copyNo;
  MemoryStruct *data;
  struct Record *next, *nextColl;
} Record;

Record*
createRecord (char * line);

void
destroyRecord (Record *object);

void
dumpHashCluster (FILE* output, Record *recList, bool proc);

MYSQL*
mySQLConnect (FILE *dbSet, MYSQL *conn);

char*
getURLfromDB (MYSQL *conn, char* filename);

bool
compRec (Record *first, Record *second);

static size_t
WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp);

MemoryStruct*
httpDLFile (char *url, int offset, int length);




#endif	/* WARCCOLLRES_H */

