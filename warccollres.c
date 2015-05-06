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

#include "warccollres.h"

clock_t start, end;
double compareTime = 0, downloadTime = 0, databaseTime = 0;

Record*
create_record (char * line)
{
  /* The Record constructor */
  Record *object = calloc (1, sizeof (Record));
  object->next = NULL;
  object->next_collision = NULL;
  object->member_memory = NULL;
  object->compressed_member_memory = NULL;
  object->member_file = NULL;
  object->compressed_member_file = NULL;
  object->member_size = 0;

  /* Parsing the input line and storing its token in the Record structure */
  char* token = NULL;
  token = strtok (line, " ");
  object->filename = calloc (strlen (token) + 1, sizeof (char));
  strcpy (object->filename, token);
  object->offset = atoi (strtok (NULL, " "));
  object->length = atoi (strtok (NULL, " "));
  token = strtok (NULL, " ");
  object->uri = calloc (strlen (token) + 1, sizeof (char));
  strcpy (object->uri, token);
  token = strtok (NULL, " ");
  object->date = calloc (strlen (token) + 1, sizeof (char));
  strcpy (object->date, token);
  token = strtok (NULL, " ");
  object->hash = calloc (strlen (token) + 1, sizeof (char));
  strcpy (object->hash, token);
  return object;
}

void
destroy_record (Record *object)
{
  /* The Record destructor */
  if (object == NULL)
    return;
  if (object->member_file != NULL)
    {
      fclose (object->member_file);
      object->member_file = NULL;
    }
  if (object->compressed_member_file != NULL)
    {
      fclose (object->compressed_member_file);
      object->compressed_member_file = NULL;
    }
  if (object->filename)
    free (object->filename);
  if (object->uri)
    free (object->uri);
  if (object->date)
    free (object->date);
  if (object->hash)
    free (object->hash);
  if (object->member_memory != NULL && object->member_memory->size > 0)
    free (object->member_memory->memory);
  if (object->member_memory != NULL)
    free (object->member_memory);
  if (object->compressed_member_memory != NULL)
    free (object->compressed_member_memory);
  object->filename = NULL;
  object->uri = NULL;
  object->hash = NULL;
  object->date = NULL;
  object->member_memory = NULL;
  if (object->next_collision != NULL)
    destroy_record (object->next_collision);
  if (object->next != NULL)
    destroy_record (object->next);
  object->next = NULL;
  object->next_collision = NULL;
  free (object);
  object = NULL;
}

void
dump_hash_cluster (FILE* output, Record *recList)
{
  /* Dumping the previous hash cluster to the output file */
  Record *tempColl = recList;
  /* Dumping the collided records */
  while (tempColl != NULL)
    {
      /* Dumping the similar records */
      Record *tempRec = tempColl;
      while (tempRec != NULL)
        {
          fprintf (output, "%s %zu %zu %s %s %s %zu"
                   , tempRec->filename
                   , tempRec->offset
                   , tempRec->length
                   , tempRec->uri
                   , tempRec->date
                   , tempRec->hash
                   , tempRec->ext);
          if (options.proc)
            {
              fprintf (output, " %zu", tempRec->copy_no);
              if (tempRec->copy_no == 1)
                fprintf (output, " - -");
              else
                fprintf (output, " %s %s"
                         , tempColl->uri
                         , tempColl->date);

            }
          fprintf (output, "\n");
          /* Preparing the next record */
          tempRec = tempRec->next;
        }
      tempColl = tempColl->next_collision;
    }
}

MYSQL *
mySQL_connect (config_t *db_cfg, MYSQL * conn)
{
  const char *server = NULL, *user = NULL, *password = NULL, *database = NULL;

  /* 
   * Get the database server.
   */
  if (!config_lookup_string (db_cfg, "server", &server))
    {
      fprintf (stderr, "No server set in configuration file.\n");
      return NULL;
    }
  
  /* 
   * Get the database user.
   */
  if (!config_lookup_string (db_cfg, "user", &user))
    {
      fprintf (stderr, "No user set in configuration file.\n");
      return NULL;
    }
  
  /* 
   * Get the database password.
   */
  if (!config_lookup_string (db_cfg, "password", &password))
    {
      fprintf (stderr, "No password set in configuration file.\n");
      return NULL;
    }
  
  /* 
   * Get the database name.
   */
  if (!config_lookup_string (db_cfg, "database", &database))
    {
      fprintf (stderr, "No database set in configuration file.\n");
      return NULL;
    }

  conn = mysql_init (NULL);
  /* Connect to database */
  if (!mysql_real_connect (conn, server,
                           user, password, database, 0, NULL, 0))
    {
      fprintf (stderr, "%s\n", mysql_error (conn));
      return NULL;
    }
  
  return conn;
}

size_t
get_url_from_db (MYSQL *conn, char *filename, char ***url)
{
  MYSQL_RES *res;
  MYSQL_ROW row;

  /* send SQL query */
  char temp[] = "SELECT url FROM `path_index` WHERE filename = '";
  char *query = (char*) calloc (strlen (temp) + strlen (filename) + 2,
                                sizeof (char));
  strcpy (query, temp);
  strcat (query, filename);
  strcat (query, "'");

  if (mysql_query (conn, query))
    {
      fprintf (stderr, "%s\n", mysql_error (conn));
      exit (1);
    }
  free (query);

  /*
   *  Get the result.
   */
  res = mysql_store_result (conn);

  /*
   *  Get number of rows in the result.
   */
  int res_count = mysql_num_rows (res);

  *url = calloc (res_count, sizeof (char*));

  int i;

  for (i = 0; i < res_count; i++)
    {
      row = mysql_fetch_row (res);
      if (row && row[0] != NULL)
        {
          (*url)[i] = calloc (strlen (row[0]), sizeof (char));
          strcpy ((*url)[i], row[0]);
        }
      else
        {
          (*url)[i] = NULL;
        }
    }
  mysql_free_result (res);
  return res_count;
}

bool
compare_records (Record *first, Record * second)
{
  long firstIndex = 0, secondIndex = 0;

  //Seeking to the end of the WARC header of the first record.
  for (firstIndex;
          first->member_memory->memory[firstIndex] != '\n' ||
          (first->member_memory->memory[firstIndex + 1] != '\n' &&
           first->member_memory->memory[firstIndex + 2] != '\n');
          firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;
  //Seeking to the end of the HTTP header of the first record.
  for (firstIndex;
          first->member_memory->memory[firstIndex] != '\n' ||
          (first->member_memory->memory[firstIndex + 1] != '\n' &&
           first->member_memory->memory[firstIndex + 2] != '\n');
          firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;
  //Seeking to the end of the WARC header of the second record.
  for (secondIndex;
          second->member_memory->memory[secondIndex] != '\n' ||
          (second->member_memory->memory[secondIndex + 1] != '\n' &&
           second->member_memory->memory[secondIndex + 2] != '\n');
          secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;
  //Seeking to the end of the HTTP header of the second record.
  for (secondIndex;
          second->member_memory->memory[secondIndex] != '\n' ||
          (second->member_memory->memory[secondIndex + 1] != '\n' &&
           second->member_memory->memory[secondIndex + 2] != '\n');
          secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;


  if ((first->member_memory->size - firstIndex) !=
      (second->member_memory->size - secondIndex))
    return false;
  while (firstIndex < first->member_memory->size - 4 &&
         secondIndex < second->member_memory->size - 4)
    {
      if (first->member_memory->memory[firstIndex++] !=
          second->member_memory->memory[secondIndex++])
        return false;
    }
  return true;
}

//TODO

bool
compare_records_file (Record *first, Record * second)
{
  size_t len = 0, read = 0, firstIndex, secondIndex;
  char *line = NULL, *firstBuffer, *secondBuffer;

  rewind (first->member_file);
  rewind (second->member_file);

  //Seeking to the end of the WARC header of the first record.
  while (!feof (first->member_file) &&
         (read = getline (&line, &len, first->member_file)) > 0)
    {
      if (read == 2 && line[0] == '\r' && line[1] == '\n')
        break;
      free (line);
      line = NULL;
      len = 0;
    }
  free (line);
  line = NULL;

  //Seeking to the end of the HTTP header of the first record.
  while (!feof (first->member_file) &&
         (read = getline (&line, &len, first->member_file)) > 0)
    {
      if ((read == 2 && line[0] == '\r' && line[1] == '\n') || \
          (read == 1 && line[0] == '\n'))
        break;
      free (line);
      line = NULL;
      len = 0;
    }
  free (line);
  line = NULL;
  len = 0;

  //Seeking to the end of the WARC header of the second record.
  while (!feof (second->member_file) &&
         (read = getline (&line, &len, second->member_file)) > 0)
    {
      if (read == 2 && line[0] == '\r' && line[1] == '\n')
        break;
      free (line);
      line = NULL;
      len = 0;
    }
  free (line);
  line = NULL;
  len = 0;

  //Seeking to the end of the HTTP header of the second record.
  while (!feof (second->member_file) &&
         (read = getline (&line, &len, second->member_file)) > 0)
    {
      if ((read == 2 && line[0] == '\r' && line[1] == '\n') || \
          (read == 1 && line[0] == '\n'))
        break;
      free (line);
      line = NULL;
      len = 0;
    }
  free (line);
  line = NULL;
  len = 0;

  firstIndex = ftell (first->member_file);
  secondIndex = ftell (second->member_file);

  //Compare the content size, if the size matches, then continue the comparison.
  if ((first->member_size - firstIndex) != (second->member_size - secondIndex))
    return false;

  firstBuffer = calloc (options.output_buffer, sizeof (char));
  secondBuffer = calloc (options.output_buffer, sizeof (char));

  while (!(feof (first->member_file) && feof (first->member_file)))
    {
      read = fread (firstBuffer, 1, options.output_buffer, first->member_file);
      read = fread (secondBuffer, 1, options.output_buffer,
                    second->member_file);

      size_t i;
      for (i = 0; i < read; i++)
        {
          if (firstBuffer[i] != secondBuffer[i])
            return false;
        }
    }
  free (firstBuffer);
  firstBuffer = NULL;

  free (secondBuffer);
  secondBuffer = NULL;

  return true;
}

//TODO

void
process_chunk (z_stream *z, int chunk, void *vp)
{
  Record* record = (Record*) vp;

  if (options.memory)
    {
      record->member_memory->memory = realloc (record->member_memory->memory,
                                               z->total_out);
      memcpy (&(record->member_memory->memory[record->member_memory->size]),
              z->next_out, (z->total_out - record->member_memory->size));
      record->member_memory->size = z->total_out;
    }
  else
    {
      fwrite (z->next_out, 1, (z->total_out - record->member_size),
              record->member_file);
    }
  record->member_size = z->total_out;
}

/*
 * Inflated the downloaded WARC member to either a file, or memory structure if
 * the --memory-only option was used.
 * 
 * Takes as input a pointer to the whole record structure the contains the
 * compressed WARC member.
 * 
 * Returns a true if the inflation process was successful, and false otherwise.
 */

bool
inflate_record_member (Record *record)
{
  z_stream z;
  gzmInflateInit (&z);
  //extra byte for the null terminator
  z.next_in = calloc (options.input_buffer + 1, sizeof (Bytef));
  z.next_out = calloc (options.output_buffer + 1, sizeof (Bytef));

  if (options.memory)
    {
      FILE* outf = fmemopen (record->compressed_member_memory->memory,
                             record->compressed_member_memory->size, "r");

      record->member_memory = (MemoryStruct *) malloc (sizeof (MemoryStruct));
      record->member_memory->size = 0;
      record->member_memory->memory = calloc (1, sizeof (char));

      inflateMember (&z, outf, options.input_buffer, options.output_buffer
                     , process_chunk, record);

      fclose (outf);

      free (record->compressed_member_memory->memory);
      record->compressed_member_memory->memory = NULL;
      record->compressed_member_memory->size = 0;
      free (record->compressed_member_memory);
      record->compressed_member_memory = NULL;
    }
  else
    {
      if ((record->member_file = tmpfile ()) == NULL)
        {
          fprintf (stderr, "%s\n", strerror (errno));
          free (z.next_in);
          free (z.next_in);
          return false;
        }

      record->member_size = 0;

      rewind (record->compressed_member_file);

      inflateMember (&z, record->compressed_member_file, options.input_buffer,
                     options.output_buffer, process_chunk, record);

      if (fclose (record->compressed_member_file))
        fprintf (stderr, "Error: Could not close temp file.");
      record->compressed_member_file = NULL;
    }
  inflateEnd (&z);
  free (z.next_in);
  free (z.next_out);
  return true;
}

static size_t
write_memory_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct Record *record = (struct Record *) userp;

  if (options.memory)
    {
      record->compressed_member_memory->memory =
              realloc (record->compressed_member_memory->memory,
                       record->compressed_member_memory->size + realsize + 1);

      if (record->compressed_member_memory->memory == NULL)
        {
          /* out of memory! */
          printf ("not enough memory (realloc returned NULL)\n");
          return 0;
        }
      size_t size = record->compressed_member_memory->size;
      memcpy (&(record->compressed_member_memory->memory[size]),
              contents, realsize);
      record->compressed_member_memory->size += realsize;
      //record->compressed_member_memory->memory[record->compressed_member_memory->size] = 0;
    }
  else
    {
      fwrite (contents, 1, realsize, record->compressed_member_file);
    }
  record->member_size += realsize;

  return realsize;
}

bool
http_download_file (char **url, size_t url_count, Record *record)
{
  CURL *curl_handle;
  CURLcode res;

  char* range = (char*) calloc (50, sizeof (char));
  snprintf (range, 50, "%zu-%zu", record->offset,
            record->offset + record->length - 1);

  if (options.memory)
    {
      record->compressed_member_memory =
              (MemoryStruct *) calloc (1, sizeof (MemoryStruct));

      /*
       *******************************************
       * Will be grown as needed by the realloc. *
       *******************************************
       */
      record->compressed_member_memory->memory =
              (char*) calloc (1, sizeof (char));
      record->compressed_member_memory->size = 0;
    }
  else
    {
      /*
       **********************************************
       * Write the compressed member to a temp file *
       **********************************************
       */
      if ((record->compressed_member_file = tmpfile ()) == NULL)
        {
          fprintf (stderr, "%s\n", strerror (errno));
          return false;
        }
    }

  /* init the curl session */
  curl_handle = curl_easy_init ();

  /* send all data to this function  */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEDATA, (void *) record);

  curl_easy_setopt (curl_handle, CURLOPT_RANGE, range);

  curl_easy_setopt (curl_handle, CURLOPT_FAILONERROR, 1);

  bool downloaded = false;

  int i;

  for (i = 0; i < url_count; i++)
    {
      /* specify URL to get */
      curl_easy_setopt (curl_handle, CURLOPT_URL, url[i]);
      /* get it! */
      res = curl_easy_perform (curl_handle);

      /*
       * Check if there was any error.
       */
      if (res == CURLE_OK)
        {
          downloaded = true;
          break;
        }
    }


  /* check for errors */
  if (!downloaded)
    {
      fprintf (stderr, "curl_easy_perform() failed: %s\n",
               curl_easy_strerror (res));
      return false;
    }
  else
    {
      if (!options.memory)
        rewind (record->compressed_member_file);

      /*inflate here. */
      if (!inflate_record_member (record))
        return false;
    }
  /* cleanup curl stuff */
  curl_easy_cleanup (curl_handle);

  free (range);

  return true;
}

bool
download_record (Record *record, MYSQL *conn, size_t *lineNo)
{
  /* 
   **************************************************************
   * Obtain the URL where the file is located from the database *
   **************************************************************
   */
  char **url = NULL;
  size_t url_count = 0;
  start = clock ();
  url_count = get_url_from_db (conn, record->filename, &url);
  end = clock ();
  databaseTime += ((double) (end - start)) / CLOCKS_PER_SEC;
  if (url == NULL)
    {
      if (!options.verbose)
        fprintf (stderr, "Error: Could not find a server for the processed "
                 "record in line %ld.\n", *lineNo);
      destroy_record (record);
      return false;
    }

  /*
   ***************************************
   * Get the member from the HTTP server *
   ***************************************
   */
  start = clock ();
  if (!http_download_file (url, url_count, record))
    return false;
  end = clock ();

  downloadTime += ((double) (end - start)) / CLOCKS_PER_SEC;
  free (url);
  if (record->member_size == 0)
    {
      if (!options.verbose)
        fprintf (stderr, "Error: Could not download the member from the "
                 "HTTP server for the processed record in line %ld.\n",
                 *lineNo);
      destroy_record (record);
      return false;
    }
  return true;
}

/*
 *******************
 * Display version *
 *******************
 */
void
version ()
{
  printf ("GNU warccollres 0.1\n"
          " * Copyright (C) 2014 Bibliotheca Alexandrina\n");
}

/*
 *****************
 * Display usage *
 *****************
 */

void
usage ()
{
  fprintf (stderr, "Usage: warccollres [-i | --input <filename>]"
           "[-o | --output <filename>] [-s | --db-settings <filename>] "
           "[-p | --proc] [-I | --input-buffer] [-O | --output-buffer] "
           "[-m | --memory-only][-q | --quite] [-v | --verbose]\n");
}

/*
 *****************
 * Display help *
 *****************
 */

void
help ()
{
  printf ("Usage\n");

  printf ("\tUsage: warccollres [-i | --input <filename>]"
          "[-o | --output <filename>] [-s | --db-settings <filename>] "
          "[-p | --proc] [-I | --input-buffer] [-O | --output-buffer] "
          "[-m | --memory-only][-q | --quite] [-v | --verbose]\n\n");

  printf ("Options\n");

  printf ("\t-i, --input=FILE\n");
  printf ("\t\tPath to digests manifest file.\n\n");

  printf ("\t-o, --output=FILE\n");
  printf ("\t\tPath to extended digests manifest file.\n\n");

  printf ("\t-o, --db-settings=FILE\n");
  printf ("\t\tPath to the database settings file.\n\n");

  printf ("\t-I, --input-buffer=NUMBER\n");
  printf ("\t\tsize of the buffer used to read/write compressed temp "
          "files.\n\n");

  printf ("\t-O, --output-buffer=NUMBER\n");
  printf ("\t\tsize of the buffer used to read/write inflated temp files.\n\n");

  printf ("\t-p, --proc\n");
  printf ("\t\tResolve the reference of duplicate WARC members.\n\n");

  printf ("\t-m, --memory-only\n");
  printf ("\t\tPerform all processing in memory only.\n");

  printf ("\t-v, --verbose\n");
  printf ("\t\tVerbose mode. Print more messages about the process.\n\n");

  printf ("\t-q, --quite\n");
  printf ("\t\tQuite mode. Do not print any messages about the process.\n\n");

  printf ("\t-V, --version\n");
  printf ("\t\tPrint the version.\n\n");

  printf ("\t-h, --help\n");
  printf ("\t\tPrint this help message.\n\n");
}

int
process_args (int argc, char** argv)
{
  options.verbose = 1;
  options.memory = false;
  options.proc = false;
  options.iFile = NULL;
  options.oFile = NULL;
  options.dbFile = NULL;

  options.input_buffer = 8 * 1024;
  options.output_buffer = 16 * 1024;

  int opt, option_index = 0;

  while ((opt = getopt_long (argc, argv, ":i:o:s:I:O:pqvm",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'i':
          if (strlen (optarg) > 0)
            {
              options.iFile = calloc (strlen (optarg) + 1, sizeof (char));
              strcpy (options.iFile, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No input file was specified.\n");
            }
          break;
        case 'o':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              options.oFile = calloc (strlen (optarg) + 1, sizeof (char));
              strcpy (options.oFile, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No output file was specified.\n");
            }
          break;
        case 's':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              options.dbFile = calloc (strlen (optarg) + 1, sizeof (char));
              strcpy (options.dbFile, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No database settings file was "
                       "specified.\n");
            }
          break;
        case 'I':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              int length = strlen (optarg);
              switch (optarg[length - 1])
                {
                case 'K':
                  options.input_buffer = atoi (optarg) * 1024;
                  break;
                case 'M':
                  options.input_buffer = atoi (optarg) * 1024 * 1024;
                  break;
                case 'G':
                  options.input_buffer = atoi (optarg) * 1024 * 1024 * 1024;
                  break;
                default:
                  options.input_buffer = atoi (optarg);
                }
            }
          else
            {
              fprintf (stderr, "Error: Unrecognized input buffer.\n");
            }
          break;
        case 'O':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              int length = strlen (optarg);
              switch (optarg[length - 1])
                {
                case 'K':
                  options.output_buffer = atoi (optarg) * 1024;
                  break;
                case 'M':
                  options.output_buffer = atoi (optarg) * 1024 * 1024;
                  break;
                case 'G':
                  options.output_buffer = atoi (optarg) * 1024 * 1024 * 1024;
                  break;
                default:
                  options.output_buffer = atoi (optarg);
                }
            }
          else
            {
              fprintf (stderr, "Error: Unrecognized output buffer.\n");
            }
          break;
        case 'p':
          options.proc = true;
          break;
        case 'm':
          options.memory = true;
          break;

        case 'q':
          options.verbose = 0;
          break;
        case 'v':
          if (options.verbose)
            options.verbose++;
          break;
        case 'V':
          version ();
          exit (EXIT_SUCCESS);
        case 'h':
          help ();
          exit (EXIT_SUCCESS);
        default: /* '?' */
          usage ();
          exit (EXIT_FAILURE);
        }
    }
}

int
main (int argc, char** argv)
{

  process_args (argc, argv);

  /* Default values if any was not selected */
  if (options.iFile == NULL)
    {
      fprintf (stderr, "Error: No input file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }
  if (options.oFile == NULL)
    {
      fprintf (stderr, "Error: No output file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }
  if (options.dbFile == NULL)
    {
      fprintf (stderr, "Error: No database settings file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }

  FILE *input = fopen (options.iFile, "r");
  free (options.iFile);

  if (!input)
    {
      fprintf (stderr, "Error: Couldn't open the input file %s.\nAborting..."
               , options.iFile);
    }
  else
    {

      /* Connecting to the database where the URLs are available */
      MYSQL *conn;
      config_t db_cfg;

      config_init (&db_cfg);

      /* Read the file. If there is an error, report it and exit. */
      if (!config_read_file (&db_cfg, options.dbFile))
        {
          fprintf (stderr, "%s:%d - %s\n", config_error_file (&db_cfg),
                   config_error_line (&db_cfg), config_error_text (&db_cfg));
          config_destroy (&db_cfg);
          return (EXIT_FAILURE);
        }
      if(conn = mySQL_connect (&db_cfg, conn))
        config_destroy(&db_cfg);
      else{
          fprintf (stderr, "Error: Couldn't parse the database settings file "
                  "%s.\nAborting...\n"
               , options.dbFile);
        return (EXIT_FAILURE);
        }

      free (options.dbFile);
      /* Start processing the input file */
      FILE* output = fopen (options.oFile, "w");
      free (options.oFile);
      char *line = NULL, *currentHash = NULL;
      size_t len = 0, lineNo = 0;
      size_t totalRecs = 0, totalDup = 0, totalColls = 0, totalSkip = 0;
      Record *currentRec = NULL, *recList = NULL;
      /* initialize the global curl session */
      curl_global_init (CURL_GLOBAL_ALL);
      while ((getline (&line, &len, input)) > 0)
        {
          lineNo++;
          line[strlen (line) - 1] = '\0';
          line = realloc (line, strlen (line) + 1);
          currentRec = create_record (line);
          free (line);
          len = 0;
          line = NULL;


          /* Adding the first record to the hash cluster */
          if (recList == NULL)
            {
              recList = currentRec;
              currentHash = currentRec->hash;
              currentRec->ext = 1;
              currentRec->copy_no = 1;
              totalRecs++;
            }
          else
            {
              /* Check for a new hash */
              if (!strcmp (currentRec->hash, currentHash))
                {

                  /*
                   *********************************************************
                   * Download the first WARC member in the hash cluster if *
                   * it was not downloaded.                                *
                   *********************************************************
                   */

                  if (recList->member_size == 0)
                    if (!download_record (recList, conn, &lineNo))
                      {
                        totalSkip++;
                        recList = NULL;
                        continue;
                      }

                  /*
                   *********************************************************
                   * Download the first WARC member in the hash cluster if *
                   * it was not downloaded.                                *
                   *********************************************************
                   */

                  if (!download_record (currentRec, conn, &lineNo))
                    {
                      totalSkip++;
                      currentRec = NULL;
                      continue;
                    }


                  /* Check for collisions */
                  Record *collRec = recList;
                  bool exist = false;
                  while (!exist)
                    {
                      start = clock ();

                      if ((options.memory &&
                           compare_records (collRec, currentRec)) ||
                          (!options.memory &&
                           compare_records_file (collRec, currentRec)))
                        {
                          end = clock ();
                          compareTime += ((double) (end - start)) /
                                  CLOCKS_PER_SEC;
                          if (options.verbose > 1)
                            printf ("Duplicate was found at line %ld.\n"
                                    , lineNo);
                          /* Adding the current record to the list */
                          Record * sameRec = collRec;
                          /* Getting the last similar record */
                          while (sameRec->next != NULL)
                            sameRec = sameRec->next;
                          sameRec->next = currentRec;
                          currentRec->ext = sameRec->ext;
                          currentRec->copy_no = sameRec->copy_no + 1;

                          /* Removing the data of the duplicate record */
                          if (options.memory)
                            {

                              free (currentRec->member_memory->memory);
                              currentRec->member_memory->size = 0;
                            }
                          else
                            {
                              if (fclose (currentRec->member_file) != 0)
                                fprintf (stderr, "Error: Could not close temp "
                                         "file.");
                              currentRec->member_file = NULL;
                            }
                          totalDup++;
                          exist = true;
                        }

                      if (collRec->next_collision == NULL)
                        break;
                      collRec = collRec->next_collision;
                    }
                  if (!exist)
                    {
                      if (!options.verbose)
                        printf ("Collision was detected at line %ld.\n"
                                , lineNo);
                      /* Adding the record to the list of collisions */
                      collRec->next_collision = currentRec;
                      currentRec->ext = collRec->ext + 1;
                      currentRec->copy_no = 1;
                      totalColls++;
                    }

                }
              else
                {
                  if (options.verbose > 2)
                    printf ("Processing new hash cluster at line %ld.\n",
                            lineNo);
                  dump_hash_cluster (output, recList);
                  /* Destroying the records of the old hash cluster */
                  destroy_record (recList);
                  recList = NULL;
                  recList = currentRec;
                  currentHash = currentRec->hash;
                  currentRec->ext = 1;
                  currentRec->copy_no = 1;
                }
              totalRecs++;
            }
        }
      /* Global clean up for libcurl */
      curl_global_cleanup ();
      if (line != NULL)
        free (line);
      /* Cleaning up after the remaining hash cluster */
      if (!options.verbose)
        printf ("Cleaning up...\n");
      dump_hash_cluster (output, recList);
      currentHash = NULL;
      /* Destroying the records of the remaining hash cluster */
      destroy_record (recList);
      recList = NULL;
      mysql_close (conn);
      mysql_library_end ();
      fclose (input);
      fclose (output);
      if (!options.verbose)
        {
          size_t total = totalRecs + totalSkip;
          size_t unique = totalRecs - (totalDup + totalColls);

          printf ("Total member(s): %ld.\n  skipped: %ld (%.2f%%)."
                  "\n\n  processed:%ld (%.2f%%)\n    unique: %ld (%.2f%%)."
                  "\n    duplicate: %ld (%.2f%%).\n    collision: %ld (%.2f%%)."
                  "\n"
                  , total
                  , totalSkip
                  , totalSkip * 100.0 / total
                  , totalRecs
                  , totalRecs * 100.0 / total
                  , unique
                  , unique * 100.0 / totalRecs
                  , totalDup
                  , totalDup * 100.0 / totalRecs
                  , totalColls
                  , totalColls * 100.0 / totalRecs);
          printf ("Processing time: %f seconds\nNetwork time: %f seconds\n"
                  "Database time: %f seconds\n"
                  , compareTime
                  , downloadTime
                  , databaseTime);
        }
    }
  return (EXIT_SUCCESS);
}