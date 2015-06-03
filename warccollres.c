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
 *     1. WARC file name
 *     2. Offset (compressed)
 *     3. End (compressed)
 *     4. URI
 *     5. Date
 *     6. Digest
 * 
 * The extended digest file contains following data:
 *     1. WARC file name
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

/*
 * The duplicate_record constructor
 */
duplicate_record*
create_duplicate_record (char * line)
{
  duplicate_record *object = calloc (1, sizeof (duplicate_record));
  object->next = NULL;
  object->member_memory = NULL;
  object->compressed_member_memory = NULL;
  object->member_file = NULL;
  object->compressed_member_file = NULL;
  object->member_size = 0;

  /*
   * Parsing the input line and storing its token in the Record structure
   */
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
  if (global.current_hash)
    {
      free (global.current_hash);
      global.current_hash = NULL;
    }
  global.current_hash = calloc (strlen (token) + 1, sizeof (char));
  strcpy (global.current_hash, token);
  return object;
}

void
destroy_duplicate_record (duplicate_record *object)
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
  if (object->member_memory != NULL && object->member_memory->size > 0)
    free (object->member_memory->memory);
  if (object->member_memory != NULL)
    free (object->member_memory);
  if (object->compressed_member_memory != NULL)
    free (object->compressed_member_memory);
  object->filename = NULL;
  object->uri = NULL;
  object->date = NULL;
  object->member_memory = NULL;

  if (object->next != NULL)
    destroy_duplicate_record (object->next);
  object->next = NULL;
  free (object);
  object = NULL;
}

/*
 * The collision_record constructor
 */
collision_record*
create_collision_record (duplicate_record *duplicate)
{

  /*
   * Create an object of the collision record from the duplicate object
   */
  collision_record *collision = calloc (1, sizeof (collision_record));

  /*
   * Copy all data from the duplicate record to the new collision record
   */
  collision->duplicate_list = duplicate;

  /*
   * Set the default values for the other attributes of the collision record
   */
  collision->next_collision = NULL;
  collision->last_duplicate = duplicate;

  return collision;
}

void
destroy_collision_record (collision_record *object)
{
  /* The Record destructor */
  if (object == NULL)
    return;

  destroy_duplicate_record (object->duplicate_list);

  if (object->next_collision != NULL)
    destroy_collision_record (object->next_collision);
  object->next_collision = NULL;

  object->last_duplicate = NULL;

  free (object);
  object = NULL;
}

void
dump_hash_cluster ()
{
  /*
   * Dump the previous hash cluster to the global.output file
   */
  collision_record *temp_coll = global.record_cluster;

  size_t ext = 0, copy_no = 0;

  /*
   * Dump the collided records
   */
  while (temp_coll != NULL)
    {
      ext++;
      copy_no = 0;
      /*
       * Dump the similar records to the output file
       */
      duplicate_record *temp_rec = temp_coll->duplicate_list;
      while (temp_rec != NULL)
        {
          copy_no++;
          fprintf (global.output, "%s %zu %zu %s %s %s %zu"
                   , temp_rec->filename
                   , temp_rec->offset
                   , temp_rec->length
                   , temp_rec->uri
                   , temp_rec->date
                   , global.cluster_hash
                   , ext);
          if (options.proc)
            {
              fprintf (global.output, " %zu", copy_no);
              if (copy_no == 1)
                fprintf (global.output, " - -");
              else
                fprintf (global.output, " %s %s"
                         , temp_rec->uri
                         , temp_rec->date);

            }
          fprintf (global.output, "\n");

          /*
           * Prepare the next record
           */
          temp_rec = temp_rec->next;
        }
      temp_coll = temp_coll->next_collision;
    }
}

MYSQL *
mySQL_connect (config_t *db_cfg)
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

  global.conn = mysql_init (NULL);

  /* 
   * Connect to database
   */
  if (!mysql_real_connect (global.conn, server,
                           user, password, database, 0, NULL, 0))
    {
      fprintf (stderr, "%s\n", mysql_error (global.conn));
      return NULL;
    }

  return global.conn;
}

size_t
get_url_from_db (char *filename, char ***url)
{
  MYSQL_RES *res;
  MYSQL_ROW row;

  /*
   * Construct the SQL query
   */
  char temp[] = "SELECT url FROM `path_index` WHERE filename = '";
  char *query = (char*) calloc (strlen (temp) + strlen (filename) + 2,
                                sizeof (char));
  strcpy (query, temp);
  strcat (query, filename);
  strcat (query, "'");

  if (mysql_query (global.conn, query))
    {
      fprintf (stderr, "%s\n", mysql_error (global.conn));
      exit (1);
    }
  free (query);

  /*
   *  Get the result.
   */
  res = mysql_store_result (global.conn);

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
compare_records (duplicate_record *first, duplicate_record * second)
{
  long firstIndex = 0, secondIndex = 0;

  /*
   * Seeking to the end of the WARC header of the first record
   */
  for (firstIndex;
          first->member_memory->memory[firstIndex] != '\n' ||
          (first->member_memory->memory[firstIndex + 1] != '\n' &&
           first->member_memory->memory[firstIndex + 2] != '\n');
          firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;

  /*
   * Seeking to the end of the HTTP header of the first record
   */
  for (firstIndex;
          first->member_memory->memory[firstIndex] != '\n' ||
          (first->member_memory->memory[firstIndex + 1] != '\n' &&
           first->member_memory->memory[firstIndex + 2] != '\n');
          firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;

  /*
   * Seek to the end of the WARC header of the second record
   */
  for (secondIndex;
          second->member_memory->memory[secondIndex] != '\n' ||
          (second->member_memory->memory[secondIndex + 1] != '\n' &&
           second->member_memory->memory[secondIndex + 2] != '\n');
          secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;

  /*
   * Seek to the end of the HTTP header of the second record
   */
  for (secondIndex;
          second->member_memory->memory[secondIndex] != '\n' ||
          (second->member_memory->memory[secondIndex + 1] != '\n' &&
           second->member_memory->memory[secondIndex + 2] != '\n');
          secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;

  /*
   * Compare the content of the two WARC members
   */
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

bool
compare_records_file (duplicate_record *first, duplicate_record * second)
{
  size_t len = 0, read = 0, firstIndex, secondIndex;
  char *line = NULL, *firstBuffer, *secondBuffer;

  rewind (first->member_file);
  rewind (second->member_file);

  /*
   * Seek to the end of the WARC header of the first record
   */
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

  /*
   * Seek to the end of the HTTP header of the first record
   */
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

  /*
   * Seek to the end of the WARC header of the second record
   */
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

  /*
   * Seek to the end of the HTTP header of the second record
   */
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

  /*
   * Compare the content size, if the size matches, then continue
   * the comparison.
   */
  if ((first->member_size - firstIndex) != (second->member_size - secondIndex))
    return false;

  firstBuffer = calloc (options.output_buffer, sizeof (char));
  secondBuffer = calloc (options.output_buffer, sizeof (char));

  /*
   * Compare the content of the two WARC members
   */
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

void
process_chunk (z_stream *z, int chunk, void *vp)
{
  duplicate_record* record = (duplicate_record*) vp;

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
inflate_record_member (duplicate_record *record)
{
  z_stream z;
  gzmInflateInit (&z);

  /*
   * extra byte for the null terminator
   */
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
        fprintf (stderr, "Error: Could not close temp file.\n");
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
  struct duplicate_record *record = (struct duplicate_record *) userp;

  if (options.memory)
    {
      record->compressed_member_memory->memory =
              realloc (record->compressed_member_memory->memory,
                       record->compressed_member_memory->size + realsize + 1);

      if (record->compressed_member_memory->memory == NULL)
        {
          /*
           * Not enough memory
           */
          fprintf (stderr, "Error: Not enough memory to download the file.\n");
          return 0;
        }
      size_t size = record->compressed_member_memory->size;
      memcpy (&(record->compressed_member_memory->memory[size]),
              contents, realsize);
      record->compressed_member_memory->size += realsize;
    }
  else
    {
      fwrite (contents, 1, realsize, record->compressed_member_file);
    }
  record->member_size += realsize;

  return realsize;
}

bool
http_download_file (char **url, size_t url_count, duplicate_record *record)
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
       * Allocate the memory structure with initial array of size 1
       * and it will grow according to size of the WARC member.
       */
      record->compressed_member_memory->memory =
              (char*) calloc (1, sizeof (char));
      record->compressed_member_memory->size = 0;
    }
  else
    {
      /*
       * Write the compressed member to a temp file
       */
      if ((record->compressed_member_file = tmpfile ()) == NULL)
        {
          fprintf (stderr, "%s\n", strerror (errno));
          return false;
        }
    }

  /* 
   * Initialize the curl session
   */
  curl_handle = curl_easy_init ();

  /*
   * Specify the callback function for cURL
   */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);

  /*
   * Specify the structure to write the data into for cURL
   */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEDATA, (void *) record);

  curl_easy_setopt (curl_handle, CURLOPT_RANGE, range);

  curl_easy_setopt (curl_handle, CURLOPT_FAILONERROR, 1);

  bool downloaded = false;

  int i;

  for (i = 0; i < url_count; i++)
    {
      /* 
       * specify URL to get
       */
      curl_easy_setopt (curl_handle, CURLOPT_URL, url[i]);

      /*
       * Attempt to download the WARC member
       */
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


  /* 
   * check for download errors
   */
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

      /*
       * inflate the WARC member.
       */
      if (!inflate_record_member (record))
        return false;
    }

  /* 
   * cleanup curl handle
   */
  curl_easy_cleanup (curl_handle);

  free (range);

  return true;
}

bool
download_record (duplicate_record *record)
{
  /*
   * Obtain the URL where the file is located from the database
   */
  char **url = NULL;
  size_t url_count = 0;
  start = clock ();
  url_count = get_url_from_db (record->filename, &url);
  end = clock ();
  global.time_database += ((double) (end - start)) / CLOCKS_PER_SEC;
  if (url == NULL)
    {
      if (!options.verbose)
        fprintf (stderr, "Error: Could not find a server for the processed "
                 "record in line %ld.\n", global.line_no);
      destroy_duplicate_record (record);
      return false;
    }

  /*
   * Get the member from the HTTP server
   */
  start = clock ();
  if (!http_download_file (url, url_count, record))
    return false;
  end = clock ();

  global.time_download += ((double) (end - start)) / CLOCKS_PER_SEC;
  free (url);
  if (record->member_size == 0)
    {
      if (!options.verbose)
        fprintf (stderr, "Error: Could not download the member from the "
                 "HTTP server for the processed record in line %ld.\n",
                 global.line_no);
      destroy_duplicate_record (record);
      return false;
    }
  return true;
}

/*
 * Display version message
 */
void
version ()
{
  printf ("GNU warccollres 0.1\n"
          " * Copyright (C) 2014 Bibliotheca Alexandrina\n");
}

/*
 * Display usage message
 */
void
usage ()
{
  fprintf (stderr, "Usage: warccollres --input FILE --output FILE "
           "--settings FILE "
           "[--proc] [--input-buffer SIZE] "
           "[--output-buffer SIZE] [--memory-only] [--quiet] [--verbose] "
           "[--version] [--help]\n");
}

/*
 * Display help message
 */
void
help ()
{
  printf ("Usage\n");

  printf ("\twarccollres [options] --input FILE --output FILE "
          "--settings FILE\n\n");

  printf ("Options\n");

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

  printf ("\t-q, --quiet\n");
  printf ("\t\tQuiet mode. Do not print any messages about the process.\n\n");

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
  options.input_file = NULL;
  options.output_file = NULL;
  options.settings_file = NULL;

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
              options.input_file = calloc (strlen (optarg) + 1, sizeof (char));
              strcpy (options.input_file, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No input file was specified.\n");
            }
          break;
        case 'o':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              options.output_file = calloc (strlen (optarg) + 1, sizeof (char));
              strcpy (options.output_file, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No output file was specified.\n");
            }
          break;
        case 's':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              options.settings_file = calloc (strlen (optarg) + 1,
                                              sizeof (char));
              strcpy (options.settings_file, optarg);
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

  if (options.input_file == NULL)
    {
      fprintf (stderr, "Error: No input file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }
  if (options.output_file == NULL)
    {
      fprintf (stderr, "Error: No output file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }
  if (options.settings_file == NULL)
    {
      fprintf (stderr, "Error: No database settings file was specified.\n");
      usage ();
      exit (EXIT_FAILURE);
    }
}

/*
 * Process a record with the same hash as the current hash cluster
 */
bool
process_cluster ()
{

  /*
   * Download the first WARC member in the hash cluster if
   * it was not downloaded.
   */
  if (global.record_cluster->duplicate_list->member_size == 0)
    if (!download_record (global.record_cluster->duplicate_list))
      {
        global.total_skipped++;
        global.record_cluster = NULL;
        return false;
      }

  /*
   * Download the new WARC member in the hash cluster 
   */
  if (!download_record (global.current_record))
    {
      global.total_skipped++;
      global.current_record = NULL;
      return false;
    }


  /*
   * Check for collisions
   */
  collision_record *coll_rec = global.record_cluster;
  bool exist = false;
  while (!exist)
    {
      start = clock ();

      if ((options.memory &&
           compare_records (coll_rec->duplicate_list, global.current_record)) ||
          (!options.memory &&
           compare_records_file (coll_rec->duplicate_list,
                                 global.current_record)))
        {
          end = clock ();
          global.time_compare += ((double) (end - start)) /
                  CLOCKS_PER_SEC;
          if (options.verbose > 1)
            printf ("Duplicate was found at line %ld.\n"
                    , global.line_no);

          /* 
           * Adding the current record to the list
           */
          coll_rec->last_duplicate->next = global.current_record;
          coll_rec->last_duplicate = global.current_record;

          /* 
           * Removing the data of the duplicate record
           */
          if (options.memory)
            {

              free (global.current_record->member_memory->memory);
              global.current_record->member_memory->size = 0;
            }
          else
            {
              if (fclose (global.current_record->member_file) != 0)
                fprintf (stderr, "Error: Could not close temp file.");
              global.current_record->member_file = NULL;
            }
          global.total_duplicates++;
          exist = true;
        }

      if (coll_rec->next_collision == NULL)
        break;
      coll_rec = coll_rec->next_collision;
    }
  if (!exist)
    {
      if (options.verbose)
        printf ("Collision was detected at line %ld.\n"
                , global.line_no);
      /* 
       * Adding the record to the list of collisions
       */
      coll_rec->next_collision = create_collision_record (global.current_record);
      global.total_collisions++;
    }

  return true;
}

/*
 * Process a new hash cluster
 * 
 * The function dumps the current hash cluster into the output file,
 * destroys the current hash cluster, then creates a new hash cluster
 * for the new record
 */
void
process_new_cluster ()
{
  if (options.verbose > 2)
    fprintf (stderr, "Processing new hash cluster at line %ld.\n",
             global.line_no);
  dump_hash_cluster ();

  /* 
   * Destroying the records of the old hash cluster
   */
  destroy_collision_record (global.record_cluster);
  global.record_cluster = create_collision_record (global.current_record);
  if (global.cluster_hash)
    free (global.cluster_hash);
  global.cluster_hash = global.current_hash;
  global.current_hash = NULL;
}

void
global_init ()
{
  global.input = fopen (options.input_file, "r");
  free (options.input_file);

  if (!global.input)
    {
      fprintf (stderr, "Error: Couldn't open the global.input file %s.\n"
               "Aborting...\n"
               , options.input_file);
      exit (EXIT_FAILURE);
    }
  else
    {

      config_t db_cfg;

      config_init (&db_cfg);

      /* 
       * Read the file. If there is an error, report it and exit.
       */
      if (!config_read_file (&db_cfg, options.settings_file))
        {
          fprintf (stderr, "%s:%d - %s\n", config_error_file (&db_cfg),
                   config_error_line (&db_cfg), config_error_text (&db_cfg));
          config_destroy (&db_cfg);
          exit (EXIT_FAILURE);
        }

      /* 
       * connecting to the database where the URLs are available
       */
      if (global.conn = mySQL_connect (&db_cfg))
        config_destroy (&db_cfg);
      else
        {
          fprintf (stderr, "Error: Couldn't parse the database settings file "
                   "%s.\nAborting...\n"
                   , options.settings_file);
          exit (EXIT_FAILURE);
        }

      free (options.settings_file);

      /* 
       * Start processing the global.input file
       */
      global.output = fopen (options.output_file, "w");
      free (options.output_file);
      global.current_line = NULL;
      global.current_hash = NULL;
      global.cluster_hash = NULL;
      global.line_no = 0;
      global.total_records = 0;
      global.total_duplicates = 0;
      global.total_collisions = 0;
      global.total_skipped = 0;
      global.current_record = NULL;
      global.record_cluster = NULL;

      global.time_compare = 0;
      global.time_download = 0;
      global.time_database = 0;

      /*
       * initialize the global curl session
       */
      curl_global_init (CURL_GLOBAL_ALL);
    }
}

void
process_input ()
{
  size_t len = 0;

  while ((getline (&global.current_line, &len, global.input)) > 0)
    {
      global.line_no++;
      global.current_line[strlen (global.current_line) - 1] = '\0';
      global.current_line = realloc (global.current_line,
                                     strlen (global.current_line) + 1);
      global.current_record = create_duplicate_record (global.current_line);
      free (global.current_line);
      len = 0;
      global.current_line = NULL;


      /* 
       * Adding the first record to the hash cluster
       */
      if (global.record_cluster == NULL)
        {
          global.record_cluster =
                  create_collision_record (global.current_record);
          global.cluster_hash = global.current_hash;
          global.current_hash = NULL;
          global.total_records++;
        }
      else
        {
          /* Check for a new hash */
          if (!strcmp (global.current_hash, global.cluster_hash))
            {
              /*
               * Same hash was found.
               * Check if whether the record is a duplicate or a collision.
               */
              if (!process_cluster ())
                continue;

            }
          else
            {
              /*
               * Different hash was found.
               */
              process_new_cluster ();
            }

          global.total_records++;
        }
    }
}

void
cleanup ()
{
  if (options.verbose)
    printf ("Cleaning up...\n");

  /* 
   * Global clean up for cURL
   */
  curl_global_cleanup ();

  dump_hash_cluster (global.output, global.record_cluster);

  /* 
   * Destroying the records of the remaining hash cluster
   */
  destroy_collision_record (global.record_cluster);
  global.record_cluster = NULL;
  mysql_close (global.conn);
  mysql_library_end ();
  fclose (global.input);
  fclose (global.output);
}

void
print_stats ()
{
  if (options.verbose)
    {
      size_t total = global.total_records + global.total_skipped;
      size_t unique = global.total_records -
              (global.total_duplicates + global.total_collisions);

      printf ("Total member(s): %ld.\n  skipped: %ld (%.2f%%)."
              "\n\n  processed:%ld (%.2f%%)\n    unique: %ld (%.2f%%)."
              "\n    duplicate: %ld (%.2f%%).\n    collision: %ld (%.2f%%)."
              "\n"
              , total
              , global.total_skipped
              , global.total_skipped * 100.0 / total
              , global.total_records
              , global.total_records * 100.0 / total
              , unique
              , unique * 100.0 / global.total_records
              , global.total_duplicates
              , global.total_duplicates * 100.0 / global.total_records
              , global.total_collisions
              , global.total_collisions * 100.0 / global.total_records);
      printf ("Processing time: %f seconds\nNetwork time: %f seconds\n"
              "Database time: %f seconds\n"
              , global.time_compare
              , global.time_download
              , global.time_database);
    }
}

int
main (int argc, char** argv)
{
  /* 
   * Process the arguments and check for their sanity
   */
  process_args (argc, argv);

  /* 
   * Initialize Everything needed for processing the input
   */
  global_init ();

  /* 
   * Process the input file
   */
  process_input ();

  /* 
   * Cleaning up after the remaining hash cluster
   */
  cleanup ();

  /*
   * Print statistics about the run
   */
  print_stats ();

  return (EXIT_SUCCESS);
}