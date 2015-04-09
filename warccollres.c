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
#include "warccollres.h"

clock_t start, end;
double compareTime = 0, downloadTime = 0, databaseTime = 0;

Record*
create_record (char * line)
{
  /* The Record constructor */
  Record *object = malloc (sizeof (Record));
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
  object->filename = malloc (strlen (token) + 1);
  strcpy (object->filename, token);
  object->offset = atoi (strtok (NULL, " "));
  object->length = atoi (strtok (NULL, " "));
  token = strtok (NULL, " ");
  object->uri = malloc (strlen (token) + 1);
  strcpy (object->uri, token);
  token = strtok (NULL, " ");
  object->date = malloc (strlen (token) + 1);
  strcpy (object->date, token);
  token = strtok (NULL, " ");
  object->hash = malloc (strlen (token) + 1);
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
mySQL_connect (FILE *dbSet, MYSQL * conn)
{
  char *server = NULL, *user = NULL, *password = NULL, *database = NULL;
  size_t len = 0;
  if (getline (&server, &len, dbSet) <= 0)
    {
      fprintf (stderr, "ERROR: cannot read the database settings file.\r\n");
      return NULL;
    }
  server[strlen (server) - 1] = '\0';
  len = 0;
  if (getline (&user, &len, dbSet) <= 0)
    {
      fprintf (stderr, "ERROR: cannot read the database settings file.\r\n");
      return NULL;
    }
  user[strlen (user) - 1] = '\0';
  len = 0;
  if (getline (&password, &len, dbSet) <= 0)
    {
      fprintf (stderr, "ERROR: cannot read the database settings file.\r\n");
      return NULL;
    }
  password[strlen (password) - 1] = '\0';
  len = 0;
  if (getline (&database, &len, dbSet) <= 0)
    {
      fprintf (stderr, "ERROR: cannot read the database settings file.\r\n");
      return NULL;
    }
  database[strlen (database) - 1] = '\0';
  conn = mysql_init (NULL);
  /* Connect to database */
  if (!mysql_real_connect (conn, server,
                           user, password, database, 0, NULL, 0))
    {
      fprintf (stderr, "%s\n", mysql_error (conn));
      return NULL;
    }
  free (server);
  free (user);
  free (password);
  free (database);
  return conn;
}

char*
get_url_from_db (MYSQL *conn, char* filename)
{
  MYSQL_RES *res;
  MYSQL_ROW row;

  /* send SQL query */
  char temp[] = "SELECT url FROM `path_index` WHERE filename = '";
  char *query = (char*) malloc (strlen (temp) + strlen (filename) + 2);
  strcpy (query, temp);
  strcat (query, filename);
  strcat (query, "'");

  if (mysql_query (conn, query))
    {
      fprintf (stderr, "%s\n", mysql_error (conn));
      exit (1);
    }
  free (query);
  res = mysql_use_result (conn);
  /* Get the result */
  row = mysql_fetch_row (res);
  char *url;
  if (row[0] != NULL)
    {
      url = malloc (sizeof (char) * strlen (row[0]));
      strcpy (url, row[0]);
    }
  else
    {
      url = NULL;
    }
  mysql_free_result (res);
  return url;
}

bool
compare_records (Record *first, Record * second)
{
  long firstIndex = 0, secondIndex = 0;

  //Seeking to the end of the WARC header of the first record.
  for (firstIndex; first->member_memory->memory[firstIndex] != '\n' || \
            (first->member_memory->memory[firstIndex + 1] != '\n' && \
            first->member_memory->memory[firstIndex + 2] != '\n'); firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;
  //Seeking to the end of the HTTP header of the first record.
  for (firstIndex; first->member_memory->memory[firstIndex] != '\n' || \
            (first->member_memory->memory[firstIndex + 1] != '\n' && \
            first->member_memory->memory[firstIndex + 2] != '\n'); firstIndex++);
  if (first->member_memory->memory[firstIndex + 1] == '\n')
    firstIndex += 2;
  else
    firstIndex += 3;
  //Seeking to the end of the WARC header of the second record.
  for (secondIndex; second->member_memory->memory[secondIndex] != '\n' || \
            (second->member_memory->memory[secondIndex + 1] != '\n' && \
            second->member_memory->memory[secondIndex + 2] != '\n'); secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;
  //Seeking to the end of the HTTP header of the second record.
  for (secondIndex; second->member_memory->memory[secondIndex] != '\n' || \
            (second->member_memory->memory[secondIndex + 1] != '\n' && \
            second->member_memory->memory[secondIndex + 2] != '\n'); secondIndex++);
  if (second->member_memory->memory[secondIndex + 1] == '\n')
    secondIndex += 2;
  else
    secondIndex += 3;


  if ((first->member_memory->size - firstIndex) != (second->member_memory->size - secondIndex))
    return false;
  while (firstIndex < first->member_memory->size - 4 && secondIndex < second->member_memory->size - 4)
    {
      if (first->member_memory->memory[firstIndex++] != second->member_memory->memory[secondIndex++])
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
  while (!feof (first->member_file) && (read = getline (&line, &len, first->member_file)) > 0)
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
  while (!feof (first->member_file) && (read = getline (&line, &len, first->member_file)) > 0)
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
  while (!feof (second->member_file) && (read = getline (&line, &len, second->member_file)) > 0)
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
  while (!feof (second->member_file) && (read = getline (&line, &len, second->member_file)) > 0)
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

  firstBuffer = malloc (sizeof (char) * options.output_buffer);
  secondBuffer = malloc (sizeof (char) * options.output_buffer);

  while (!(feof (first->member_file) && feof (first->member_file)))
    {
      read = fread (firstBuffer, 1, options.output_buffer, first->member_file);
      read = fread (secondBuffer, 1, options.output_buffer, second->member_file);

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
      record->member_memory->memory = realloc (record->member_memory->memory, z->total_out);
      memcpy (&(record->member_memory->memory[record->member_memory->size]), z->next_out, (z->total_out - record->member_memory->size));
      record->member_memory->size = z->total_out;
    }
  else
    {
      fwrite (z->next_out, 1, (z->total_out - record->member_size), record->member_file);
    }
  record->member_size = z->total_out;
}

bool
inflate_record_member (Record *record)
{
  z_stream z;
  gzmInflateInit (&z);
  z.next_in = calloc (options.input_buffer + 1, sizeof (Bytef)); //extra byte for the null terminator
  z.next_out = calloc (options.output_buffer + 1, sizeof (Bytef));

  inflateReset2 (&z, 31);

  if (options.memory)
    {
      FILE* outf = fmemopen (record->compressed_member_memory->memory, record->compressed_member_memory->size, "r");

      record->member_memory = (MemoryStruct *) malloc (sizeof (MemoryStruct));
      record->member_memory->size = 0;
      record->member_memory->memory = malloc (1);

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
      record->compressed_member_memory->memory = realloc (record->compressed_member_memory->memory, record->compressed_member_memory->size + realsize + 1);
      if (record->compressed_member_memory->memory == NULL)
        {
          /* out of memory! */
          printf ("not enough memory (realloc returned NULL)\n");
          return 0;
        }

      memcpy (&(record->compressed_member_memory->memory[record->compressed_member_memory->size]), contents, realsize);
      record->compressed_member_memory->size += realsize;
      record->compressed_member_memory->memory[record->compressed_member_memory->size] = 0;
    }
  else
    {
      fwrite (contents, 1, realsize, record->compressed_member_file);
    }
  record->member_size += realsize;

  return realsize;
}

bool
http_download_file (char *url, Record *record)
{
  CURL *curl_handle;
  CURLcode res;

  char* range = (char*) malloc (50);
  sprintf (range, "%zu-%zu", record->offset, record->offset + record->length - 1);

  if (options.memory)
    {
      record->compressed_member_memory = (MemoryStruct *) malloc (sizeof (MemoryStruct));
      record->compressed_member_memory->memory = (char*) malloc (1); /* will be grown as needed by the realloc above */
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

  /* specify URL to get */
  curl_easy_setopt (curl_handle, CURLOPT_URL, url);

  /* send all data to this function  */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEDATA, (void *) record);

  curl_easy_setopt (curl_handle, CURLOPT_RANGE, range);

  /* get it! */
  res = curl_easy_perform (curl_handle);
  /* check for errors */
  if (res != CURLE_OK)
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
  char *url;
  start = clock ();
  url = get_url_from_db (conn, record->filename);
  end = clock ();
  databaseTime += ((double) (end - start)) / CLOCKS_PER_SEC;
  if (url == NULL)
    {
      if (!options.quite && options.verbose)
        fprintf (stderr, "Error: Could not find a server for the processed \
record in line %ld.\n", *lineNo);
      destroy_record (record);
      return false;
    }

  /*
   *************************************
   * Get the member from the HTTP server *
   *************************************
   */
  start = clock ();
  if (!http_download_file (url, record))
    return false;
  end = clock ();

  downloadTime += ((double) (end - start)) / CLOCKS_PER_SEC;
  free (url);
  if (record->member_size == 0)
    {
      if (!options.quite && options.verbose)
        fprintf (stderr, "Error: Could not download the member from the \
HTTP server for the processed record in line %ld.\n", *lineNo);
      destroy_record (record);
      return false;
    }
  return true;
}

void
usage ()
{
  fprintf (stderr, "Usage: warccollres [-i | --input <filename>] \
[-o | --output <filename>] [-s | --db-settings <filename>] \
[-p | --proc] [-b | --input-buffer] [-B | --output-buffer] \
[-m | --memory-only][-q | --quite] [-v | --verbose]\n");
}

int
process_args (int argc, char** argv)
{
  options.quite = false;
  options.verbose = false;
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
              options.iFile = malloc (strlen (optarg) + 1);
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
              options.oFile = malloc (strlen (optarg) + 1);
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
              options.dbFile = malloc (strlen (optarg) + 1);
              strcpy (options.dbFile, optarg);
            }
          else
            {
              fprintf (stderr, "Error: No database settings file was specified.\n");
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
        case 'q':
          options.quite = true;
          break;
        case 'v':
          options.verbose = true;
          break;
        case 'm':
          options.memory = true;
          break;
        case 'h':
          usage ();
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
      FILE *dbSet = fopen (options.dbFile, "r");
      if (dbSet)
        {
          conn = mySQL_connect (dbSet, conn);
          fclose (dbSet);
        }
      else
        {
          fprintf (stderr, "Error: Could not open the database's settings file.\
\nAborting...");
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

                      if ((options.memory && compare_records (collRec, currentRec)) || \
                          (!options.memory && compare_records_file (collRec, currentRec)))
                        {
                          end = clock ();
                          compareTime += ((double) (end - start)) / CLOCKS_PER_SEC;
                          if (!options.quite && options.verbose)
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
                                fprintf (stderr, "Error: Could not close temp file.");
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
                      if (!options.quite && options.verbose)
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
                  if (!options.quite && options.verbose)
                    printf ("Processing new hash cluster at line %ld.\n", lineNo);
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
      if (!options.quite && options.verbose)
        printf ("Cleaning up...\n");
      dump_hash_cluster (output, recList);
      currentHash = NULL;
      /* Destroying the records of the remaining hash cluster */
      destroy_record (recList);
      recList = NULL;
      mysql_close (conn);
      fclose (input);
      fclose (output);
      if (!quite)
        {
          size_t total = totalRecs + totalSkip;
          size_t unique = totalRecs - (totalDup + totalColls);

          printf ("Total member(s): %ld.\n  skipped: %ld (%.2f%%).\
\n\n  processed:%ld (%.2f%%)\n    unique: %ld (%.2f%%).\
\n    duplicate: %ld (%.2f%%).\n    collision: %ld (%.2f%%).\n"
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
          printf ("Processing time: %f seconds\nNetwork time: %f seconds\n\
Database time: %f seconds\n"
                  , compareTime
                  , downloadTime
                  , databaseTime);
        }
    }
  return (EXIT_SUCCESS);
}