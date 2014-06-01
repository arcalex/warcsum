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



Record*
createRecord (char * line)
{
  /* The Record constructor */
  Record *object = malloc (sizeof (Record));
  object->next = NULL;
  object->nextColl = NULL;
  object->data = NULL;
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
  object->hash[strlen (token) - 1] = '\0';
  return object;
}

void
destroyRecord (Record *object)
{
  /* The Record destructor */
  if (object == NULL)
    return;
  if (object->filename)
    free (object->filename);
  if (object->uri)
    free (object->uri);
  if (object->date)
    free (object->date);
  if (object->hash)
    free (object->hash);
  if (object->data != NULL && object->data->memory && object->data->size > 0)
    free (object->data->memory);
  object->filename = NULL;
  object->uri = NULL;
  object->hash = NULL;
  object->date = NULL;
  object->data = NULL;
  if (object->nextColl != NULL)
    destroyRecord (object->nextColl);
  if (object->next != NULL)
    destroyRecord (object->next);
  object->next = NULL;
  object->nextColl = NULL;
  free (object);
}

void
dumpHashCluster (FILE* output, Record *recList, bool proc)
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
          fprintf (output, "%s %ld %ld %s %s %s %d"
                   , tempRec->filename
                   , tempRec->offset
                   , tempRec->length
                   , tempRec->uri
                   , tempRec->date
                   , tempRec->hash
                   , tempRec->ext);
          if (proc)
            {
              fprintf (output, " %d", tempRec->copyNo);
              if (tempRec->copyNo != 1)
                fprintf (output, " %s %s - -"
                         , tempColl->uri
                         , tempColl->date);
              fprintf (output, "\n");
            }
          /* Preparing the next record */
          tempRec = tempRec->next;
        }
      tempColl = tempColl->nextColl;
    }
}

MYSQL*
mySQLConnect (FILE *dbSet, MYSQL *conn)
{
  char *server, *user, *password, *database;
  size_t len = 0;
  getline (&server, &len, dbSet);
  server[strlen (server) - 1] = '\0';
  len = 0;
  getline (&user, &len, dbSet);
  user[strlen (user) - 1] = '\0';
  len = 0;
  getline (&password, &len, dbSet);
  password[strlen (password) - 1] = '\0';
  len = 0;
  getline (&database, &len, dbSet);
  database[strlen (database) - 1] = '\0';
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

char*
getURLfromDB (MYSQL *conn, char* filename)
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
      url = malloc (strlen (row[0]));
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
compRec (Record *first, Record *second)
{
  long firstIndex = 0, secondIndex = 0;
  //Seeking to the end of the WARC header of the first record.
  for (firstIndex; first->data->memory[firstIndex] != '\n' || \
            (first->data->memory[firstIndex + 1] != '\n' && \
            first->data->memory[firstIndex + 2] != '\n'); firstIndex++);
  //Seeking to the end of the HTTP header of the first record.
  for (++firstIndex; first->data->memory[firstIndex] != '\n' || \
            (first->data->memory[firstIndex + 1] != '\n' && \
            first->data->memory[firstIndex + 2] != '\n'); firstIndex++);
  //Seeking to the end of the WARC header of the second record.
  for (secondIndex; second->data->memory[secondIndex] != '\n' || \
            (second->data->memory[secondIndex + 1] != '\n' && \
            second->data->memory[secondIndex + 2] != '\n'); secondIndex++);
  //Seeking to the end of the HTTP header of the second record.
  for (++secondIndex; second->data->memory[secondIndex] != '\n' || \
            (second->data->memory[secondIndex + 1] != '\n' && \
            second->data->memory[secondIndex + 2] != '\n'); secondIndex++);
  if ((first->data->size - firstIndex) != (second->data->size - secondIndex))
    return false;
  while (firstIndex < first->data->size - 4 && secondIndex < second->data->size - 4)
    {
      if (first->data->memory[firstIndex++] != second->data->memory[secondIndex++])
        return false;
    }
  return true;
}

static size_t
WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *) userp;

  mem->memory = realloc (mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL)
    {
      /* out of memory! */
      printf ("not enough memory (realloc returned NULL)\n");
      return 0;
    }

  memcpy (&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

MemoryStruct*
httpDLFile (char *url, int offset, int length)
{
  CURL *curl_handle;
  CURLcode res;

  char* range = (char*) malloc (50);
  sprintf (range, "%d-%d", offset, offset + length - 1);
  MemoryStruct *chunk = malloc (sizeof (MemoryStruct));

  chunk->memory = (char*) malloc (1); /* will be grown as needed by the realloc above */
  chunk->size = 0; /* no data at this point */

  /* init the curl session */
  curl_global_init (CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init ();

  /* specify URL to get */
  curl_easy_setopt (curl_handle, CURLOPT_URL, url);

  /* send all data to this function  */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt (curl_handle, CURLOPT_WRITEDATA, (void *) chunk);

  curl_easy_setopt (curl_handle, CURLOPT_RANGE, range);

  /* get it! */
  res = curl_easy_perform (curl_handle);
  /* check for errors */
  if (res != CURLE_OK)
    {
      fprintf (stderr, "curl_easy_perform() failed: %s\n",
               curl_easy_strerror (res));
    }
  else
    {
      /*inflate here. */

      FILE* outf = fmemopen (chunk->memory, chunk->size, "r");

      z_stream z;
      unsigned char *member = malloc (1024000);
      gzmInflateInit (&z);
      inflateMember (outf, &z, member, 1024000);
      inflateEnd (&z);
      fclose (outf);

      free (chunk->memory);
      chunk->size = z.total_out;
      chunk->memory = malloc (chunk->size);
      memcpy (chunk->memory, member, chunk->size);
      free (member);
    }
  /* cleanup curl stuff */
  curl_easy_cleanup (curl_handle);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup ();
  free (range);
  return chunk;
}

int
main (int argc, char** argv)
{

  int opt, option_index = 0;
  char *iFile = NULL, *oFile = NULL, *dbFile = NULL;
  bool proc = false;

  static struct option long_options[] = {
    {"input", required_argument, 0, 'i'},
    {"output", required_argument, 0, 'o'},
    {"db-settings", required_argument, 0, 's'},
    {"proc", no_argument, 0, 'p'},
    {"quite", no_argument, 0, 'q'},
    {"verbose", no_argument, 0, 'v'},
    {0, 0, 0, 0}
  };
  while ((opt = getopt_long (argc, argv, "i:o:s:pqv",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'i':
          if (strlen (optarg) > 0)
            {
              iFile = malloc (strlen (optarg));
              strcpy (iFile, optarg);
            }
          else
            {
              printf ("No input file was specified.\n");
            }
          break;
        case 'o':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              oFile = malloc (strlen (optarg));
              strcpy (oFile, optarg);
            }
          else
            {
              printf ("No output file was specified.\n");
            }
          break;
        case 's':
          if (strlen (optarg) > 0 && optarg[0] != '-')
            {
              dbFile = malloc (strlen (optarg));
              strcpy (dbFile, optarg);
            }
          else
            {
              printf ("No database settings file was specified.\n");
            }
          break;
        case 'p':
          proc = true;
          break;
        case 'q':
          quite = true;
          break;
        case 'v':
          verbose = true;
          break;
        case 'h':
          fprintf (stderr, "Usage: warccollres [-i | --input <filename>] \
[-o | --output <filename>] [-s | --db-settings <filename>] \
[-p | --proc] [-q | --quite] [-v | --verbose]\n");
          return (EXIT_SUCCESS);
        default: /* '?' */
          fprintf (stderr, "Usage: warccollres [-i | --input <filename>] \
[-o | --output <filename>] [-s | --db-settings <filename>] \
[-p | --proc] [-q | --quite] [-v | --verbose]\n");
          exit (EXIT_FAILURE);
        }
    }


  /* Default values if any was not selected */
  if (iFile == NULL)
    {
      const char *temp = "manifest";
      iFile = malloc (9);
      strcpy (iFile, temp);
      if (!quite)
        printf ("Using %s as the input file...\n", iFile);
    }
  if (oFile == NULL)
    {
      oFile = malloc (strlen (iFile));
      strcpy (oFile, iFile);
      strcat (oFile, ".output");
      if (!quite)
        printf ("Using %s as the output filename...\n", oFile);
    }
  if (dbFile == NULL)
    {
      const char *temp = "settings";
      dbFile = malloc (9);
      strcpy (dbFile, temp);
      if (!quite)
        printf ("Using %s as the database connecting settings file...\n", dbFile);
    }

  FILE *input = fopen (iFile, "r");

  if (!input)
    {
      printf ("Error: Couldn't open the input file %.\nAborting...", iFile);
    }
  else
    {

      /* Connecting to the database where the URLs are available */
      MYSQL *conn;
      FILE *dbSet = fopen (dbFile, "r");
      if (dbSet)
        {
          conn = mySQLConnect (dbSet, conn);
          fclose (dbSet);
        }
      else
        {
          printf ("Error: Could not open the database's settings file.\nAborting...");
          return (EXIT_FAILURE);
        }
      free (dbFile);
      /* Start processing the input file */
      FILE* output = fopen (oFile, "w");
      free (oFile);
      char *line, *currentHash = NULL;
      size_t len = 0, lineNo = 0;
      size_t totalRecs = 0, totalDup = 0, totalColls = 0, totalSkip = 0;
      Record *currentRec = NULL, *recList = NULL;
      while ((getline (&line, &len, input)) > 0)
        {
          lineNo++;
          line[strlen (line) - 1] = '\0';
          line = realloc (line, strlen (line));
          currentRec = createRecord (line);
          free (line);
          len = 0;
          line = NULL;
          /* Obtain the URL where the file is located from the database */
          char *url;
          url = getURLfromDB (conn, currentRec->filename);
          if (url == NULL)
            {
              if (!quite && verbose)
                printf ("Could not find a server for the processed record\
in line %ld.\n", lineNo);
              destroyRecord (currentRec);
              totalSkip++;
              continue;
            }
          /* Get the date from the HTTP server */
          currentRec->data = httpDLFile (url
                                         , currentRec->offset
                                         , currentRec->length);
          free (url);
          /* Adding the first record to the has cluster */
          if (recList == NULL)
            {
              recList = currentRec;
              currentHash = currentRec->hash;
              currentRec->ext = 1;
              currentRec->copyNo = 1;
              totalRecs++;
            }
          else
            {
              /* Check for a new hash */
              if (!strcmp (currentRec->hash, currentHash))
                {
                  /* Check for collisions */
                  Record *collRec = recList;
                  bool exist = false;
                  while (!exist)
                    {
                      if (compRec (collRec, currentRec))
                        {
                          if (!quite && verbose)
                            printf ("Duplicate found in line %ld.\n"
                                    , lineNo);
                          /* Adding the current record to the list */
                          Record *sameRec = collRec;
                          /* Getting the last similar record */
                          while (sameRec->next != NULL)
                            sameRec = sameRec->next;
                          sameRec->next = currentRec;
                          currentRec->ext = sameRec->ext;
                          currentRec->copyNo = sameRec->copyNo + 1;
                          /* Removing the data of the duplicate record */
                          if (currentRec->data->memory && currentRec->data->size > 0)
                            free (currentRec->data->memory);
                          currentRec->data->size = 0;
                          totalDup++;
                          exist = true;
                        }
                      if (collRec->nextColl == NULL)
                        break;
                      collRec = collRec->nextColl;
                    }
                  if (!exist)
                    {
                      if (!quite && verbose)
                        printf ("Collision detected in line %ld.\n"
                                , lineNo);
                      /* Adding the record to the list of collisions */
                      collRec->nextColl = currentRec;
                      currentRec->ext = collRec->ext + 1;
                      currentRec->copyNo = 1;
                      totalColls++;
                    }

                }
              else
                {
                  if (!quite && verbose)
                    printf ("Processing new hash cluster.\n");
                  dumpHashCluster (output, recList, proc);
                  /* Destroying the records of the old hash cluster */
                  destroyRecord (recList);
                  recList = NULL;
                  recList = currentRec;
                  currentHash = currentRec->hash;
                  currentRec->ext = 1;
                  currentRec->copyNo = 1;
                }
              totalRecs++;
            }
        }
      /* Cleaning up after the remaining hash cluster */
      if (!quite && verbose)
        printf ("Cleaning up...\n");
      dumpHashCluster (output, recList, proc);
      /* Destroying the records of the remaining hash cluster */
      destroyRecord (recList);
      recList = NULL;
      mysql_close (conn);
      fclose (input);
      fclose (output);
      if (!quite)
        {
          size_t total = totalRecs + totalSkip;
          size_t unique = totalRecs - (totalDup + totalColls);
          //        printf ("Processed record(s): %d.\nSkipped record(s): %d.\n\
//Duplicate(s) found: %d.\nCollision(s) found: %d.\n"
          //                , totalRecs
          //                , totalSkip
          //                , totalDup
          //                , totalColls);
          printf ("Total member(s): %ld.\n\tskipped: %ld (%.2f%).\
\n\n\tprocessed:%ld (%.2f%)\n\t\tunique: %ld (%.2f%).\
\n\t\tduplicate: %ld (%.2f%).\n\t\tcollision: %ld (%.2f%).\n"
                  , total
                  , totalSkip
                  , ((float) totalSkip * 100 / total)
                  , totalRecs
                  , ((float) totalRecs * 100 / total)
                  , unique
                  , ((float) unique * 100 / totalRecs)
                  , totalDup
                  , ((float) totalDup * 100 / totalRecs)
                  , totalColls
                  , ((float) totalColls * 100 / totalRecs));
        }
    }
  return (EXIT_SUCCESS);
}
