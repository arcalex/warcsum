/*
 *
 * Created on April 28, 2014, 11:58 AM
 */
#include "warcsum.h"

char* WARC_HEADER = "WARC/1.0\r";
char* CONTENT_LENGTH = "Content-Length";
char* WARC_TYPE = "WARC-Type";
char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
char* WARC_TARGET_URI = "WARC-Target-URI";
char* WARC_DATE = "WARC-Date";
char* CONTENT_TYPE = "Content-Type";

int forceRecalc, verbose, recursive, input_set, output_set, type_set;
short algo;
char t[KEY_LENGTH];

const char * const b32_to_bin[] = {
  "00000",
  "00001",
  "00010",
  "00011",
  "00100",
  "00101",
  "00110",
  "00111",
  "01000",
  "01001",
  "01010",
  "01011",
  "01100",
  "01101",
  "01110",
  "01111",
  "10000",
  "10001",
  "10010",
  "10011",
  "10100",
  "10101",
  "10110",
  "10111",
  "11000",
  "11001",
  "11010",
  "11011",
  "11100",
  "11101",
  "11110",
  "11111"
};


const char const bin_to_hex[] = {
  '0',
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
  'a',
  'b',
  'c',
  'd',
  'e',
  'f'
};

/*
 * Hashes input char* using algorithm (1: md5, 2:sha1, 3:sha256) and 
 * sets output with the digest
 */
void
hash (unsigned char* buffer, int hash, unsigned char* computedDigest, int lSize)
{
  int i;
  unsigned char result[DIGEST_LENGTH];
  int j = 0;


  switch (hash)
    {
    case 1: // calculate md5
      MD5 (buffer, lSize, result);
      for (i = 0; i < MD5_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computedDigest[j] = temp[0];
          computedDigest[j + 1] = temp[1];
        }
      computedDigest[j] = '\0';
      if (verbose)
        {
          printf ("Hash: MD5 \n");
        }
      break;
    case 2: // calculate sha1
      SHA1 (buffer, lSize, result);
      for (i = 0; i < SHA_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computedDigest[j] = temp[0];
          computedDigest[j + 1] = temp[1];
        }
      computedDigest[j] = '\0';
      if (verbose)
        {
          printf ("Hash: SHA1 \n");
        }
      break;
    case 3: // calculate sha256
      SHA256 (buffer, lSize, result);
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computedDigest[j] = temp[0];
          computedDigest[j + 1] = temp[1];
        }
      if (verbose)
        {
          printf ("Hash: SHA256 \n");
        }
      computedDigest[j] = '\0';
      break;
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\nHow did you get here?!", hash);
      exit (EXIT_FAILURE);
    }
}

/*
 * Converts base32 numbers following RFC 4648 to hexadecimal numbers
 */
void
base32_to_hex (char* in, char* out)
{
  char binary[160];
  assert (strlen (in) == 32);
  int i;
  for (i = 0; i < strlen (in); i++)
    {
      if ((in[i] >= 'A' && in[i] <= 'Z'))
        {
          strcpy (&binary[i * 5], b32_to_bin[in[i] - 'A']);
        }
      else if (in[i] >= '2' && in[i] <= '7')
        {
          strcpy (&binary[i * 5], b32_to_bin[in[i] - ('2' - 26)]);
        }
      else
        {
          assert (0);
        }
    }
  assert (strlen (binary) == 160);
  int s = 0;
  for (i = 0; i < strlen (binary); i += 4, s++)
    {
      char temp[4];
      memcpy (temp, &binary[i], 4);
      int j;
      int t = 0;
      for (j = 3; j >= 0; j--)
        {
          if (temp[j] == '1')
            {
              t |= (1 << (3 - j));
            }
        }
      out[s] = bin_to_hex[t];
    }
  out[40] = '\0';
}

/*
 * Compares 2 char*s and returns 0 if equal, 1 otherwise 
 */
short
strcmp_case_insensitive (char* a, char* b)
{
  if (strlen (a) != strlen (b))
    {
      return 1;
    }
  else
    {
      int i = 0;
      while (a[i])
        {
          if (tolower (a[i]) != tolower (b[i]))
            {
              return 1;
            }
          i++;
        }
      return 0;
    }
}

int
process_member (char* member, char* manifest, z_stream *z)
{

  char FINAL_HASH[DIGEST_LENGTH];
  char DATE[DATE_LENGTH];
  char URI[URL_LENGTH];
  int lSize;
  char precomputed_digest[DIGEST_LENGTH];
  char precomputed_hash[KEY_LENGTH];
  char type[10];
  char content_type[20];
  char* str;
  ssize_t read_length;
  short content_length_set = 0;
  short payload_digest_set = 0;
  FILE* member_file;
  member_file = fmemopen (member, z->total_out, "r");
  size_t ZERO = 0;
  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }
  //  str = strtok_r (member, "\n", &member_end);
  if (str != NULL && strcmp_case_insensitive (str, WARC_HEADER))
    {
      if (verbose)
        {
          printf ("Not a WARC file!!\n");
        }

      return 1;
    }
  ZERO = 0;
  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }

  //  str = strtok_r (NULL, "\n", &member_end);
  //  while (str != NULL && strcmp_case_insensitive (str, "\r")) // WARC Header
  while (strcmp_case_insensitive (str, "\r") && strcmp_case_insensitive (str, "")) // WARC Header
    {
      char key[KEY_LENGTH], value[WARC_HEADER_SIZE];
      char *pch;
      char *pch_end;
      pch = strtok_r (str, " \n", &pch_end);
      int i;

      for (i = 0; pch != NULL; i++)
        {
          if (i == 0)
            {
              memcpy (key, pch, strlen (pch) - 1);
              key[strlen (pch) - 1] = '\0';
            }
          else if (i == 1)
            {
              strcpy (value, pch);
            }
          pch = strtok_r (NULL, " \n\r", &pch_end);
        }

      free (pch);
      if (!strcmp_case_insensitive (key, CONTENT_LENGTH))
        {
          if (verbose)
            {
              printf ("WARC content length: %s \n", value);

            }
          lSize = atoi (value);
          content_length_set = 1;
        }
      else if (!strcmp_case_insensitive (key, WARC_PAYLOAD_DIGEST))
        {
          payload_digest_set = 1;
          char* pch;
          char* pch_end;
          pch = strtok_r (value, ":\r\n ", &pch_end);
          int i;
          for (i = 0; pch != NULL; i++)
            {
              if (i == 0)
                {
                  memcpy (precomputed_hash, pch, strlen (pch));
                  precomputed_hash[strlen (pch)] = '\0';
                }
              else if (strcmp_case_insensitive (pch, ""))
                {
                  memcpy (precomputed_digest, pch, strlen (pch));
                  precomputed_digest[strlen (pch)] = '\0';
                }
              pch = strtok_r (NULL, ":", &pch_end);
            }


          if (verbose)
            {
              printf ("WARC payload digest: %s:%s \n", precomputed_hash,
                      precomputed_digest);
            }
          free (pch);
        }
      else if (!strcmp_case_insensitive (key, WARC_TYPE))
        {
          strcpy (type, value);
          if (verbose)
            {
              printf ("WARC type: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_DATE))
        {
          strcpy (DATE, value);
          if (verbose)
            {
              printf ("WARC date: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_TARGET_URI))
        {
          strcpy (URI, value);
          if (verbose)
            {
              printf ("WARC target uri: %s, %s \n", value, URI);
            }
        }
      else if (!strcmp_case_insensitive (key, CONTENT_TYPE))
        {
          char* pch;
          char* pch_end;
          pch = strtok_r (value, ";\r\n ", &pch_end);
          memcpy (content_type, pch, strlen (pch));
          content_type[strlen (pch)] = '\0';

          if (verbose)
            {
              printf ("Content-Type: %s \n", content_type);
            }
        }
      ZERO = 0;

      read_length = getline (&str, &ZERO, member_file);
      if (str[read_length - 1] == '\n')
        {
          str[read_length - 1] = '\0';
        }

      //            str = strtok_r (NULL, "\n", &member_end);
    }

  if (strcmp_case_insensitive (type, "response"))
    {
      if (verbose)
        {
          printf ("WARC-Type is not \"response\" \n");
        }
      return 1;
    }
  else if (strcmp_case_insensitive (content_type, "application/http"))
    {
      if (verbose)
        {
          printf ("Response is not HTTP. \n");
        }
      return 1;
    }
  else
    {

      if (payload_digest_set && algo == 2 && !forceRecalc)
        {
          char fixedDigest[DIGEST_LENGTH];
          base32_to_hex (precomputed_digest, fixedDigest);
          strcpy (FINAL_HASH, fixedDigest);
        }
      else
        {
          ZERO = 0;

          read_length = getline (&str, &ZERO, member_file);
          if (str[read_length - 1] == '\n')
            {
              str[read_length - 1] = '\0';
            }

          //          str = strtok_r (NULL, "\n", &member_end);
          while (str != NULL && (strcmp_case_insensitive (str, "\r") && strcmp_case_insensitive (str, "")))
            { // HTTP Header
              ZERO = 0;

              read_length = getline (&str, &ZERO, member_file);
              if (str[read_length - 1] == '\n')
                {
                  str[read_length - 1] = '\0';
                }
              //              str = strtok_r (NULL, "\n", &member_end);
            }
          int lSize = ftell (member_file);
          char computedDigest[DIGEST_LENGTH];

          char member_end[MEMBER_SIZE];
          memcpy (member_end, &member[lSize], z->total_out - lSize);
          fread (member_end, 1, z->total_out - lSize, member_file);

          hash ((unsigned char*) member_end, algo, (unsigned char*) computedDigest, z->total_out - lSize);

          if (verbose)
            {
              printf ("Calculated digest:\t%s:%s \n", t, computedDigest);
            }

          strcpy (FINAL_HASH, computedDigest);


        }

    }


  sprintf (manifest, "%s %s %s", URI, DATE, FINAL_HASH);

  return 0;
}

int
manifest (char* warcFileName, char* manifestFileName)
{
  char temp_FILENAME[FILE_NAME_LENGTH];
  strcpy (temp_FILENAME, warcFileName);
  if (verbose)
    {
      printf ("\n===================\n%s\n%s\n", temp_FILENAME, manifestFileName);
    }

  FILE* warcFile;
  FILE* manifestFile;
  warcFile = fopen (temp_FILENAME, "r");
  if (warcFile == NULL)
    {
      printf ("ERROR opening file: %s\n!!", temp_FILENAME);
      return 1;
    }
  /* Inflate Member to member */
  long int START = 0, END = 0, C_SIZE = 0;
  char FILENAME[FILE_NAME_LENGTH];
  char* pch;
  char* pch_end;
  pch = strtok_r (temp_FILENAME, "/\\", &pch_end);
  int i;
  for (i = 0; pch != NULL; i++)
    {
      strcpy (FILENAME, pch);
      pch = strtok_r (NULL, "/\\", &pch_end);
    }
  pch_end = NULL;
  fseek (warcFile, 0, SEEK_END);
  long fsize = ftell (warcFile);
  fseek (warcFile, 0, SEEK_SET);
  z_stream z;

  START = ftell (warcFile);
  while (ftell (warcFile) != fsize)
    {
      unsigned char member[MEMBER_SIZE];

      START = ftell (warcFile);
      gzmInflateInit (&z);
      if (verbose)
        {
          printf ("***\n");
        }
      inflateMember (warcFile, &z, member, MEMBER_SIZE);

      (void) inflateEnd (&z);

      END = ftell (warcFile);
      if (END == fsize)
        {
          END--;
        }
      C_SIZE = END - START;
      z.total_out -= 4;
      char manifest[MANIFEST_LINE_SIZE];
      if (verbose)
        {
          printf ("Processing offset: %d\n", START);
        }

      int status = process_member (member, manifest, &z);

      if (status)
        {
          continue;

        }
      if (verbose)
        {
          printf ("Manifest1: %s \n", manifest);
        }

      char manifest2[MANIFEST_LINE_SIZE];
      sprintf (manifest2, "%s %ld %ld %s\n", FILENAME, START, C_SIZE, manifest);
      if (verbose)
        {
          printf ("Manifest written \n");
        }


      manifestFile = fopen (manifestFileName, "a");
      fwrite (manifest2, 1, strlen (manifest2), manifestFile);

      if (verbose)
        {
          printf ("Manifest: %s \n", manifest2);
        }
      fclose (manifestFile);
    }

  return 0;
}

char **
directoryFiles (char *input_dir, int* file_count)
{
  struct dirent **rel_files;
  struct stat st;
  int i;
  int j = 0;
  *file_count = scandir (input_dir, &rel_files, 0, versionsort);
  char** abs_files = (char**) malloc (*file_count * sizeof (char*));

  if (*file_count < 0)
    {
      perror (input_dir);
    }
  else
    {
      for (i = 0; i < *file_count; i++)
        {
          if (!strcmp (rel_files[i]->d_name, ".")
              || !strcmp (rel_files[i]->d_name, "..") || S_ISDIR (st.st_mode))
            {
              free (rel_files[i]);
              continue;
            }
          else
            {
              abs_files[j] = (char*) malloc (FILE_NAME_LENGTH * sizeof (char));
              sprintf (abs_files[j++], "%s/%s", input_dir, rel_files[i]->d_name);
              free (rel_files[i]);
            }
        }
      free (rel_files);
    }
  *file_count = j;
  return abs_files;
}

int
main (int argc, char **argv)
{
  forceRecalc = 0;
  verbose = 0;
  recursive = 0;
  input_set = 0;
  output_set = 0;
  type_set = 0;
  int opt;
  char warcFileName[FILE_NAME_LENGTH];
  char manifestFileName[FILE_NAME_LENGTH];
  static struct option long_options[] = {
    {"output", required_argument, 0, 'o'},
    {"input", required_argument, 0, 'i'},
    {"type", required_argument, 0, 't'},
    {"recursive", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"force-recalc", no_argument, 0, 'f'},
    {0, 0, 0, 0}
  };

  int option_index = 0;

  while ((opt = getopt_long (argc, argv, "i:o:t:frv",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'i':
          input_set = 1;
          strcpy (warcFileName, optarg);
          break;
        case 't':
          type_set = 1;
          strcpy (t, optarg);
          if (!strcmp_case_insensitive (t, "md5"))
            {
              algo = 1;
            }
          else if (!strcmp_case_insensitive (t, "sha1"))
            {
              algo = 2;
            }
          else if (!strcmp_case_insensitive (t, "sha256"))
            {
              algo = 3;
            }
          else
            {
              fprintf (stderr,
                       "Invalid argument %s for -t. "
                       "Options: md5, sha1, sha256 \n", t);
              exit (EXIT_FAILURE);
            }
          break;
        case 'f':
          forceRecalc = 1;
          break;
        case 'o':
          output_set = 1;
          strcpy (manifestFileName, optarg);
          break;
        case 'v':
          verbose = 1;
          break;
        case 'r':
          recursive = 1;
          break;
        default:
          fprintf (stderr, "Usage: warcsum [-i input file | required] "
                   "[-t hashing algorithm | required] "
                   "[-o output file | required] "
                   "[-f force digest calculation] "
                   "[-r recursive] \n");
          exit (EXIT_FAILURE);
        }
    }
  if (!input_set || !output_set || !type_set)
    {
      fprintf (stderr, "Usage: warcsum [-i input file | required] "
               "[-t hashing algorithm | required] "
               "[-o output file | required] "
               "[-f force digest calculation] "
               "[-r recursive] \n");
      exit (EXIT_FAILURE);
    }
  if (!recursive)
    {
      manifest (warcFileName, manifestFileName);
    }
  else
    {
      int n;
      char** abs_files;
      abs_files = directoryFiles (warcFileName, &n);
      int i;
      for (i = 0; i < n; i++)
        {
          manifest (abs_files[i], manifestFileName);
          free (abs_files[i]);
        }
      free (abs_files);
    }
  return 0;
}
