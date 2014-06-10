#include "warcsum.h"

char* WARC_HEADER = "WARC/1.0\r";
char* CONTENT_LENGTH = "Content-Length";
char* WARC_TYPE = "WARC-Type";
char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
char* WARC_TARGET_URI = "WARC-Target-URI";
char* WARC_DATE = "WARC-Date";
char* CONTENT_TYPE = "Content-Type";

int force_recalculate_hash, verbose, recursive;
int input_set, output_set, type_set, algo;
char t[KEY_LENGTH];

double time_hash = 0, time_inflate = 0, time_parse = 0;


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

int
hash_init (void** hash_ctx, int hash)
{
  switch (hash)
    {
    case 1:
      *hash_ctx = calloc (1, sizeof (MD5_CTX));
      return MD5_Init ((MD5_CTX*) * hash_ctx);
    case 2:
      *hash_ctx = calloc (1, sizeof (SHA_CTX));
      return SHA1_Init ((SHA_CTX*) * hash_ctx);
    case 3:
      *hash_ctx = calloc (1, sizeof (SHA256_CTX));
      return SHA256_Init ((SHA256_CTX*) * hash_ctx);
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\nHow did you get here?!\n\n", hash);
      exit (EXIT_FAILURE);
    }
}

/*
 * Hashes input char* using algorithm (1: md5, 2:sha1, 3:sha256) and 
 * sets output with the hexadecimal digest
 */
int
hash_update (unsigned char* buffer, int hash,
             int input_length, void* hash_ctx)
{
  switch (hash)
    {
    case 1: // calculate md5
      return MD5_Update ((MD5_CTX*) hash_ctx, buffer, input_length);
    case 2: // calculate sha1
      return SHA1_Update ((SHA_CTX*) hash_ctx, buffer, input_length);
    case 3: // calculate sha256
      return SHA256_Update ((SHA256_CTX*) hash_ctx, buffer, input_length);
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\nHow did you get here?!\n\n", hash);
      exit (EXIT_FAILURE);
    }
}

int
hash_final (void* hash_ctx, int hash, char* computed_digest)
{
  int j = 0;
  int i;
  int ret;
  unsigned char result[DIGEST_LENGTH];

  switch (hash)
    {
    case 1:
      ret = MD5_Final (result, (MD5_CTX*) hash_ctx);
//      for (j = 0; j < MD5_DIGEST_LENGTH; j++) printf ("%02x", c[j]);

      for (i = 0; i < MD5_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computed_digest[j] = temp[0];
          computed_digest[j + 1] = temp[1];
        }
      computed_digest[j] = '\0';
      if (verbose)
        {
          printf ("Hash: MD5 \n");
        }
      break;
    case 2:
      ret = SHA1_Final (result, (SHA_CTX*) hash_ctx);
      for (i = 0; i < SHA_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computed_digest[j] = temp[0];
          computed_digest[j + 1] = temp[1];
        }
      computed_digest[j] = '\0';
      if (verbose)
        {
          printf ("Hash: SHA1 \n");
        }
      break;
    case 3:
      ret = SHA256_Final (result, (SHA256_CTX*) hash_ctx);
      for (i = 0; i < SHA256_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[2];
          sprintf (temp, "%02x", result[i]);
          computed_digest[j] = temp[0];
          computed_digest[j + 1] = temp[1];
        }
      if (verbose)
        {
          printf ("Hash: SHA256 \n");
        }
      computed_digest[j] = '\0';
      break;
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\nHow did you get here?!\n\n", hash);
      exit (EXIT_FAILURE);
    }
  free (hash_ctx);
  return ret;
}

/*
 * Converts base32 numbers following RFC 4648 to hexadecimal numbers
 */
void
base32_to_hex (char* in, char* out)
{
  char binary[BINARY_SHA1_LENGTH];
  assert (strlen (in) == 32);

  /* base32 to binary */
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

  /* binary to hex */
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
  char precomputed_digest[DIGEST_LENGTH];
  char precomputed_hash[KEY_LENGTH];
  char type[WARC_TYPE_LENGTH];
  char content_type[CONTENT_TYPE_LENGTH];
  char* str;
  ssize_t read_length;
  short payload_digest_set = 0;
  FILE* member_file;
  member_file = fmemopen (member, z->total_out, "r");
  size_t ZERO = 0;
  str = NULL;
  /* TIME */
  time_t now_parse;
  time (&now_parse);
  /* END OF TIME */

  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }
  if (str != NULL && strcmp_case_insensitive (str, WARC_HEADER))
    {
      if (verbose)
        {
          printf ("Not a WARC file!!\n");
        }
      free (str);
      fclose (member_file);

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      return 1;
    }
  ZERO = 0;
  free (str);

  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }
  /* Process WARC header */
  while (strcmp_case_insensitive (str, "\r")
         && strcmp_case_insensitive (str, ""))
    {
      char key[KEY_LENGTH], value[WARC_HEADER_SIZE];
      char *pch;
      pch = strtok (str, " \n");
      int i;

      /* parse header line to key: value */
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
          pch = strtok (NULL, " \n\r");
        }
      free (pch);

      /* check key and fill header variables */

      if (!strcmp_case_insensitive (key, WARC_PAYLOAD_DIGEST)
          && !force_recalculate_hash)
        {
          payload_digest_set = 1;
          char* pch;
          pch = strtok (value, ":\r\n ");
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
              pch = strtok (NULL, ":");
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
              printf ("WARC target uri: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, CONTENT_TYPE))
        {
          char* pch;
          pch = strtok (value, ";\r\n ");
          memcpy (content_type, pch, strlen (pch));
          content_type[strlen (pch)] = '\0';

          if (verbose)
            {
              printf ("Content-Type: %s \n", content_type);
            }
        }
      ZERO = 0;
      free (str);
      read_length = getline (&str, &ZERO, member_file);
      if (str[read_length - 1] == '\n')
        {
          str[read_length - 1] = '\0';
        }
    }

  /* continue if warc-type: response
   * and content-type: application/http */
  if (strcmp_case_insensitive (type, "response"))
    {
      if (verbose)
        {
          printf ("WARC-Type is not \"response\" \n");
        }
      free (str);
      fclose (member_file);

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      return 1;
    }
  else if (strcmp_case_insensitive (content_type, "application/http"))
    {
      if (verbose)
        {
          printf ("Response is not HTTP. \n");
        }
      free (str);
      fclose (member_file);

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      return 1;
    }
  else
    {
      free (str);
      ZERO = 0;
      read_length = getline (&str, &ZERO, member_file);
      if (str[read_length - 1] == '\n')
        {
          str[read_length - 1] = '\0';
        }

      /* read HTTP header and discard it */
      while (str != NULL && (strcmp_case_insensitive (str, "\r")
                             && strcmp_case_insensitive (str, "")))
        {
          ZERO = 0;
          free (str);
          read_length = getline (&str, &ZERO, member_file);
          if (str[read_length - 1] == '\n')
            {
              str[read_length - 1] = '\0';
            }
        }
      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      free (str);
      int read_bytes = ftell (member_file);

      if (z->total_out - read_bytes == 0)
        {
          fclose (member_file);
          /* TIME */
          time_t then_parse;
          time (&then_parse);
          time_parse += difftime (then_parse, now_parse);
          /* END OF TIME */
          return 1;
        }

      /* if digest is calculated and don't need to recalculate*/
      if (payload_digest_set && algo == 2 && !force_recalculate_hash)
        {
          char fixed_digest[DIGEST_LENGTH];
          base32_to_hex (precomputed_digest, fixed_digest);
          strcpy (FINAL_HASH, fixed_digest);
          if (verbose)
            {
              printf ("Stored digest:\t%s:%s \n", t, fixed_digest);
            }
        }
      else
        {
          char computed_digest[DIGEST_LENGTH];
          unsigned char *payload = calloc (MEMBER_SIZE, sizeof (char));
          memcpy (payload, &member[read_bytes], z->total_out - read_bytes);
          fread (payload, 1, z->total_out - read_bytes, member_file);

          /* TIME */
          time_t now_hash;
          time (&now_hash);
          /* END OF TIME */

          void* hash_ctx; 
          hash_init (&hash_ctx, algo);
          hash_update (payload, algo, z->total_out - read_bytes, hash_ctx);
          hash_final (hash_ctx, algo, computed_digest);
          
          time_t then_hash;
          time (&then_hash);
          time_hash += difftime (then_hash, now_hash);
          /* END OF TIME */

          if (verbose)
            {
              printf ("Calculated digest:\t%s:%s \n", t, computed_digest);
            }

          strcpy (FINAL_HASH, computed_digest);
          free (payload);
        }
    }


  sprintf (manifest, "%s %s %s", URI, DATE, FINAL_HASH);
  fclose (member_file);
  return 0;
}

int
process_multimember (char* warc_filename, char* manifest_filename)
{
  char temp_FILENAME[FILE_NAME_LENGTH];
  long int START = 0, END = 0, C_SIZE = 0;
  FILE* warc_file;
  FILE* manifest_file;
  char FILENAME[FILE_NAME_LENGTH];
  long file_size;
  z_stream z;

  strcpy (temp_FILENAME, warc_filename);

  printf ("\n===================\n%s\n%s\n", temp_FILENAME, manifest_filename);

  warc_file = fopen (temp_FILENAME, "r");
  if (warc_file == NULL)
    {
      printf ("ERROR opening file: %s\n!!", temp_FILENAME);
      fclose (warc_file);
      return 1;
    }
  /* Inflate Member to member */
  char* pch;
  pch = strtok (temp_FILENAME, "/\\");
  int i;
  for (i = 0; pch != NULL; i++)
    {
      strcpy (FILENAME, pch);
      pch = strtok (NULL, "/\\");
    }
  fseek (warc_file, 0, SEEK_END);
  file_size = ftell (warc_file);
  fseek (warc_file, 0, SEEK_SET);
  gzmInflateInit (&z);

  START = ftell (warc_file);
  while (ftell (warc_file) < file_size)
    {
      unsigned char* member = calloc (MEMBER_SIZE, sizeof (char));

      START = ftell (warc_file);
      if (verbose)
        {
          printf ("***\n");
        }

      /* TIME */
      time_t now_inflate;
      time (&now_inflate);
      /* END OF TIME */

      inflateReset2 (&z, 31);

      inflateMember (warc_file, &z, member, MEMBER_SIZE);

      /* TIME */
      time_t then_inflate;
      time (&then_inflate);
      time_inflate += difftime (then_inflate, now_inflate);
      /* END OF TIME */


      if (z.total_out >= MEMBER_SIZE)
        {
          free (member);
          continue;
        }
      END = ftell (warc_file);
      if (END == file_size)
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
      free (member);

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


      manifest_file = fopen (manifest_filename, "a");
      fwrite (manifest2, 1, strlen (manifest2), manifest_file);
      fclose (manifest_file);

      if (verbose)
        {
          printf ("Manifest: %s \n", manifest2);
        }
    }
  (void) inflateEnd (&z);

  fclose (warc_file);

  return 0;
}

char **
directoryFiles (char *input_dir, int* file_count)
{
  struct dirent **rel_files = NULL;
  struct stat st;
  int i;
  int j = 0;
  *file_count = scandir (input_dir, &rel_files, 0, versionsort);
  char** abs_files = (char**) calloc (*file_count, sizeof (char*));

  if (*file_count < 0)
    {
      free (abs_files);
      perror (input_dir);
      j = -1;
    }
  else
    {
      for (i = 0; i < *file_count; i++)
        {
          char* abs_file = (char*) calloc (FILE_NAME_LENGTH, sizeof (char));
          sprintf (abs_file, "%s/%s", input_dir, rel_files[i]->d_name);

          lstat (abs_file, &st);
          if (!strcmp (rel_files[i]->d_name, ".")
              || !strcmp (rel_files[i]->d_name, "..")
              || !S_ISREG (st.st_mode)
              || strcmp (&abs_file[strlen (abs_file) - 8], ".warc.gz"))
            {
              free (rel_files[i]);
              free (abs_file);
              continue;
            }
          else
            {
              abs_files[j++] = abs_file;
              free (rel_files[i]);
            }
        }
      free (rel_files);
    }
  *file_count = j;
  return abs_files;
}

int
process_directory (char* input_dir, char* manifest_filename)
{
  int n;
  char** abs_files;
  abs_files = directoryFiles (input_dir, &n);
  if (n == -1)
    {
      return 1;
    }
  int i;
  for (i = 0; i < n; i++)
    {
      process_multimember (abs_files[i], manifest_filename);
      free (abs_files[i]);
    }
  free (abs_files);
  return 0;
}

int
main (int argc, char **argv)
{
  force_recalculate_hash = 0;
  verbose = 0;
  recursive = 0;
  input_set = 0;
  output_set = 0;
  type_set = 0;
  int opt;
  char warc_filename[FILE_NAME_LENGTH];
  char manifest_filename[FILE_NAME_LENGTH];
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
          strcpy (warc_filename, optarg);
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
          force_recalculate_hash = 1;
          break;
        case 'o':
          output_set = 1;
          strcpy (manifest_filename, optarg);
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
      int ret = process_multimember (warc_filename, manifest_filename);
      if (verbose)
        {
          printf ("Inflate member:\t%f\n", time_inflate);
          printf ("Hash member:\t%f\n", time_hash);
          printf ("Parse member:\t%f\n", time_parse);
        }
      return ret;
    }
  else
    {
      int ret = process_directory (warc_filename, manifest_filename);
      if (verbose)
        {
          printf ("Inflate member:\t%f\n", time_inflate);
          printf ("Hash member:\t%f\n", time_hash);
          printf ("Parse member:\t%f\n", time_parse);
        }
      return ret;
    }

  return 0;
}
