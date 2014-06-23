#include "warcsum.h"

const char* WARC_HEADER = "WARC/1.0\r";
const char* CONTENT_LENGTH = "Content-Length";
const char* WARC_TYPE = "WARC-Type";
const char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
const char* WARC_TARGET_URI = "WARC-Target-URI";
const char* WARC_DATE = "WARC-Date";
const char* CONTENT_TYPE = "Content-Type";


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
  /* TIME */
  time_t now_hash;
  time (&now_hash);
  /* END OF TIME */

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
  /* TIME */
  time_t then_hash;
  time (&then_hash);
  time_hash += difftime (then_hash, now_hash);
  /* END OF TIME */
}

/*
 * Hashes input char* using algorithm (1: md5, 2:sha1, 3:sha256) and 
 * sets output with the hexadecimal digest
 */
int
hash_update (unsigned char* buffer, int hash,
             int input_length, void* hash_ctx)
{
  /* TIME */
  time_t now_hash;
  time (&now_hash);
  /* END OF TIME */

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
  /* TIME */
  time_t then_hash;
  time (&then_hash);
  time_hash += difftime (then_hash, now_hash);
  /* END OF TIME */

}

int
hash_final (void* hash_ctx, int hash, char* computed_digest, struct cli_args args)
{
  /* TIME */
  time_t now_hash;
  time (&now_hash);
  /* END OF TIME */

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
      if (args.verbose)
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
      if (args.verbose)
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
      if (args.verbose)
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
  /* TIME */
  time_t then_hash;
  time (&then_hash);
  time_hash += difftime (then_hash, now_hash);
  /* END OF TIME */
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
strcmp_case_insensitive (char* a, const char* b)
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
process_header (z_stream *z, void* vp)
{
  int read_bytes;
  char precomputed_digest[DIGEST_LENGTH];
  char precomputed_hash[KEY_LENGTH];
  char type[WARC_TYPE_LENGTH];
  char content_type[CONTENT_TYPE_LENGTH];
  char* str;
  ssize_t read_length;
  short payload_digest_set = 0;
  FILE* member_file;

  member_file = fmemopen (z->next_out, ((struct mydata*) vp)->max_out - z->avail_out, "r");
  if (member_file == NULL)
    {
      printf ("Could not process header\n");
      return -1;
    }
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
      if (((struct mydata*) vp)->args.verbose)
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
      return -1;
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
          && !((struct mydata*) vp)->args.force_recalculate_digest)
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


          if (((struct mydata*) vp)->args.verbose)
            {
              printf ("WARC payload digest: %s:%s \n", precomputed_hash,
                      precomputed_digest);
            }
          free (pch);
        }
      else if (!strcmp_case_insensitive (key, WARC_TYPE))
        {
          strcpy (type, value);
          if (((struct mydata*) vp)->args.verbose)
            {
              printf ("WARC type: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_DATE))
        {
          strcpy (((struct mydata*) vp)->DATE, value);
          if (((struct mydata*) vp)->args.verbose)
            {
              printf ("WARC date: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_TARGET_URI))
        {
          strcpy (((struct mydata*) vp)->URI, value);
          if (((struct mydata*) vp)->args.verbose)
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

          if (((struct mydata*) vp)->args.verbose)
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
      if (((struct mydata*) vp)->args.verbose)
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
      return -1;
    }
  else if (strcmp_case_insensitive (content_type, "application/http"))
    {
      if (((struct mydata*) vp)->args.verbose)
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
      return -1;
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
      read_bytes = ftell (member_file);
      fclose (member_file);

      /* if digest is calculated and don't need to recalculate*/
      if (payload_digest_set && ((struct mydata*) vp)->args.hash_code == 2 && !((struct mydata*) vp)->args.force_recalculate_digest)
        {
          base32_to_hex (precomputed_digest, ((struct mydata*) vp)->fixed_digest);
          if (((struct mydata*) vp)->args.verbose)
            {
              printf ("Stored digest:\t%s:%s \n", ((struct mydata*) vp)->args.hash_char, ((struct mydata*) vp)->fixed_digest);
            }
        }
    }

  //  z->next_out[((struct mydata*) vp)->max_out - z->avail_out - 4] = '\0';
  return read_bytes;
}

void
process_chunk (z_stream* z, int chunk, void* vp)
{

  int next_out_length = ((struct mydata*) vp)->max_out - z->avail_out;
  /* TIME */
  time_t now_parse;
  time (&now_parse);
  /* END OF TIME */
  struct mydata* mm = ((struct mydata*) vp);

  int read_bytes = 0;

  switch (chunk)
    {
    case CHUNK_FIRST:
      read_bytes = process_header (z, vp);
      if (read_bytes != -1)
        {
          ((struct mydata*) vp)->response = 1;
        }

      if (((struct mydata*) vp)->response) // if header is processed
        {
          if (((struct mydata*) vp)->args.force_recalculate_digest || ((struct mydata*) vp)->hash_algo != 2)
            {
              hash_update (&z->next_out[read_bytes], ((struct mydata*) vp)->hash_algo,
                           next_out_length - read_bytes - 4, ((struct mydata*) vp)->hash_ctx);
              memcpy (((struct mydata*) vp)->last_4, &z->next_out[next_out_length - 4], 4);
            }
        }

      break;
    case CHUNK_MIDDLE:
      if (((struct mydata*) vp)->response) // if header is processed
        {
          if (next_out_length >= 4)
            {
              if (((struct mydata*) vp)->args.force_recalculate_digest || ((struct mydata*) vp)->hash_algo != 2)
                {
                  hash_update (((struct mydata*) vp)->last_4, ((struct mydata*) vp)->hash_algo,
                               4, ((struct mydata*) vp)->hash_ctx);
                  hash_update (z->next_out, ((struct mydata*) vp)->hash_algo,
                               next_out_length - 4, ((struct mydata*) vp)->hash_ctx);
                  memcpy (((struct mydata*) vp)->last_4, &z->next_out[next_out_length - 4], 4);
                }
            }
          else
            {
              if (((struct mydata*) vp)->args.force_recalculate_digest || ((struct mydata*) vp)->hash_algo != 2)
                {
                  hash_update (((struct mydata*) vp)->last_4, ((struct mydata*) vp)->hash_algo,
                               next_out_length, ((struct mydata*) vp)->hash_ctx);
                  memcpy (((struct mydata*) vp)->last_4,
                          &((struct mydata*) vp)->last_4[next_out_length],
                          4 - next_out_length);
                  memcpy (&((struct mydata*) vp)->last_4[4 - next_out_length],
                          z->next_out,
                          next_out_length);
                }
            }
        }
      break;
    case CHUNK_LAST:
      if (((struct mydata*) vp)->response) // if header is processed
        {

          if (next_out_length > 4)
            {
              if (((struct mydata*) vp)->args.force_recalculate_digest || ((struct mydata*) vp)->hash_algo != 2)
                {
                  hash_update (((struct mydata*) vp)->last_4, ((struct mydata*) vp)->hash_algo,
                               4, ((struct mydata*) vp)->hash_ctx);
                  hash_update (z->next_out, ((struct mydata*) vp)->hash_algo,
                               next_out_length - 4, ((struct mydata*) vp)->hash_ctx);
                }
            }
          else
            {
              hash_update (((struct mydata*) vp)->last_4, ((struct mydata*) vp)->hash_algo,
                           next_out_length, ((struct mydata*) vp)->hash_ctx);
            }
        }

      break;
    case CHUNK_FIRST_LAST:
      read_bytes = process_header (z, vp);
      if (((struct mydata*) vp)->response) // if header is processed
        {
          if (((struct mydata*) vp)->args.force_recalculate_digest || ((struct mydata*) vp)->hash_algo != 2)
            {
              hash_update (&z->next_out[read_bytes], ((struct mydata*) vp)->hash_algo,
                           next_out_length - read_bytes, ((struct mydata*) vp)->hash_ctx);
            }
        }
      break;
    }

  /* TIME */
  time_t then_parse;
  time (&then_parse);
  time_parse += difftime (then_parse, now_parse);
  /* END OF TIME */
}

int
process_member (FILE* f_in, FILE* f_out, z_stream *z, struct mydata *m)
{
  m->response = 0;
  m->last_4[0] = '\0';
  m->START = ftell (f_in);
  inflateReset2 (z, 31);
  hash_init (&m->hash_ctx, m->args.hash_code);
  int err = inflateMember (z, f_in, m->max_in, m->max_out, process_chunk, m);
  hash_final (m->hash_ctx, m->args.hash_code, m->computed_digest, m->args);
  m->END = ftell (f_in);

  if (m->response)
    {
      char final_digest[DIGEST_LENGTH];
      if (m->args.force_recalculate_digest || m->hash_algo != 2)
        {
          strcpy (final_digest, m->computed_digest);
        }
      else
        {
          strcpy (final_digest, m->fixed_digest);
        }
      sprintf (m->manifest, "%s %ld %ld %s %s %s\n", m->WARCFILE_NAME, m->START, m->END - m->START, m->URI, m->DATE, final_digest);

      fwrite (m->manifest, 1, strlen (m->manifest), f_out);
      return 0;
    }
  return 1;
}

int
process_file (char *in, FILE* f_out, z_stream* z, struct mydata* m)
{
  printf ("*** %s\n", in);
  int file_size;
  FILE* f_in;

  f_in = fopen (in, "r");
  if (f_in == NULL)
    {
      fprintf (stderr, "Unable to open file: %s\n", in);
      return 1;
    }
  fseek (f_in, 0, SEEK_END);
  file_size = ftell (f_in);
  fseek (f_in, 0, SEEK_SET);

  char temp_FILENAME[FILE_NAME_LENGTH];
  strcpy (temp_FILENAME, in);
  char* pch;
  pch = strtok (temp_FILENAME, "/\\");
  int i;
  for (i = 0; pch != NULL; i++)
    {
      strcpy (m->WARCFILE_NAME, pch);
      pch = strtok (NULL, "/\\");
    }

  do
    {
      //      printf ("%ld\n", ftell (f_in));
      process_member (f_in, f_out, z, m);
    }
  while (ftell (f_in) < file_size);

  fclose (f_in);
  return 0;
}

void
init (z_stream* z, struct mydata* m)
{
  /* z_stream initialization */
  gzmInflateInit (z);
  z->next_in = calloc ((m->args.max_in + 1), sizeof (Bytef)); //extra byte for the null terminator
  z->next_out = calloc ((m->args.max_out + 1), sizeof (Bytef));

  /* mydata, m, declaration and initialization.*/
  m->max_in = m->args.max_in;
  m->max_out = m->args.max_out;
  m->hash_algo = m->args.hash_code;
}

void
end (z_stream* z)
{
  /* z_stream initialization */
  inflateEnd (z);
  free (z->next_in);
  free (z->next_out);
}

int
process_args (int argc, char **argv, struct cli_args* args)
{
  /* Default values */
  args->force_recalculate_digest = 0;
  args->verbose = 0;
  args->hash_code = 2;
  strcpy (args->hash_char, "SHA1");
  strcpy (args->f_input, "");
  strcpy (args->f_output, "");
  args->max_in = 8 * 1024;
  args->max_out = 16 * 1024;

  int opt;

  static struct option long_options[] = {
    {"output", required_argument, 0, 'o'},
    {"input", required_argument, 0, 'i'},
    {"hash", required_argument, 0, 'h'},
    {"recursive", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"force-recalc", no_argument, 0, 'f'},
    {0, 0, 0, 0}
  };

  int option_index = 0;

  while ((opt = getopt_long (argc, argv, "a:b:i:o:h:fv",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'i':
          strcpy (args->f_input, optarg);
          break;
        case 'h':
          strcpy (args->hash_char, optarg);
          if (!strcmp_case_insensitive (args->hash_char, "md5"))
            {
              args->hash_code = 1;
            }
          else if (!strcmp_case_insensitive (args->hash_char, "sha1"))
            {
              args->hash_code = 2;
            }
          else if (!strcmp_case_insensitive (args->hash_char, "sha256"))
            {
              args->hash_code = 3;
            }
          else
            {
              fprintf (stderr,
                       "Invalid argument %s for hash. "
                       "Options: md5, sha1, sha256 \n", args->hash_char);
              exit (EXIT_FAILURE);
            }
          break;
        case 'f':
          args->force_recalculate_digest = 1;
          break;
        case 'o':
          strcpy (args->f_output, optarg);
          break;
        case 'v':
          args->verbose = 1;
          break;
        case 'a':
          args->max_in = atoi (optarg);
          break;
        case 'b':
          args->max_out = atoi (optarg);
          break;
        default:
          fprintf (stderr, "Usage: warcsum [-i input file | required] "
                   "[-o output file | required] "
                   "[-h hashing algorithm] "
                   "[-f force digest calculation] \n");
          exit (EXIT_FAILURE);
        }
    }
  if (!strcmp (args->f_input, "") || !strcmp (args->f_output, ""))
    {
      fprintf (stderr, "Usage: warcsum [-i input file | required] "
               "[-h hashing algorithm | required] "
               "[-o output file | required] "
               "[-f force digest calculation] \n");
      exit (EXIT_FAILURE);
    }
  return 0;
}

int
main (int argc, char **argv)
{
  struct mydata m;
  process_args (argc, argv, &m.args);
  FILE* f_out;
  f_out = fopen (m.args.f_output, "w");

  z_stream z;
  init (&z, &m);
  process_file (m.args.f_input, f_out, &z, &m);
  end (&z);
  fclose (f_out);
  return 0;
}
