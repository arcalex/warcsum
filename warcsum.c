#include "warcsum.h"

const char* WARC_HEADER = "WARC/1.0\r";
const char* CONTENT_LENGTH = "Content-Length";
const char* WARC_TYPE = "WARC-Type";
const char* WARC_PAYLOAD_DIGEST = "WARC-Payload-Digest";
const char* WARC_TARGET_URI = "WARC-Target-URI";
const char* WARC_DATE = "WARC-Date";
const char* CONTENT_TYPE = "Content-Type";


double time_hash = 0, time_inflate = 0, time_parse = 0;

/*
 *  Mapping base32 digits to binary 
 */
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


/*
 *  Mapping binary digits to base16 
 */
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
 *  Initializes hash_ctx struct 
 */
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
 * Update hash struct with input buffer
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

/*
 * Finalize hash and produce digest in hex
 */
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

/*
 * Process WARC header and extract: URI, Date
 * @returns header length if valid WARC response header with http response was found,
 * -1 otherwise.
 */
int
process_header (z_stream *z, void* vp)
{
  int read_bytes = -1;
  char precomputed_digest[DIGEST_LENGTH];
  char precomputed_hash[KEY_LENGTH];
  char type[WARC_TYPE_LENGTH];
  char content_type[CONTENT_TYPE_LENGTH];
  char* str;
  ssize_t read_length;
  short payload_digest_set = 0;
  FILE* member_file;

  /* Open chank as file. */
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

  /* Read line and replace remove \n from its end. */
  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }

  /* Check if it has WARC header */
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

      /* check key and fill header mydata variables */

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

  /* if warc-type is not "response" or content-type not "application/http"
   * return -1
   * else continue
   */
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

      /* read HTTP header till first empty line and discard it */
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

      /* if digest is calculated and don't need to recalculate
       * then fix it to hexadecimal
       */
      if (payload_digest_set && ((struct mydata*) vp)->args.hash_code == 2 && !((struct mydata*) vp)->args.force_recalculate_digest)
        {
          base32_to_hex (precomputed_digest, ((struct mydata*) vp)->fixed_digest);
          if (((struct mydata*) vp)->args.verbose)
            {
              printf ("Stored digest:\t%s:%s \n", ((struct mydata*) vp)->args.hash_char, ((struct mydata*) vp)->fixed_digest);
            }
        }
    }

  return read_bytes;
}

/*
 * if provided chunk is at beginning of member, process header then hash payload
 * else hash payload.
 * Used as callback function by inflate member.
 * @param1: z_stream* holds inflated data and metadata
 * @param2: chuck to know if chunk is first, middle, last or first and last chunk
 * @param3: user defined struct or variable passed to inflate member to be used in process_chunk for general purposes
 */
void
process_chunk (z_stream* z, int chunk, void* vp)
{
  // mm points to vp with casting for more readable and debuggable code.
  struct mydata* mm = ((struct mydata*) vp);
  // next_out_length holds inflated buffer size
  int next_out_length = mm->max_out - z->avail_out;
  /* TIME */
  time_t now_parse;
  time (&now_parse);
  /* END OF TIME */

  int read_bytes = 0;

  /*
   * Last 4 bytes of a chunk are not hashed with the rest of the chunk to make sure they are not part of "\r\n\r\n" which is the separator between members in multi member WARC files.
   */
  switch (chunk)
    {
    case CHUNK_FIRST: // first chunk of the member
      // first process header
      read_bytes = process_header (z, vp);
      if (read_bytes != -1) // if header is valid (warc file, warc response and http response)
        {
          mm->response = 1;
        }

      if (mm->response) // if header is valid
        {
          if (mm->args.force_recalculate_digest || mm->hash_algo != 2) // if recalculate digest
            {
              hash_update (&z->next_out[read_bytes], mm->hash_algo,
                           next_out_length - read_bytes - 4, mm->hash_ctx);
              memcpy (mm->last_4, &z->next_out[next_out_length - 4], 4);
            }
        }

      break;
    case CHUNK_MIDDLE: // neither first nor last chunk of member
      if (mm->response) // if header is processed
        {
          /* MIDDLE CHUNK:
           * check if  chunk length is >= 4 => hash all member except last 4 bytes
           * o.w. hash first n bytes of last 4 of previous chunk, then append current chunk to last (4 - n) bytes to form last_4 bytes and pass them on to next chunk.
           * where n in length of current chunk (next_out_length)
           */
          if (next_out_length >= 4)
            {
              if (mm->args.force_recalculate_digest || mm->hash_algo != 2)
                {
                  hash_update (mm->last_4, mm->hash_algo,
                               4, mm->hash_ctx); // hash last 4 bytes from previous chunk
                  hash_update (z->next_out, mm->hash_algo,
                               next_out_length - 4, mm->hash_ctx); // hash current chunk except for last 4 bytes
                  memcpy (mm->last_4, &z->next_out[next_out_length - 4], 4);
                }
            }
          else
            {
              if (mm->args.force_recalculate_digest || mm->hash_algo != 2)
                {
                  hash_update (mm->last_4, mm->hash_algo,
                               next_out_length, mm->hash_ctx); // hash last_4[0..n]
                  memcpy (mm->last_4,
                          &mm->last_4[next_out_length],
                          4 - next_out_length); // push last_4[n..4] back to last_4[0..(4-n)]
                  memcpy (&mm->last_4[4 - next_out_length],
                          z->next_out,
                          next_out_length); // append current chunk to last4 (last_4[0..(4-n)] + current chunk)
                }
            }
        }
      break;
    case CHUNK_LAST:
      /*
       * LAST CHUNK:
       * check if next_out_length >= 4, hash last_4 of previous chunk, then hash current chunk except for last 4 bytes of it "\r\n\r\n"
       * o.w. hash last_4[0..n] of last chunk, where n in next_out_length
       */
      if (mm->response) // if header is processed
        {

          if (next_out_length >= 4)
            {
              if (mm->args.force_recalculate_digest || mm->hash_algo != 2)
                {
                  hash_update (mm->last_4, mm->hash_algo,
                               4, mm->hash_ctx); // hash last_4
                  hash_update (z->next_out, mm->hash_algo,
                               next_out_length - 4, mm->hash_ctx); // hash current chunk [0..(n-4)] where n is next_out_length
                }
            }
          else
            {
              hash_update (mm->last_4, mm->hash_algo,
                           next_out_length, mm->hash_ctx); // hash last_4[0..n] from previous chunk, where n is next_out_length
            }
        }

      break;
    case CHUNK_FIRST_LAST:
      /* Member fits 1 chunk
       * process header
       * hash chunk[0..(n-4)] where n is next_out_length
       */
      read_bytes = process_header (z, vp); // process header
      if (mm->response)
        {
          if (mm->args.force_recalculate_digest || mm->hash_algo != 2)
            {
              hash_update (&z->next_out[read_bytes], mm->hash_algo,
                           next_out_length - read_bytes, mm->hash_ctx); // hash chunk[0..(n-4)], where n is next_out_length
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

/*
 * Processes next member from warc.gz file pointer
 */
int
process_member (FILE* f_in, FILE* f_out, z_stream *z, struct mydata *m)
{
  /* Reset mydata */
  m->response = 0;
  m->last_4[0] = '\0';
  m->START = ftell (f_in);

  /* Reset z_stream */
  inflateReset2 (z, 31);

  /*Initialize hash_ctx struct */
  hash_init (&m->hash_ctx, m->args.hash_code);

  /* call inflateMember from libgzMulti */
  int err = inflateMember (z, f_in, m->max_in, m->max_out, process_chunk, m);

  /* Finalize hash_ctx and produce calculated digest */
  hash_final (m->hash_ctx, m->args.hash_code, m->computed_digest, m->args);
  m->END = ftell (f_in);

  if (m->response) // if processed member was response
    {
      char final_digest[DIGEST_LENGTH];
      if (m->args.force_recalculate_digest || m->hash_algo != 2) // if calculated hash was chosen
        {
          strcpy (final_digest, m->computed_digest);
        }
      else // if stored hash was chosen
        {
          strcpy (final_digest, m->fixed_digest);
        }
      sprintf (m->manifest, "%s %ld %ld %s %s %s\n", m->WARCFILE_NAME, m->START, m->END - m->START, m->URI, m->DATE, final_digest);

      fwrite (m->manifest, 1, strlen (m->manifest), f_out); // write digest to digests file
      return 0;
    }
  return 1;
}

/* Process warc.gz file */
int
process_file (char *in, FILE* f_out, z_stream* z, struct mydata* m)
{
  printf ("*** %s\n", in);

  /* Open file */
  int file_size;
  FILE* f_in;
  f_in = fopen (in, "r");
  if (f_in == NULL)
    {
      fprintf (stderr, "Unable to open file: %s\n", in);
      return 1;
    }
  /* Calculate file size */
  fseek (f_in, 0, SEEK_END);
  file_size = ftell (f_in);
  fseek (f_in, 0, SEEK_SET);

  /* Get warc file name without full path to be used in digest file*/
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

  // process member by member from the file, till end of file
  do
    {
      process_member (f_in, f_out, z, m);
    }
  while (ftell (f_in) < file_size);

  fclose (f_in);
  return 0;
}

/* Initialize z_stream and mydata */
void
init (z_stream* z, struct mydata* m)
{
  /* z_stream initialization */
  gzmInflateInit (z);
  z->next_in = calloc ((m->args.max_in + 1), sizeof (Bytef)); //extra byte for the null terminator
  z->next_out = calloc ((m->args.max_out + 1), sizeof (Bytef));

  /* mydata initialization.*/
  m->max_in = m->args.max_in;
  m->max_out = m->args.max_out;
  m->hash_algo = m->args.hash_code;
}

/* finalize z_stream */
void
end (z_stream* z)
{
  /* z_stream initialization */
  inflateEnd (z);
  free (z->next_in);
  free (z->next_out);
}

/*
 * Parse and process cli and set cli_args struct
 */
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
  /* z_stream initialization */
  gzmInflateInit (&z);
  z.next_in = calloc ((m.args.max_in + 1), sizeof (Bytef)); //extra byte for the null terminator
  z.next_out = calloc ((m.args.max_out + 1), sizeof (Bytef));

  /* mydata initialization.*/
  m.max_in = m.args.max_in;
  m.max_out = m.args.max_out;
  m.hash_algo = m.args.hash_code;

  process_file (m.args.f_input, f_out, &z, &m);
  /* z_stream initialization */
  inflateEnd (&z);
  free (z.next_in);
  free (z.next_out);
  
  fclose (f_out);
  return 0;
}
