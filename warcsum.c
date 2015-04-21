#include "warcsum.h"

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
  //  printf ("HASH INIT\n");
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
    case 4:
      *hash_ctx = calloc (1, sizeof (SHA512_CTX));
      return SHA512_Init ((SHA512_CTX*) * hash_ctx);
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\n"
               "How did you get here?!\n\n", hash);
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
  input_length = input_length < 0 ? 0 : input_length;
  switch (hash)
    {
    case 1: // calculate md5
      return MD5_Update ((MD5_CTX*) hash_ctx, buffer, input_length);
    case 2: // calculate sha1
      return SHA1_Update ((SHA_CTX*) hash_ctx, buffer, input_length);
    case 3: // calculate sha256
      return SHA256_Update ((SHA256_CTX*) hash_ctx, buffer, input_length);
    case 4: // calculate sha256
      return SHA512_Update ((SHA512_CTX*) hash_ctx, buffer, input_length);
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\n"
               "How did you get here?!\n\n", hash);
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
hash_final (void* hash_ctx, int hash, char* computed_digest,
            struct cli_args args)
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
          char temp[3];
          snprintf (temp, sizeof (temp), "%02x", result[i]);
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
          char temp[3];
          snprintf (temp, sizeof (temp), "%02x", result[i]);
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
          char temp[3];
          snprintf (temp, sizeof (temp), "%02x", result[i]);
          computed_digest[j] = temp[0];
          computed_digest[j + 1] = temp[1];
        }
      if (args.verbose)
        {
          printf ("Hash: SHA256 \n");
        }
      computed_digest[j] = '\0';
      break;
    case 4:
      ret = SHA512_Final (result, (SHA512_CTX*) hash_ctx);
      for (i = 0; i < SHA512_DIGEST_LENGTH; i++, j += 2)
        {
          char temp[3];
          snprintf (temp, sizeof (temp), "%02x", result[i]);
          computed_digest[j] = temp[0];
          computed_digest[j + 1] = temp[1];
        }
      if (args.verbose)
        {
          printf ("Hash: SHA512 \n");
        }
      computed_digest[j] = '\0';
      break;
    default:
      fprintf (stderr, "Unknown hash algorithm: %d!!\n"
               "How did you get here?!\n\n", hash);
      exit (EXIT_FAILURE);
    }
  free (hash_ctx);
  /* TIME */
  time_t then_hash;
  time (&then_hash);
  time_hash += difftime (then_hash, now_hash);
  /* END OF TIME */
  return ret;

}

/*
 * Converts base32 numbers following RFC 4648 to hexadecimal numbers
 */
int
base32_to_hex (char* in, char* out)
{
  char binary[BINARY_SHA1_LENGTH];

  /* If strlen(in) != 32 then digest was divided between 2 chunks */
  if (strlen (in) != 32)
    {
      return -1;
    }

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
  return 0;
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
 * Process warcheader to check if http response, then extract DATE and URI
 */
int
process_warcheader (z_stream *z, void* vp)
{
  struct warcsum_struct *attrs = (struct warcsum_struct*) vp;
  int return_value = 0;
  int read_bytes = -1;
  char precomputed_digest[DIGEST_LENGTH];
  char precomputed_hash[KEY_LENGTH];
  char type[WARC_TYPE_LENGTH];
  char content_type[CONTENT_TYPE_LENGTH];
  char* str;
  ssize_t read_length;
  size_t ZERO;
  short payload_digest_set = 0;
  short is_warc_member = 1;
  /* 
   * fmemopen is used to handle strings in memory as files for easier reading 
   * line by line
   */
  FILE* member_file;
  member_file = fmemopen (z->next_out,
                          attrs->effective_out - z->avail_out, "r");

  /* allocate URI dynamically to handle large URLs*/
  char* value = calloc (attrs->effective_out, sizeof (char));
  attrs->URI = calloc (attrs->effective_out, sizeof (char));

  /* Something went wrong creating member_file */
  if (member_file == NULL)
    {
      printf ("Could not process header\n");
      return -1;
    }



  /* TIME */
  time_t now_parse;
  time (&now_parse);
  /* END OF TIME */

  /* Read line and remove \n from its end. */
  ZERO = 0;
  str = NULL;
  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }

  /* Check if it has WARC header */
  // comparison with WARC_HEADER length added to handle single line files
  if (str != NULL && strcmp_case_insensitive (str, WARC_HEADER)
      && attrs->effective_out - z->avail_out > strlen (WARC_HEADER))
    {
      if (attrs->args.verbose)
        {
          printf ("Not a WARC member!!\n");
        }

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      is_warc_member = 0;
      return_value = -1;
    }


  ZERO = 0;
  free (str);
  read_length = getline (&str, &ZERO, member_file);
  if (str[read_length - 1] == '\n')
    {
      str[read_length - 1] = '\0';
    }

  /* Process WARC header line by line*/
  while (!feof (member_file) && strcmp_case_insensitive (str, "\r")
         && strcmp_case_insensitive (str, ""))
    {
      char key[KEY_LENGTH];
      value[0] = '\0';
      char *pch;
      pch = strtok (str, " \n");
      int i;

      /* parse header line to (key: value) */
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

      /* check key and fill header warcsum_struct variables */
      if (!strcmp_case_insensitive (key, WARC_TYPE))
        {
          strcpy (type, value);
          if (attrs->args.verbose)
            {
              printf ("WARC type: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_PAYLOAD_DIGEST)
               && !attrs->args.force_recalculate_digest)
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


          if (attrs->args.verbose)
            {
              printf ("WARC payload digest: %s:%s \n", precomputed_hash,
                      precomputed_digest);
            }
          free (pch);
        }
      else if (!strcmp_case_insensitive (key, WARC_DATE))
        {
          strcpy (attrs->DATE, value);
          if (attrs->args.verbose)
            {
              printf ("WARC date: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, WARC_TARGET_URI))
        {
          strcpy (attrs->URI, value);
          if (attrs->args.verbose)
            {
              printf ("WARC target uri: %s \n", value);
            }
        }
      else if (!strcmp_case_insensitive (key, CONTENT_TYPE))
        {
          char* pch;
          pch = strtok (value, ";\r\n ");
          if (pch != NULL)
            {
              memcpy (content_type, pch, strlen (pch));
              content_type[strlen (pch)] = '\0';
              if (attrs->args.verbose)
                {
                  printf ("Content-Type: %s \n", content_type);
                }
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
  free (value);
  free (str);
  read_bytes = ftell (member_file);
  fclose (member_file);

  /* if end of warc header (empty line) was not encountered, 
   * then need_double */
  if (read_bytes == attrs->effective_out - z->avail_out && is_warc_member)
    {
      attrs->need_double = 1;
      return_value = -1;
    }

  /* if warc member is not response */
  if (strcmp_case_insensitive (type, "response")
      && strcmp_case_insensitive (type, ""))
    {
      if (attrs->args.verbose)
        {
          printf ("WARC-Type is not \"response\" \n");
        }

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      return_value = -1;
    }

  /* if warc response is not application/http */
  if (strcmp_case_insensitive (content_type, "application/http")
      && strcmp_case_insensitive (type, ""))
    {
      if (attrs->args.verbose)
        {
          printf ("Content-type is not \"application/http\" \n");
        }

      /* TIME */
      time_t then_parse;
      time (&then_parse);
      time_parse += difftime (then_parse, now_parse);
      /* END OF TIME */
      return_value = -1;
    }


  /* 
   * if digest is calculated and don't need to recalculate
   * then fix it to hexadecimal
   */
  if (return_value != -1 && payload_digest_set && attrs->args.hash_code == 2
      && !attrs->args.force_recalculate_digest)
    {
      int converted = base32_to_hex (precomputed_digest, attrs->fixed_digest);
      if (converted == -1)
        {
          return_value = -1;
        }
      else
        {
          if (attrs->args.verbose)
            {
              printf ("Stored digest:\t%s:%s \n",
                      attrs->args.hash_char, attrs->fixed_digest);
            }
        }
    }

  return return_value == -1 ? -1 : read_bytes;
}

/* Read the http header and discard it totally */
int
process_httpheader (z_stream *z, void *vp, int header_offset)
{
  struct warcsum_struct *ws = (struct warcsum_struct*) vp;
  int read_bytes = -1;
  int return_value = 0;
  char* str;
  ssize_t read_length;
  size_t ZERO;
  FILE* member_file;

  ZERO = 0;
  member_file = fmemopen (&z->next_out[header_offset],
                          ws->effective_out - z->avail_out - header_offset,
                          "r");
  if (member_file == NULL)
    {
      printf ("Could not process HTTP header\n");
      return_value = -1;
    }
  else
    {
      read_length = getline (&str, &ZERO, member_file);
      if (str[read_length - 1] == '\n')
        {
          str[read_length - 1] = '\0';
        }

      /* read HTTP header till first empty line and discard it */
      while ((str != NULL && (strcmp_case_insensitive (str, "\r")
                              && strcmp_case_insensitive (str, ""))))
        {
          ZERO = 0;
          free (str);
          read_length = getline (&str, &ZERO, member_file);
          if (read_length && str[read_length - 1] == '\n')
            {
              str[read_length - 1] = '\0';
            }
        }
      free (str);
      read_bytes = ftell (member_file);
      fclose (member_file);

    }

  return return_value == -1 ? -1 : read_bytes;
}

/* Process WARC header and extract: URI, Date */
int
process_header (z_stream *z, void* vp)
{
  struct warcsum_struct *mm = (struct warcsum_struct*) vp;
  int warc_header_length = 0;
  int http_header_length = 0;
  warc_header_length = process_warcheader (z, vp);
  if (warc_header_length == -1)
    {
      return -1;
    }
  if (mm->effective_out - z->avail_out > warc_header_length)
    {
      http_header_length = process_httpheader (z, vp, warc_header_length);
    }

  if (http_header_length + warc_header_length
      == mm->effective_out - z->avail_out)
    {
      mm->need_double = 1;
      return -1;
    }
  else
    {
      return http_header_length + warc_header_length;
    }
}

/*
 * if provided chunk is at beginning of member,
 *    process header then hash payload
 * else hash payload.
 * Used as callback function by inflate member.
 */
void
process_chunk (z_stream* z, int chunk, void* vp)
{
  // mm points to vp with casting for more readable and debuggable code.
  struct warcsum_struct* ws = ((struct warcsum_struct*) vp);
  // next_out_length holds inflated buffer size
  int next_out_length = ws->effective_out - z->avail_out;

  /* TIME */
  time_t now_parse;
  time (&now_parse);
  /* END OF TIME */

  int read_bytes = 0;

  /*
   * Last 4 bytes of a chunk are not hashed with the rest of the chunk to make 
   * sure they are not part of "\r\n\r\n" which is the separator between members 
   * in multi member WARC files.
   */
  switch (chunk)
    {
    case CHUNK_FIRST: // first chunk of the member

      // first process header
      read_bytes = process_header (z, vp);

      // if header is valid (warc file, warc response and http response)
      if (read_bytes != -1)
        {
          ws->response = 1;
        }

      // if header is valid
      if (ws->response)
        {
          // if recalculate digest
          if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
            {
              /* 
               * if warc payload length is greater than 4 chars, then save the 
               * last 4 chars in last_4 for handling \r\n\r\n 
               * else save all payload in last_4 and update size_last_4 with the
               * number of chars saved
               */
              if ((next_out_length - read_bytes) >= 4)
                {
                  hash_update (&z->next_out[read_bytes], ws->hash_algo,
                               next_out_length - read_bytes - 4, ws->hash_ctx);
                  memcpy (ws->last_4, &z->next_out[next_out_length - 4], 4);
                  ws->size_last_4 = 4;
                }
              else
                {
                  memcpy (ws->last_4, &z->next_out[read_bytes],
                          next_out_length - read_bytes);
                  ws->size_last_4 = next_out_length - read_bytes;
                }
            }

        }

      break;
    case CHUNK_MIDDLE: // neither first nor last chunk of member
      if (ws->response) // if header is processed and member is warc response
        {
          /* MIDDLE CHUNK:
           * check if  chunk length is >= 4 => hash last_4 
           *      + all member except last 4 bytes
           * o.w. follow comments in else section
           */
          if (next_out_length >= 4)
            {
              if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
                {
                  // hash last 4 bytes from previous chunk
                  hash_update (ws->last_4, ws->hash_algo,
                               ws->size_last_4, ws->hash_ctx);
                  // hash current chunk except for last 4 bytes
                  hash_update (z->next_out, ws->hash_algo,
                               next_out_length - 4, ws->hash_ctx);
                  memcpy (ws->last_4, &z->next_out[next_out_length - 4], 4);
                  ws->size_last_4 = 4;
                }
            }
          else
            {
              if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
                {
                  // length of chars to be hashed from last_4
                  int to_be_hashed = next_out_length + ws->size_last_4 - 4;

                  // hash last_4[0..to_be_hashed]
                  hash_update (ws->last_4, ws->hash_algo,
                               to_be_hashed, ws->hash_ctx);

                  // last_4 <- (4 - next_out_length) chars of last_4 + next_out

                  // push last_4[n..4] back to last_4[0..(4-n)] 
                  // memmove used instead of memcpy 
                  //      due to overlapping source and destination
                  memmove (ws->last_4,
                           &ws->last_4[ws->size_last_4 - (4 - next_out_length)],
                           4 - next_out_length);

                  // append current chunk to last4 
                  //     (last_4[0..(4-n)] + current chunk)
                  memcpy (&ws->last_4[4 - next_out_length],
                          z->next_out,
                          next_out_length);
                  ws->size_last_4 = 4;
                }
            }
        }
      break;
    case CHUNK_LAST:
      /*
       * LAST CHUNK:
       * check if next_out_length >= 4, hash last_4 of previous chunk, 
       * then hash current chunk except for last 4 bytes of it "\r\n\r\n"
       * 
       * o.w. hash last_4[0..n] of last chunk, where n in next_out_length
       */
      if (ws->response) // if header is processed
        {
          if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
            {

              if (next_out_length >= 4)
                {
                  // hash last_4
                  hash_update (ws->last_4, ws->hash_algo,
                               ws->size_last_4, ws->hash_ctx);
                  // hash current chunk [0..(n-4)] where n is next_out_length
                  hash_update (z->next_out, ws->hash_algo,
                               next_out_length - 4, ws->hash_ctx);

                }
              else
                {
                  // hash last_4[0..n] from previous chunk, 
                  // where n is next_out_length + size_last_4 - 4
                  hash_update (ws->last_4, ws->hash_algo,
                               ws->size_last_4 + next_out_length - 4,
                               ws->hash_ctx);
                }
            }
        }
      break;
    case CHUNK_FIRST_LAST:
      /* Member fits in 1 chunk
       * process header
       * hash chunk[0..(n-4)] where n is next_out_length
       */
      read_bytes = process_header (z, vp); // process header

      // if header is valid (warc file, warc response and http response)
      if (read_bytes != -1)
        {
          ws->response = 1;
        }

      // skip member if empty and argument skip empty is set
      if (ws->response && (next_out_length - read_bytes <= 4) && ws->args.skip_empty)
        {
          ws->response = 0;
        }

      if (ws->response)
        {
          if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
            {
              // hash chunk[0..(n-4)], where n is next_out_length
              hash_update (&z->next_out[read_bytes], ws->hash_algo,
                           next_out_length - read_bytes - 4, ws->hash_ctx);
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

/* Processes next member from warc.gz file pointer */
int
process_member (FILE* f_in, FILE* f_out, z_stream *z,
                struct warcsum_struct* ws)
{
  if (ws->args.verbose)
    {
      printf ("\n\n");
      printf ("OFFSET: %ld\n", ftell (f_in));
    }

  /* Reset mydata */
  ws->response = 0;
  ws->last_4[0] = '\0';
  ws->START = ftell (f_in);

  /* Reset z_stream */
  // for notes on '31' refer to libgzmulti code
  inflateReset2 (z, 31);

  /* Initialize hash_ctx struct */
  hash_init (&ws->hash_ctx, ws->args.hash_code);

  /* call inflateMember from libgzMulti */
  int err = inflateMember (z, f_in, ws->effective_in,
                           ws->effective_out, process_chunk, ws);

  /* Finalize hash_ctx and produce calculated digest */
  hash_final (ws->hash_ctx, ws->args.hash_code,
              ws->computed_digest, ws->args);

  /* store position of end of member in compressed file
   * requested by warccolres to download member
   */
  ws->END = ftell (f_in);

  if (ws->response) // if processed member was response
    {
      char final_digest[DIGEST_LENGTH];
      // if calculated hash was chosen
      if (ws->args.force_recalculate_digest || ws->hash_algo != 2)
        {
          strcpy (final_digest, ws->computed_digest);
        }
      else // if stored hash was chosen
        {
          strcpy (final_digest, ws->fixed_digest);
        }

      snprintf (ws->manifest, sizeof (ws->manifest), "%s %u %u %s %s %s\n", ws->WARCFILE_NAME,
                ws->START, ws->END - ws->START, ws->URI,
                ws->DATE, final_digest);

      if (ws->args.verbose)
        {
          printf ("%s\n", ws->manifest);
        }

      // write digest to digests file
      fwrite (ws->manifest, 1, strlen (ws->manifest), f_out);

      free (ws->URI);
      return 0;
    }
  else
    {
      free (ws->URI);
      return 1;
    }
}

/* Process warc.gz file */
int
process_file (char *in, FILE* f_out, z_stream* z, struct warcsum_struct* ws)
{
  /* Open file */
  int file_size;
  FILE* f_in;
  f_in = fopen (in, "r");
  ws->f_in = f_in;
  if (f_in == NULL)
    {
      fprintf (stderr, "Unable to open file: %s\n", in);
      return 1;
    }

  /* check if regular file */
  int fd = fileno (f_in);
  struct stat ss = {0};

  if (-1 == fstat (fd, &ss))
    {
      perror ("fstat() failed");
      return 1;
    }

  else if (!S_ISREG (ss.st_mode))
    {
      printf ("%s is not a regular file.\n", in);
      fclose (f_in);
      return 1;
    }


  /* Calculate file size */
  fseek (f_in, 0, SEEK_END);
  file_size = ftell (f_in);
  fseek (f_in, 0, SEEK_SET);

  /* Get warc file name without full path to be used in digest file */
  char temp_FILENAME[FILE_NAME_LENGTH];
  strcpy (temp_FILENAME, in);
  char* pch;
  pch = strtok (temp_FILENAME, "/\\");
  int i;
  for (i = 0; pch != NULL; i++)
    {
      strcpy (ws->WARCFILE_NAME, pch);
      pch = strtok (NULL, "/\\");
    }

  /* initialize effective_in/out with real_in/out for first member
   */
  ws->effective_in = ws->args.real_in;
  ws->effective_out = ws->args.real_out;


  //  fseek (f_in, 97285811, SEEK_SET);
  // process member by member from the file, till end of file
  do
    {
      /* reprocessing the same member with larger chunk size 
       * for fitting the header in the chunk 
       */
      if (ws->need_double)
        {
          if (ws->args.verbose)
            {
              printf ("Chunk size not sufficient\n"
                      "Doubling chunk size\n"
                      "%u %u\n",
                      ws->START, ws->effective_out);
            }
          short doubled = 0;
          // if can double effective_in_out without overflowing:
          // double effective_in/out
          // o.w. set to UINT_MAX
          if (ws->effective_out * 2 > ws->effective_out)
            {
              ws->effective_out *= 2;
              doubled++;
            }
          else if (ws->effective_out != UINT_MAX)
            {
              ws->effective_out = UINT_MAX;
              doubled++;
            }
          if (ws->effective_in * 2 > ws->effective_in)
            {
              ws->effective_in *= 2;
              doubled++;
            }
          else if (ws->effective_in != UINT_MAX)
            {
              ws->effective_in = UINT_MAX;
              doubled++;
            }

          if (doubled)
            {
              // fseek back to start of member
              fseek (ws->f_in, ws->START, SEEK_SET);
              reset (z, ws);
            }
          else
            {
              printf ("Both in buffer and out buffer reached maximum "
                      "allowed size!\n"
                      "Skipping member.\n");
            }
        }
      else
        {
          /* reset effective_in/out in case they were changed 
           * due to not fitting header in last member
           */
          ws->effective_in = ws->args.real_in;
          ws->effective_out = ws->args.real_out;
          reset (z, ws);
        }
      ws->need_double = 0;
      process_member (f_in, f_out, z, ws);
      //      fseek (f_in, 0, SEEK_END);

    }
  while (ftell (f_in) < file_size || ws->need_double);

  fclose (f_in);
  return 0;
}

/* Process all warc.gz files in a directory */
int
process_directory (char* input_dir, FILE* f_out, z_stream* z, struct warcsum_struct* ws)
{
  DIR *dir;
  struct dirent *ent;
  struct stat file_stat;
  if ((dir = opendir (input_dir)) != NULL)
    {
      while ((ent = readdir (dir)) != NULL)
        {
          // cat dir path to file
          char full_file_path[FILE_NAME_LENGTH];
          strcpy (full_file_path, input_dir);
          strcat (full_file_path, "/");
          strcat (full_file_path, ent->d_name);
          if (stat (full_file_path, &file_stat))
            {
              perror ("Error processing file: ");
            }
          // if "." or "..", skip it
          if (!strcmp_case_insensitive (ent->d_name, ".")
              || !strcmp_case_insensitive (ent->d_name, ".."));
            // if a regular file, process it
          else if (S_ISREG(file_stat.st_mode))
            {
              process_file (full_file_path, f_out, z, ws);
            }
            // if a directory, recurse through it
          else if (S_ISDIR(file_stat.st_mode))
            {
              // add '/' to the end of the directory path
              process_directory (full_file_path, f_out, z, ws);
            }
          else
            {
              if (ws->args.verbose)
                {
                  printf ("%s is neither a regular file nor a directory!\n",
                          ent->d_name);
                }
            }
        }
      closedir (dir);
      return 0;
    }
  perror ("Could not open directory !!\n");
  return 1;
}

/* Initialize z_stream and warcsum_struct */
void
init (z_stream* z, struct warcsum_struct* ws)
{
  /* z_stream initialization */
  gzmInflateInit (z);
  //extra byte for the null terminator
  z->next_in = calloc ((ws->args.real_in + 1), sizeof (Bytef));
  z->next_out = calloc ((ws->args.real_out + 1), sizeof (Bytef));

  /* warcsum_struct initialization.*/
  ws->effective_in = ws->args.real_in;
  ws->effective_out = ws->args.real_out;
  ws->hash_algo = ws->args.hash_code;
  ws->need_double = 0;
}

/* reset z_stream and warcsum_struct */
void
reset (z_stream* z, struct warcsum_struct* ws)
{
  free (z->next_in);
  free (z->next_out);

  z->next_in = calloc (ws->effective_in + 1, sizeof (Bytef));
  z->next_out = calloc (ws->effective_out + 1, sizeof (Bytef));
}

/* finalize z_stream */
void
end (z_stream* z)
{
  /* z_stream terminating */
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
  args->append = 0;
  args->skip_empty = 0;
  args->recursive = 0;
  strcpy (args->hash_char, "SHA1");
  strcpy (args->f_input, "");
  strcpy (args->f_output, "");
  args->real_in = 8 * 1024;
  args->real_out = 16 * 1024;

  int opt;
  static struct option long_options[] = {
    {"output", required_argument, 0, 'o'},
    {"input", required_argument, 0, 'i'},
    {"hash", required_argument, 0, 'H'},
    {"recursive", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"force-recalc", no_argument, 0, 'f'},
    {"skip-empty", no_argument, 0, 's'},
    {"input-buffer", required_argument, 0, 'I'},
    {"output-buffer", required_argument, 0, 'O'},
    {"append", no_argument, 0, 'a'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0}
  };

  int option_index = 0;
  int length;

  while ((opt = getopt_long (argc, argv, "I:O:i:o:H:fvahVrs",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'i':
          strcpy (args->f_input, optarg);
          break;
        case 'o':
          strcpy (args->f_output, optarg);
          break;
        case 'H':
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
          else if (!strcmp_case_insensitive (args->hash_char, "sha512"))
            {
              args->hash_code = 4;
            }
          else
            {
              fprintf (stderr,
                       "Invalid argument %s for hash. "
                       "Options: md5, sha1, sha256, sha512\n", args->hash_char);
              exit (EXIT_FAILURE);
            }
          break;
        case 'f':
          args->force_recalculate_digest = 1;
          break;
        case 'v':
          args->verbose = 1;
          break;
        case 's':
          args->skip_empty = 1;
          break;
        case 'I':
          length = strlen (optarg);
          switch (optarg[length - 1])
            {
            case 'K':
              args->real_in = atoi (optarg) * 1024;
              break;
            case 'M':
              args->real_in = atoi (optarg) * 1024 * 1024;
              break;
            case 'G':
              args->real_in = atoi (optarg) * 1024 * 1024 * 1024;
              break;
            default:
              args->real_in = atoi (optarg);
            }
          break;
        case 'O':
          length = strlen (optarg);
          switch (optarg[length - 1])
            {
            case 'K':
              args->real_out = atoi (optarg) * 1024;
              break;
            case 'M':
              args->real_out = atoi (optarg) * 1024 * 1024;
              break;
            case 'G':
              args->real_out = atoi (optarg) * 1024 * 1024 * 1024;
              break;
            default:
              args->real_out = atoi (optarg);
            }
          break;

        case 'a':
          args->append = 1;
          break;
        case 'r':
          args->recursive = 1;
          break;
        case 'V':
          version ();
          exit (EXIT_SUCCESS);
        case 'h':
          help ();
          exit (EXIT_SUCCESS);
        default:
          fprintf (stderr, "Usage: warcsum [-i input file | required] "
                   "[-o output file | required] "
                   "[-H hashing algorithm] "
                   "[-f force digest calculation] "
                   "[-v verbose] "
                   "[-r recursive] "
                   "[-I input buffer size] "
                   "[-O output buffer size] "
                   "[-a append] \n");
          exit (EXIT_FAILURE);
        }
    }
  if (!strcmp (args->f_input, "") || !strcmp (args->f_output, ""))
    {
      fprintf (stderr, "Usage: warcsum [-i input file | required] "
               "[-o output file | required] "
               "[-H hashing algorithm] "
               "[-f force digest calculation] "
               "[-v verbose] "
               "[-r recursive] "
               "[-I input buffer size] "
               "[-O output buffer size] "
               "[-a append] \n");
      exit (EXIT_FAILURE);
    }
  return 0;
}

/*
 * Display version
 */
void
version ()
{
  printf ("GNU warcsum 0.1\n"
          " * Copyright (C) 2015 Bibliotheca Alexandrina\n");
}

/*
 * Display help page
 */
void
help ()
{
  printf ("Usage\n");
  printf ("\twarcsum [-i FILE] [-o FILE] [-H HASH ALGO] "
          "[-I Input buffer size] [-O Output buffer size] -a -f -v\n");
  printf ("Options\n");
  printf ("\t-i, --input=FILE\n");
  printf ("\t\tPath to warcfile.\n");
  printf ("\n");
  printf ("\t-o, --ouput=FILE\n");
  printf ("\t\tPath to digest file.\n");
  printf ("\n");
  printf ("\t-I, --input-buffer=SIZE\n");
  printf ("\t\tInitial compressed buffer size, if size is not sufficient to "
          "fit the headers, buffer size is doubled.\n");
  printf ("\n");
  printf ("\t-O, --output-buffer=SIZE\n");
  printf ("\t\tInitial uncompressed buffer size, if size is not sufficient to "
          "fit the headers, buffer size is doubled.\n");
  printf ("\n");
  printf ("\t-H, --hash=HASHING_ALGORITHM\n");
  printf ("\t\tHashing algorithm to be used for hashing the warc member "
          "payload.  Possible options are md5, sha1, sha256 or sha512. "
          "The default option is sha1.\n");
  printf ("\n");
  printf ("\t-f, --force\n");
  printf ("\t\tForce recalculate hash and discard stored hash "
          "in the WARC member header. If --hash option was supplied and hash "
          "type is not sha1, hash is recalculated by default.\n");
  printf ("\n");
  printf ("\t-a, --append\n");
  printf ("\t\tAppend to output file instead of rewriting it.\n");
  printf ("\n");
  printf ("\t-v, --verbose\n");
  printf ("\n");
}

int
main (int argc, char **argv)
{
  struct warcsum_struct ws;
  process_args (argc, argv, &ws.args);
  FILE* f_out;
  if (ws.args.append)
    {
      f_out = fopen (ws.args.f_output, "a");
    }
  else
    {
      f_out = fopen (ws.args.f_output, "w");
    }
  if (f_out == NULL)
    {
      printf ("Unable to open output file: %s\n", ws.args.f_output);
      return 1;
    }
  z_stream z;

  init (&z, &ws);

  if (ws.args.recursive)
    {
      process_directory (ws.args.f_input, f_out, &z, &ws);
    }
  else
    {
      process_file (ws.args.f_input, f_out, &z, &ws);
    }
  end (&z);

  fclose (f_out);

  return 0;
}
