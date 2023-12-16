#include <argp.h>
#include <stdio.h>

#include "md5.h"
#include "rsa.h"

const char *argp_program_version = "MD5 RSA v1";
static char doc[] = "MD5 with RSA";
static char args_doc[] = "TARGET --hash --decrypt --encrypt";
static struct argp_option options[] = {
    {"hash", 'h', 0, 0, "Outputs file hash (md5)"},
    {"encrypt", 'e', 0, 0, "Encryption mode"},
    {"decrypt", 'd', 0, 0, "Decryption mode"},
    {0}};

typedef enum { HASH = 0, ENCRYPT, DECRYPT } Modes;

struct arguments {
  Modes mode;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  switch (key) {
    case 'h':
      arguments->mode = HASH;
      break;
    case 'e':
      arguments->mode = ENCRYPT;
      break;
    case 'd':
      arguments->mode = DECRYPT;
      break;
    case ARGP_KEY_ARG:
      return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

void print_hash(uint8_t p[RESULT_SIZE]) {
  for (int i = 0; i < RESULT_SIZE; ++i) {
    printf("%x", p[i]);
  }
  printf("\n");
}

int main(const int argc, char *argv[]) {
  struct arguments arguments;
  arguments.mode = HASH;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  if (arguments.mode == HASH) {
    uint8_t result[RESULT_SIZE];
    if (argc == 1) {
      md5sum(stdin, result);
    } else {
      FILE *f = fopen(argv[1], "r");
      md5sum(f, result);
      fclose(f);
    }
    print_hash(result);
  } else if (arguments.mode == ENCRYPT) {
    struct pub_key_t pub[1];
    struct priv_key_t priv[1];
    uint8_t hash[RESULT_SIZE] = {0};

    char s[RESULT_SIZE * 2 + 1];
    fgets(s, sizeof(s), stdin);
    s[RESULT_SIZE * 2 + 1] = 0;

    for (int i = 1; i < RESULT_SIZE + 1; ++i) {
      int idx = i * 2;
      char tmp = s[idx];
      s[idx] = 0;
      sscanf(s + idx - 2, "%hhX", &hash[i - 1]);
      s[idx] = tmp;
    }

    rsa_gen_keys(pub, priv);

    for (int i = 0; i < RESULT_SIZE; ++i) {
      long long int encrypted = rsa_encrypt((long long int)hash[i], priv);
      printf("%lld ", encrypted);
    }
    printf("\n");
  } else {
    struct pub_key_t pub[1];
    struct priv_key_t priv[1];

    rsa_gen_keys(pub, priv);

    for (int i = 0; i < RESULT_SIZE; ++i) {
      long long int encrypted;
      scanf("%lld", &encrypted);
      uint8_t decrypted = rsa_decrypt(encrypted, pub);
      printf("%x", decrypted);
    }
  }

  return 0;
}
