#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>

// Definições para logging
#define LOG_FILE "miner.log"
#define DEBUG 1
#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

// Sistema de Logging
void log_message(int level, const char *format, ...)
{
  static FILE *log_file = NULL;
  static const char *level_strings[] = {
      "ERROR",
      "WARNING",
      "INFO",
      "DEBUG"};

  // Abrir arquivo de log se ainda não estiver aberto
  if (log_file == NULL)
  {
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
      printf("Error opening log file!\n");
      return;
    }
  }

  // Obter timestamp
  time_t now;
  time(&now);
  char timestamp[26];
  ctime_r(&now, timestamp);
  timestamp[24] = '\0'; // Remover newline

  // Formatar mensagem
  va_list args;
  va_start(args, format);

  // Escrever no arquivo de log
  fprintf(log_file, "[%s][%s] ", timestamp, level_strings[level]);
  vfprintf(log_file, format, args);
  fprintf(log_file, "\n");
  fflush(log_file);

  // Se em modo debug, também printar no console
  if (DEBUG)
  {
    printf("[%s] ", level_strings[level]);
    vprintf(format, args);
    printf("\n");
  }

  va_end(args);
}

// Estruturas básicas
typedef struct
{
  unsigned char from[65];
  unsigned char to[65];
  double amount;
  unsigned char signature[72];
} Transaction;

typedef struct
{
  uint32_t version;
  unsigned char prev_block[32];
  unsigned char merkle_root[32];
  uint32_t timestamp;
  uint32_t bits;
  uint64_t nonce;
  Transaction transactions[100];
  int tx_count;
} Block;

// Funções de criptografia
void sha256_hash(unsigned char *data, size_t length, unsigned char *hash_out)
{
  log_message(LOG_DEBUG, "Starting SHA256 hash calculation");

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    log_message(LOG_ERROR, "Failed to create MD context");
    return;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
  {
    log_message(LOG_ERROR, "Failed to initialize SHA256");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  if (EVP_DigestUpdate(mdctx, data, length) != 1)
  {
    log_message(LOG_ERROR, "Failed to update digest");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  unsigned int hash_len;
  if (EVP_DigestFinal_ex(mdctx, hash_out, &hash_len) != 1)
  {
    log_message(LOG_ERROR, "Failed to finalize digest");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  EVP_MD_CTX_free(mdctx);
  log_message(LOG_DEBUG, "SHA256 hash calculation completed");
}

// Mineração
int mine_block(Block *block)
{
  log_message(LOG_INFO, "Starting block mining process");
  unsigned char hash[32];
  uint64_t nonce = 0;
  static const unsigned char target[32] = {
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  while (1)
  {
    // Construir cabeçalho do bloco
    unsigned char block_header[256];
    size_t header_size = 0;

    // Logging detalhado do processo de construção do cabeçalho
    log_message(LOG_DEBUG, "Building block header - Nonce: %lu", nonce);

    memcpy(block_header, &block->version, sizeof(uint32_t));
    memcpy(block_header + sizeof(uint32_t), block->prev_block, 32);
    header_size = sizeof(uint32_t) + 32;

    // Calcular hash
    sha256_hash(block_header, header_size, hash);

    // Verificar dificuldade
    if (memcmp(hash, target, 32) < 0)
    {
      log_message(LOG_INFO, "Block successfully mined!");
      log_message(LOG_DEBUG, "Final nonce: %lu", nonce);
      log_message(LOG_DEBUG, "Block hash: ");
      for (int i = 0; i < 32; i++)
      {
        log_message(LOG_DEBUG, "%02x", hash[i]);
      }
      return 1;
    }

    nonce++;
    if (nonce % 100000 == 0)
    {
      log_message(LOG_INFO, "Mining attempt %lu", nonce);
    }

    if (nonce >= UINT64_MAX)
    {
      log_message(LOG_ERROR, "Nonce overflow - Mining failed");
      return 0;
    }
  }
}

int main(int argc, char *argv[])
{
  log_message(LOG_INFO, "Starting cryptocurrency mining system");

  // Inicializar OpenSSL
  OpenSSL_add_all_algorithms();
  log_message(LOG_DEBUG, "OpenSSL initialized");

  // Criar bloco inicial
  Block block = {0};
  block.version = 1;
  block.timestamp = (uint32_t)time(NULL);

  log_message(LOG_INFO, "Initial block created with timestamp: %u", block.timestamp);

  // Iniciar mineração
  log_message(LOG_INFO, "Starting mining process");
  if (mine_block(&block))
  {
    log_message(LOG_INFO, "Mining completed successfully");
  }
  else
  {
    log_message(LOG_ERROR, "Mining failed");
  }

  log_message(LOG_INFO, "Program execution completed");
  return 0;
}