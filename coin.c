#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

// Outras definições
#define MAX_WALLETS 100
#define MAX_BLOCKS 21000000
#define WALLET_FILE "wallets.dat"
#define BLOCKCHAIN_FILE "blockchain.dat"
#define MINING_REWARD 50.0
#define HALVING_INTERVAL 210000

// Para parâmetros não utilizados
#ifdef __GNUC__
#define UNUSED(x) UNUSED_##x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_##x
#endif

// Forward declarations
void log_message(int level, const char *format, ...);
void sha256_hash(unsigned char *data, size_t length, unsigned char *hash_out);
void generate_wallet_address(unsigned char *public_key, char *address);

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

typedef struct
{
  unsigned char public_key[65];
  unsigned char private_key[32];
  double balance;
  char address[50];
  Transaction *transaction_history;
  int transaction_count;
} Wallet;

typedef struct
{
  int total_blocks_mined;
  double total_coins_mined;
  double current_reward;
  time_t last_block_time;
  double network_hashrate;
  uint64_t total_hashes;
} MiningStats;

typedef struct
{
  Block *blocks;
  int block_count;
  MiningStats stats;
  Wallet *wallets;
  int wallet_count;
} Blockchain;

// Sistema de Logging
void log_message(int level, const char *format, ...)
{
  static FILE *log_file = NULL;
  static const char *level_strings[] = {
      "ERROR",
      "WARNING",
      "INFO",
      "DEBUG"};

  if (log_file == NULL)
  {
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
      printf("Error opening log file!\n");
      return;
    }
  }

  time_t now;
  time(&now);
  char timestamp[26];
  ctime_r(&now, timestamp);
  timestamp[24] = '\0';

  va_list args;
  va_start(args, format);

  fprintf(log_file, "[%s][%s] ", timestamp, level_strings[level]);
  vfprintf(log_file, format, args);
  fprintf(log_file, "\n");
  fflush(log_file);

  if (DEBUG)
  {
    printf("[%s] ", level_strings[level]);
    vprintf(format, args);
    printf("\n");
  }

  va_end(args);
}

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

void generate_wallet_address(unsigned char *public_key, char *address)
{
  unsigned char hash[32];
  sha256_hash(public_key, 65, hash);
  sprintf(address, "1");

  for (int i = 0; i < 6; i++)
  {
    sprintf(address + strlen(address), "%02x", hash[i]);
  }
}

Wallet *create_wallet(Blockchain *chain)
{
  if (chain->wallet_count >= MAX_WALLETS)
  {
    log_message(LOG_ERROR, "Máximo de carteiras atingido");
    return NULL;
  }

  Wallet *wallet = &chain->wallets[chain->wallet_count++];

  // Criar contexto para a curva secp256k1
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto");
    return NULL;
  }

  // Inicializar para parâmetros
  if (EVP_PKEY_paramgen_init(ctx) <= 0)
  {
    log_message(LOG_ERROR, "Falha na inicialização dos parâmetros");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Definir a curva
  if (EVP_PKEY_CTX_set_ec_param_enc(ctx, POINT_CONVERSION_UNCOMPRESSED) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao definir codificação do ponto");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao definir curva");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Gerar parâmetros
  EVP_PKEY *params = NULL;
  if (EVP_PKEY_paramgen(ctx, &params) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao gerar parâmetros");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Criar contexto para geração de chave
  EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(params, NULL);
  if (!key_ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto de chave");
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Inicializar geração de chave
  if (EVP_PKEY_keygen_init(key_ctx) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao inicializar geração de chave");
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Gerar o par de chaves
  EVP_PKEY *key = NULL;
  if (EVP_PKEY_keygen(key_ctx, &key) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves");
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Extrair as chaves
  size_t pub_len = sizeof(wallet->public_key);
  size_t priv_len = sizeof(wallet->private_key);

  if (EVP_PKEY_get_raw_public_key(key, wallet->public_key, &pub_len) <= 0 ||
      EVP_PKEY_get_raw_private_key(key, wallet->private_key, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chaves");
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Inicializar outros campos da carteira
  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  // Limpeza
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(key_ctx);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(ctx);

  log_message(LOG_INFO, "Nova carteira criada com endereço: %s", wallet->address);
  return wallet;
}

int transfer_coins(Blockchain *UNUSED(chain), Wallet *from, Wallet *to, double amount)
{
  if (amount <= 0 || from->balance < amount)
  {
    log_message(LOG_ERROR, "Transferência inválida ou saldo insuficiente");
    return 0;
  }

  Transaction tx = {0};
  memcpy(tx.from, from->public_key, 65);
  memcpy(tx.to, to->public_key, 65);
  tx.amount = amount;

  // Assinar transação (simplificado)
  unsigned char message[32];
  sha256_hash((unsigned char *)&amount, sizeof(double), message);

  // Atualizar saldos
  from->balance -= amount;
  to->balance += amount;

  // Registrar no histórico
  from->transaction_history[from->transaction_count++] = tx;
  to->transaction_history[to->transaction_count++] = tx;

  log_message(LOG_INFO, "Transferência realizada: %f coins de %s para %s",
              amount, from->address, to->address);
  return 1;
}

void save_blockchain_state(Blockchain *chain)
{
  FILE *file = fopen(BLOCKCHAIN_FILE, "wb");
  if (!file)
  {
    log_message(LOG_ERROR, "Erro ao salvar blockchain");
    return;
  }

  fwrite(&chain->stats, sizeof(MiningStats), 1, file);
  fwrite(&chain->block_count, sizeof(int), 1, file);

  for (int i = 0; i < chain->block_count; i++)
  {
    fwrite(&chain->blocks[i], sizeof(Block), 1, file);
  }

  fwrite(&chain->wallet_count, sizeof(int), 1, file);
  for (int i = 0; i < chain->wallet_count; i++)
  {
    fwrite(&chain->wallets[i], sizeof(Wallet), 1, file);
    fwrite(&chain->wallets[i].transaction_count, sizeof(int), 1, file);
    fwrite(chain->wallets[i].transaction_history,
           sizeof(Transaction),
           chain->wallets[i].transaction_count,
           file);
  }

  fclose(file);
  log_message(LOG_INFO, "Estado do blockchain salvo com sucesso");
}

Blockchain *load_blockchain_state()
{
  Blockchain *chain = malloc(sizeof(Blockchain));
  FILE *file = fopen(BLOCKCHAIN_FILE, "rb");

  if (!file)
  {
    log_message(LOG_INFO, "Nenhum estado anterior encontrado, iniciando novo blockchain");
    chain->blocks = malloc(sizeof(Block) * MAX_BLOCKS);
    chain->block_count = 0;
    chain->wallets = malloc(sizeof(Wallet) * MAX_WALLETS);
    chain->wallet_count = 0;
    chain->stats = (MiningStats){0};
    chain->stats.current_reward = MINING_REWARD;
    return chain;
  }

  fread(&chain->stats, sizeof(MiningStats), 1, file);
  fread(&chain->block_count, sizeof(int), 1, file);

  chain->blocks = malloc(sizeof(Block) * MAX_BLOCKS);
  for (int i = 0; i < chain->block_count; i++)
  {
    fread(&chain->blocks[i], sizeof(Block), 1, file);
  }

  fread(&chain->wallet_count, sizeof(int), 1, file);
  chain->wallets = malloc(sizeof(Wallet) * MAX_WALLETS);

  for (int i = 0; i < chain->wallet_count; i++)
  {
    fread(&chain->wallets[i], sizeof(Wallet), 1, file);

    int tx_count;
    fread(&tx_count, sizeof(int), 1, file);

    chain->wallets[i].transaction_history = malloc(sizeof(Transaction) * 1000);
    chain->wallets[i].transaction_count = tx_count;

    fread(chain->wallets[i].transaction_history,
          sizeof(Transaction),
          tx_count,
          file);
  }

  fclose(file);
  log_message(LOG_INFO, "Estado do blockchain carregado com sucesso");
  return chain;
}

void print_blockchain_stats(Blockchain *chain)
{
  printf("\n=== Estatísticas do Blockchain ===\n");
  printf("Blocos minerados: %d\n", chain->stats.total_blocks_mined);
  printf("Total de moedas: %.2f\n", chain->stats.total_coins_mined);
  printf("Recompensa atual: %.2f\n", chain->stats.current_reward);
  printf("Carteiras ativas: %d\n", chain->wallet_count);
  printf("Último bloco: %s", ctime(&chain->stats.last_block_time));
  printf("Hashrate: %.2f H/s\n", chain->stats.network_hashrate);
  printf("==============================\n\n");
}

int mine_block(Block *block, Blockchain *chain)
{
  log_message(LOG_INFO, "Iniciando mineração do bloco %d", chain->stats.total_blocks_mined + 1);

  time_t start_time = time(NULL);
  uint64_t initial_hashes = chain->stats.total_hashes;

  unsigned char hash[32];
  static const unsigned char target[32] = {
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  while (block->nonce < UINT64_MAX)
  {
    unsigned char block_header[256];
    size_t header_size = 0;

    log_message(LOG_DEBUG, "Building block header - Nonce: %lu", block->nonce);

    memcpy(block_header, &block->version, sizeof(uint32_t));
    memcpy(block_header + sizeof(uint32_t), block->prev_block, 32);
    header_size = sizeof(uint32_t) + 32;

    sha256_hash(block_header, header_size, hash);

    if (memcmp(hash, target, 32) < 0)
    {
      chain->stats.total_blocks_mined++;
      chain->stats.total_coins_mined += chain->stats.current_reward;
      chain->stats.last_block_time = time(NULL);

      time_t mining_time = chain->stats.last_block_time - start_time;
      chain->stats.total_hashes = block->nonce - initial_hashes;
      chain->stats.network_hashrate = chain->stats.total_hashes / (double)mining_time;

      log_message(LOG_INFO, "Block successfully mined!");
      log_message(LOG_DEBUG, "Final nonce: %lu", block->nonce);
      log_message(LOG_DEBUG, "Block hash: ");
      for (int i = 0; i < 32; i++)
      {
        log_message(LOG_DEBUG, "%02x", hash[i]);
      }

      save_blockchain_state(chain);
      return 1;
    }

    block->nonce++;
    if (block->nonce % 100000 == 0)
    {
      log_message(LOG_INFO, "Mining attempt %lu", block->nonce);
    }
  }

  log_message(LOG_ERROR, "Mining failed - nonce overflow");
  return 0;
}

int main(void)
{
  OpenSSL_add_all_algorithms();

  // Inicializar blockchain
  Blockchain *chain = load_blockchain_state();
  if (!chain)
  {
    log_message(LOG_ERROR, "Failed to initialize blockchain");
    return 1;
  }

  // Criar carteiras para teste
  Wallet *wallet1 = create_wallet(chain);
  if (!wallet1)
  {
    log_message(LOG_ERROR, "Failed to create wallet 1");
    return 1;
  }

  Wallet *wallet2 = create_wallet(chain);
  if (!wallet2)
  {
    log_message(LOG_ERROR, "Failed to create wallet 2");
    return 1;
  }

  log_message(LOG_INFO, "System initialized successfully");

  // Criar bloco gênesis se necessário
  if (chain->block_count == 0)
  {
    log_message(LOG_INFO, "Creating genesis block...");

    Block genesis = {0};
    genesis.version = 1;
    genesis.timestamp = (uint32_t)time(NULL);
    genesis.bits = 0x1d00ffff;

    Transaction coinbase = {0};
    memcpy(coinbase.to, wallet1->public_key, 65);
    coinbase.amount = MINING_REWARD;
    genesis.transactions[0] = coinbase;
    genesis.tx_count = 1;

    if (mine_block(&genesis, chain))
    {
      wallet1->balance += MINING_REWARD;
      chain->blocks[chain->block_count++] = genesis;
      save_blockchain_state(chain);
      log_message(LOG_INFO, "Genesis block created successfully");
    }
    else
    {
      log_message(LOG_ERROR, "Failed to create genesis block");
      return 1;
    }
  }

  // Loop principal de mineração
  while (chain->stats.total_blocks_mined < MAX_BLOCKS)
  {
    print_blockchain_stats(chain);

    Block new_block = {0};
    new_block.version = 1;
    new_block.timestamp = (uint32_t)time(NULL);
    memcpy(new_block.prev_block, chain->blocks[chain->block_count - 1].merkle_root, 32);
    new_block.bits = 0x1d00ffff;

    Transaction mining_reward = {0};
    memcpy(mining_reward.to, wallet1->public_key, 65);
    mining_reward.amount = chain->stats.current_reward;
    new_block.transactions[0] = mining_reward;
    new_block.tx_count = 1;

    if (mine_block(&new_block, chain))
    {
      wallet1->balance += mining_reward.amount;
      chain->blocks[chain->block_count++] = new_block;

      if (chain->stats.total_blocks_mined % 5 == 0)
      {
        double transfer_amount = 1.0;
        if (transfer_coins(chain, wallet1, wallet2, transfer_amount))
        {
          log_message(LOG_INFO, "Test transfer successful");
        }
      }

      if (chain->stats.total_blocks_mined % HALVING_INTERVAL == 0)
      {
        chain->stats.current_reward /= 2.0;
        log_message(LOG_INFO, "Reward halving occurred. New reward: %.8f",
                    chain->stats.current_reward);
      }

      save_blockchain_state(chain);
    }
    else
    {
      log_message(LOG_ERROR, "Failed to mine block");
      break;
    }

    sleep(1);
  }

  // Cleanup
  for (int i = 0; i < chain->wallet_count; i++)
  {
    free(chain->wallets[i].transaction_history);
  }
  free(chain->blocks);
  free(chain->wallets);
  free(chain);

  log_message(LOG_INFO, "Program terminated successfully");
  return 0;
}