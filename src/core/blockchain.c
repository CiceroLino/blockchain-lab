#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "blockchain.h"
#include "../utils/logging.h"
#include "../utils/crypto.h"

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