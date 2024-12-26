#ifndef BLOCKCHAIN_BLOCKCHAIN_H
#define BLOCKCHAIN_BLOCKCHAIN_H

#include "../include/common.h"
#include "wallet.h"

// Estruturas básicas
struct Transaction
{
  unsigned char from[65];
  unsigned char to[65];
  double amount;
  unsigned char signature[72];
};

struct Block
{
  uint32_t version;
  unsigned char prev_block[32];
  unsigned char merkle_root[32];
  uint32_t timestamp;
  uint32_t bits;
  uint64_t nonce;
  Transaction transactions[100];
  int tx_count;
};

struct MiningStats
{
  int total_blocks_mined;
  double total_coins_mined;
  double current_reward;
  time_t last_block_time;
  double network_hashrate;
  uint64_t total_hashes;
};

struct Blockchain
{
  Block *blocks;
  int block_count;
  MiningStats stats;
  Wallet *wallets;
  int wallet_count;
};

// Funções da blockchain
Blockchain *load_blockchain_state(void);
void save_blockchain_state(Blockchain *chain);
void print_blockchain_stats(Blockchain *chain);
int mine_block(Block *block, Blockchain *chain);

#endif // BLOCKCHAIN_BLOCKCHAIN_H