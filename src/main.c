#include <openssl/evp.h>
#include <unistd.h>
#include <string.h>
#include "core/blockchain.h"
#include "core/wallet.h"
#include "utils/logging.h"

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