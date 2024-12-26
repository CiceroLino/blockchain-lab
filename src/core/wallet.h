#ifndef BLOCKCHAIN_WALLET_H
#define BLOCKCHAIN_WALLET_H

#include "../include/common.h"
#include "blockchain.h"

struct Wallet
{
  unsigned char public_key[65];
  unsigned char private_key[32];
  double balance;
  char address[50];
  Transaction *transaction_history;
  int transaction_count;
};

// Funções da carteira
Wallet *create_wallet(Blockchain *chain);
int transfer_coins(Blockchain *chain, Wallet *from, Wallet *to, double amount);
void generate_wallet_address(unsigned char *public_key, char *address);

#endif // BLOCKCHAIN_WALLET_H