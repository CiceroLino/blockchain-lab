#ifndef BLOCKCHAIN_COMMON_H
#define BLOCKCHAIN_COMMON_H

#include <stdint.h>
#include <time.h>

// Definições gerais
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

// Forward declarations das estruturas principais
typedef struct Transaction Transaction;
typedef struct Block Block;
typedef struct Wallet Wallet;
typedef struct MiningStats MiningStats;
typedef struct Blockchain Blockchain;

#endif // BLOCKCHAIN_COMMON_H