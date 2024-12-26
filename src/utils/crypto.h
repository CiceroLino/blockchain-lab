#ifndef BLOCKCHAIN_CRYPTO_H
#define BLOCKCHAIN_CRYPTO_H

#include <stddef.h>

// Funções criptográficas
void sha256_hash(unsigned char *data, size_t length, unsigned char *hash_out);

#endif // BLOCKCHAIN_CRYPTO_H