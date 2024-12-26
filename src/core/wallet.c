#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include "wallet.h"
#include "../utils/logging.h"
#include "../utils/crypto.h"

void print_hex(const char *label, const unsigned char *data, size_t len)
{
  char hex[4096] = {0};
  char *ptr = hex;
  ptrdiff_t remaining = sizeof(hex) - (ptr - hex) - 3;
  for (size_t i = 0; i < len && remaining > 0; i++)
  {
    int written = sprintf(ptr, "%02x", data[i]);
    ptr += written;
    remaining -= written;
  }
  log_message(LOG_DEBUG, "%s: %s", label, hex);
}

void print_openssl_error()
{
  unsigned long err;
  char err_buf[256];
  const char *file, *data;
  int line, flags;

  while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0)
  {
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    log_message(LOG_ERROR, "OpenSSL Error: %s:%d: %s",
                file, line, err_buf);
    if (data && (flags & ERR_TXT_STRING))
    {
      log_message(LOG_ERROR, "Error data: %s", data);
    }
  }
}

Wallet *create_wallet(Blockchain *chain)
{
  log_message(LOG_DEBUG, "Iniciando criação de carteira...");

  if (!chain)
  {
    log_message(LOG_ERROR, "Chain é NULL");
    return NULL;
  }

  if (chain->wallet_count >= MAX_WALLETS)
  {
    log_message(LOG_ERROR, "Máximo de carteiras atingido");
    return NULL;
  }

  Wallet *wallet = &chain->wallets[chain->wallet_count++];

  // Criar um contexto BN
  BN_CTX *bn_ctx = BN_CTX_new();
  if (!bn_ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto BN");
    return NULL;
  }

  // Criar o grupo da curva
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (!group)
  {
    log_message(LOG_ERROR, "Falha ao criar grupo da curva");
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Criar um ponto para a chave pública
  EC_POINT *pub_point = EC_POINT_new(group);
  if (!pub_point)
  {
    log_message(LOG_ERROR, "Falha ao criar ponto EC");
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Gerar chave privada (número aleatório)
  BIGNUM *priv_key = BN_new();
  if (!priv_key)
  {
    log_message(LOG_ERROR, "Falha ao criar BIGNUM para chave privada");
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Obter a ordem da curva
  BIGNUM *order = BN_new();
  if (!EC_GROUP_get_order(group, order, bn_ctx))
  {
    log_message(LOG_ERROR, "Falha ao obter ordem da curva");
    BN_free(priv_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Gerar número aleatório para chave privada
  if (!BN_rand_range(priv_key, order))
  {
    log_message(LOG_ERROR, "Falha ao gerar número aleatório");
    BN_free(order);
    BN_free(priv_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Calcular chave pública: Q = d * G
  if (!EC_POINT_mul(group, pub_point, priv_key, NULL, NULL, bn_ctx))
  {
    log_message(LOG_ERROR, "Falha ao calcular chave pública");
    BN_free(order);
    BN_free(priv_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  // Converter chave privada para bytes
  int priv_len = BN_num_bytes(priv_key);
  if (priv_len > (int)sizeof(wallet->private_key))
  {
    log_message(LOG_ERROR, "Chave privada muito grande");
    BN_free(order);
    BN_free(priv_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }
  BN_bn2bin(priv_key, wallet->private_key);

  // Converter chave pública para bytes
  size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                      wallet->public_key, sizeof(wallet->public_key), bn_ctx);
  if (pub_len == 0)
  {
    log_message(LOG_ERROR, "Falha ao converter chave pública");
    BN_free(order);
    BN_free(priv_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return NULL;
  }

  print_hex("Chave privada", wallet->private_key, priv_len);
  print_hex("Chave pública", wallet->public_key, pub_len);

  // Limpar e liberar recursos
  BN_free(order);
  BN_free(priv_key);
  EC_POINT_free(pub_point);
  EC_GROUP_free(group);
  BN_CTX_free(bn_ctx);

  // Inicializar campos restantes
  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  log_message(LOG_INFO, "Nova carteira criada com endereço: %s", wallet->address);
  return wallet;
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

  unsigned char message[32];
  sha256_hash((unsigned char *)&amount, sizeof(double), message);

  from->balance -= amount;
  to->balance += amount;

  from->transaction_history[from->transaction_count++] = tx;
  to->transaction_history[to->transaction_count++] = tx;

  log_message(LOG_INFO, "Transferência realizada: %f coins de %s para %s",
              amount, from->address, to->address);
  return 1;
}