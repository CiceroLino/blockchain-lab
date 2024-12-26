#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "wallet.h"
#include "../utils/logging.h"
#include "../utils/crypto.h"

Wallet *create_wallet(Blockchain *chain)
{
  if (chain->wallet_count >= MAX_WALLETS)
  {
    log_message(LOG_ERROR, "Máximo de carteiras atingido");
    return NULL;
  }

  Wallet *wallet = &chain->wallets[chain->wallet_count++];

  // Criar contexto EVP
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto EVP");
    return NULL;
  }

  // Inicializar para geração de parâmetros
  if (EVP_PKEY_keygen_init(ctx) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao inicializar geração de chave");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Configurar parâmetros da curva secp256k1
  OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
  if (!param_bld)
  {
    log_message(LOG_ERROR, "Falha ao criar construtor de parâmetros");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0))
  {
    log_message(LOG_ERROR, "Falha ao definir parâmetros da curva");
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
  if (!params)
  {
    log_message(LOG_ERROR, "Falha ao criar parâmetros");
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao definir parâmetros no contexto");
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Gerar o par de chaves
  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_generate(ctx, &pkey) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves");
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Extrair chave pública
  size_t pub_len = sizeof(wallet->public_key);
  if (EVP_PKEY_get_raw_public_key(pkey, wallet->public_key, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave pública");
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Extrair chave privada
  size_t priv_len = sizeof(wallet->private_key);
  if (EVP_PKEY_get_raw_private_key(pkey, wallet->private_key, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave privada");
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  // Inicializar outros campos da carteira
  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  // Limpeza
  EVP_PKEY_free(pkey);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);
  EVP_PKEY_CTX_free(ctx);

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