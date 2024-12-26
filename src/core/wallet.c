#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include "wallet.h"
#include "../utils/logging.h"
#include "../utils/crypto.h"

// Função auxiliar para imprimir bytes em hexadecimal
void print_hex(const char *label, const unsigned char *data, size_t len)
{
  char hex[4096] = {0}; // Buffer grande o suficiente
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
  while ((err = ERR_get_error()))
  {
    char *str = ERR_error_string(err, NULL);
    if (str)
      log_message(LOG_ERROR, "OpenSSL Error: %s", str);
  }
}

Wallet *create_wallet(Blockchain *chain)
{
  if (chain->wallet_count >= MAX_WALLETS)
  {
    log_message(LOG_ERROR, "Máximo de carteiras atingido");
    return NULL;
  }

  ERR_clear_error();
  Wallet *wallet = &chain->wallets[chain->wallet_count++];

  // Criar parâmetros para a chave
  OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
  if (!param_bld)
  {
    log_message(LOG_ERROR, "Falha ao criar construtor de parâmetros");
    return NULL;
  }

  // Configurar a curva secp256k1
  if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0))
  {
    log_message(LOG_ERROR, "Falha ao definir curva secp256k1");
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  log_message(LOG_DEBUG, "Parâmetros da curva configurados");

  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
  if (!params)
  {
    log_message(LOG_ERROR, "Falha ao criar parâmetros");
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  // Criar contexto EVP
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto EVP");
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  log_message(LOG_DEBUG, "Contexto EVP criado");

  // Inicializar gerador de chave
  if (EVP_PKEY_keygen_init(ctx) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao inicializar gerador de chave");
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  // Definir parâmetros no contexto
  if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao definir parâmetros");
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  log_message(LOG_DEBUG, "Parâmetros definidos no contexto");

  // Gerar par de chaves
  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_generate(ctx, &pkey) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves");
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  log_message(LOG_DEBUG, "Par de chaves gerado com sucesso");

  // Verificar se a chave foi realmente gerada corretamente
  if (!EVP_PKEY_is_a(pkey, "EC"))
  {
    log_message(LOG_ERROR, "A chave gerada não é do tipo EC");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  // Obter informações da chave
  log_message(LOG_DEBUG, "Tipo da chave: %s",
              EVP_PKEY_get0_type_name(pkey) ? EVP_PKEY_get0_type_name(pkey) : "desconhecido");

  // Obter tamanho da chave
  int key_size = EVP_PKEY_size(pkey);
  log_message(LOG_DEBUG, "Tamanho total da chave: %d bytes", key_size);

  // Obter bits da chave
  int key_bits = EVP_PKEY_bits(pkey);
  log_message(LOG_DEBUG, "Bits da chave: %d", key_bits);

  // Tentar obter o tamanho da chave pública
  size_t pub_len = 0;
  log_message(LOG_DEBUG, "Tentando determinar tamanho da chave pública...");

  if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao determinar tamanho da chave pública");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  log_message(LOG_DEBUG, "Tamanho necessário para chave pública: %zu bytes", pub_len);

  if (pub_len > sizeof(wallet->public_key))
  {
    log_message(LOG_ERROR, "Buffer da chave pública muito pequeno (%zu > %zu)",
                pub_len, sizeof(wallet->public_key));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  // Extrair a chave pública
  if (EVP_PKEY_get_raw_public_key(pkey, wallet->public_key, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave pública");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  print_hex("Chave pública extraída", wallet->public_key, pub_len);
  log_message(LOG_DEBUG, "Chave pública extraída com sucesso (tamanho: %zu)", pub_len);

  // Determinar o tamanho necessário da chave privada
  size_t priv_len = 0;
  if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao determinar tamanho da chave privada");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  if (priv_len > sizeof(wallet->private_key))
  {
    log_message(LOG_ERROR, "Buffer da chave privada muito pequeno (%zu > %zu)",
                priv_len, sizeof(wallet->private_key));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  // Extrair a chave privada
  if (EVP_PKEY_get_raw_private_key(pkey, wallet->private_key, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave privada");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    return NULL;
  }

  print_hex("Chave privada extraída", wallet->private_key, priv_len);
  log_message(LOG_DEBUG, "Chave privada extraída com sucesso (tamanho: %zu)", priv_len);

  // Inicializar outros campos da carteira
  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  // Limpeza
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);

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