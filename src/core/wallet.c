#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <openssl/provider.h>
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

  log_message(LOG_DEBUG, "Chain válido, verificando versão OpenSSL...");
  log_message(LOG_DEBUG, "OpenSSL version: %s", OPENSSL_VERSION_TEXT);
  log_message(LOG_DEBUG, "OpenSSL version number: 0x%lx", OpenSSL_version_num());

  if (chain->wallet_count >= MAX_WALLETS)
  {
    log_message(LOG_ERROR, "Máximo de carteiras atingido");
    return NULL;
  }

  ERR_clear_error();
  Wallet *wallet = &chain->wallets[chain->wallet_count++];

  // Criar o grupo da curva diretamente
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (!group)
  {
    log_message(LOG_ERROR, "Falha ao criar grupo da curva");
    print_openssl_error();
    return NULL;
  }

  // Criar o par de chaves EC
  EC_KEY *ec_key = EC_KEY_new();
  if (!ec_key)
  {
    log_message(LOG_ERROR, "Falha ao criar estrutura EC_KEY");
    print_openssl_error();
    EC_GROUP_free(group);
    return NULL;
  }

  if (!EC_KEY_set_group(ec_key, group))
  {
    log_message(LOG_ERROR, "Falha ao definir grupo para EC_KEY");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  // Gerar o par de chaves
  if (!EC_KEY_generate_key(ec_key))
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  // Converter para EVP_PKEY
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key))
  {
    log_message(LOG_ERROR, "Falha ao converter para EVP_PKEY");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  // Carregar providers
  OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
  if (!default_provider)
  {
    log_message(LOG_ERROR, "Falha ao carregar provider default");
    print_openssl_error();
    return NULL;
  }

  OSSL_PROVIDER *legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
  if (!legacy_provider)
  {
    log_message(LOG_ERROR, "Falha ao carregar provider legacy");
    print_openssl_error();
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
  if (!param_bld)
  {
    log_message(LOG_ERROR, "Falha ao criar construtor de parâmetros");
    print_openssl_error();
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0))
  {
    log_message(LOG_ERROR, "Falha ao definir curva secp256k1");
    print_openssl_error();
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  log_message(LOG_DEBUG, "Parâmetros da curva configurados");

  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
  if (!params)
  {
    log_message(LOG_ERROR, "Falha ao criar parâmetros");
    print_openssl_error();
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx)
  {
    log_message(LOG_ERROR, "Falha ao criar contexto EVP");
    print_openssl_error();
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (!EVP_PKEY_CTX_is_a(ctx, "EC"))
  {
    log_message(LOG_ERROR, "Contexto não suporta curvas elípticas");
    print_openssl_error();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  log_message(LOG_DEBUG, "Contexto EVP criado");

  if (EVP_PKEY_keygen_init(ctx) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao inicializar gerador de chave");
    print_openssl_error();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao definir parâmetros");
    print_openssl_error();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  log_message(LOG_DEBUG, "Parâmetros definidos no contexto");

  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_generate(ctx, &pkey) <= 0 || !pkey)
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves ou pkey é NULL");
    print_openssl_error();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  log_message(LOG_DEBUG, "Par de chaves gerado com sucesso");

  if (!EVP_PKEY_is_a(pkey, "EC"))
  {
    log_message(LOG_ERROR, "A chave gerada não é do tipo EC");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, NULL))
  {
    log_message(LOG_ERROR, "Falha ao verificar nome da curva");
    print_openssl_error();
  }

  BIGNUM *order = NULL;
  if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_ORDER, &order))
  {
    log_message(LOG_ERROR, "Falha ao obter ordem da curva");
    print_openssl_error();
  }
  if (order)
    BN_free(order);

  log_message(LOG_DEBUG, "Tipo da chave: %s",
              EVP_PKEY_get0_type_name(pkey) ? EVP_PKEY_get0_type_name(pkey) : "desconhecido");

  int key_size = EVP_PKEY_size(pkey);
  log_message(LOG_DEBUG, "Tamanho total da chave: %d bytes", key_size);

  int key_bits = EVP_PKEY_bits(pkey);
  log_message(LOG_DEBUG, "Bits da chave: %d", key_bits);

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
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
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
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (EVP_PKEY_get_raw_public_key(pkey, wallet->public_key, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave pública");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  print_hex("Chave pública extraída", wallet->public_key, pub_len);
  log_message(LOG_DEBUG, "Chave pública extraída com sucesso (tamanho: %zu)", pub_len);

  size_t priv_len = 0;
  if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao determinar tamanho da chave privada");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
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
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  if (EVP_PKEY_get_raw_private_key(pkey, wallet->private_key, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave privada");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PROVIDER_unload(legacy_provider);
    OSSL_PROVIDER_unload(default_provider);
    return NULL;
  }

  print_hex("Chave privada extraída", wallet->private_key, priv_len);
  log_message(LOG_DEBUG, "Chave privada extraída com sucesso (tamanho: %zu)", priv_len);

  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);
  OSSL_PROVIDER_unload(legacy_provider);
  OSSL_PROVIDER_unload(default_provider);

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