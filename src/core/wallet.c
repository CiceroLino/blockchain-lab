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

  // Inicialização do OpenSSL
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                          OPENSSL_INIT_ADD_ALL_DIGESTS |
                          OPENSSL_INIT_LOAD_CONFIG,
                      NULL);

  if (!chain)
  {
    log_message(LOG_ERROR, "Chain é NULL");
    return NULL;
  }

  log_message(LOG_DEBUG, "Chain válido, verificando versão OpenSSL...");
  const char *version = OpenSSL_version(OPENSSL_VERSION);
  const char *version_text = OPENSSL_VERSION_TEXT;
  log_message(LOG_DEBUG, "OpenSSL version (OPENSSL_VERSION_TEXT): %s",
              version_text ? version_text : "unknown");
  log_message(LOG_DEBUG, "OpenSSL version (OpenSSL_version): %s",
              version ? version : "unknown");

  // log_message(LOG_DEBUG, "OpenSSL version (OPENSSL_VERSION_TEXT): %s", OPENSSL_VERSION_TEXT);
  // log_message(LOG_DEBUG, "OpenSSL version (OpenSSL_version): %s", OpenSSL_version(OPENSSL_VERSION));

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

  // Verificar se o grupo é válido
  if (!EC_GROUP_check(group, NULL))
  {
    log_message(LOG_ERROR, "Grupo da curva é inválido");
    print_openssl_error();
    EC_GROUP_free(group);
    return NULL;
  }

  // Verificar o nome da curva
  const char *curve_name = OBJ_nid2sn(EC_GROUP_get_curve_name(group));
  log_message(LOG_DEBUG, "Nome da curva: %s", curve_name ? curve_name : "desconhecido");

  log_message(LOG_DEBUG, "Grupo da curva criado com sucesso");

  // Verificar informações do grupo
  int curve_degree = EC_GROUP_get_degree(group);
  log_message(LOG_DEBUG, "Grau da curva: %d bits", curve_degree);

  // Criar o par de chaves EC
  EC_KEY *ec_key = EC_KEY_new();
  if (!ec_key)
  {
    log_message(LOG_ERROR, "Falha ao criar estrutura EC_KEY");
    print_openssl_error();
    EC_GROUP_free(group);
    return NULL;
  }

  log_message(LOG_DEBUG, "EC_KEY criado com sucesso");

  if (!EC_KEY_set_group(ec_key, group))
  {
    log_message(LOG_ERROR, "Falha ao definir grupo para EC_KEY");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  log_message(LOG_DEBUG, "Grupo definido para EC_KEY");

  // Gerar o par de chaves
  if (!EC_KEY_generate_key(ec_key))
  {
    log_message(LOG_ERROR, "Falha ao gerar par de chaves");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  log_message(LOG_DEBUG, "Par de chaves EC gerado com sucesso");

  // Verificar a chave privada
  const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
  if (!priv_key)
  {
    log_message(LOG_ERROR, "Chave privada não foi gerada");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  // Imprimir o tamanho da chave privada em bits
  log_message(LOG_DEBUG, "Tamanho da chave privada: %d bits", BN_num_bits(priv_key));

  // Verificar a chave pública gerada
  const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
  if (!pub_key)
  {
    log_message(LOG_ERROR, "Falha ao obter chave pública do EC_KEY");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  // Verificar o formato da chave pública
  point_conversion_form_t form = EC_KEY_get_conv_form(ec_key);
  log_message(LOG_DEBUG, "Formato da chave pública: %d", (int)form);

  // Verificar o tamanho esperado da chave pública
  size_t expected_size = EC_POINT_point2oct(group, pub_key, form, NULL, 0, NULL);
  log_message(LOG_DEBUG, "Tamanho esperado da chave pública: %zu bytes", expected_size);

  // Converter para EVP_PKEY para usar as funções de extração de chaves
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (!pkey)
  {
    log_message(LOG_ERROR, "Falha ao criar EVP_PKEY");
    print_openssl_error();
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
  {
    log_message(LOG_ERROR, "Falha ao atribuir EC_KEY ao EVP_PKEY");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return NULL;
  }

  log_message(LOG_DEBUG, "Chaves convertidas para EVP_PKEY com sucesso");

  size_t pub_len = 0;
  log_message(LOG_DEBUG, "Tentando determinar tamanho da chave pública...");

  if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao determinar tamanho da chave pública");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EC_GROUP_free(group);
    return NULL;
  }

  log_message(LOG_DEBUG, "Tamanho necessário para chave pública: %zu bytes", pub_len);

  if (pub_len > sizeof(wallet->public_key))
  {
    log_message(LOG_ERROR, "Buffer da chave pública muito pequeno (%zu > %zu)",
                pub_len, sizeof(wallet->public_key));
    EVP_PKEY_free(pkey);
    EC_GROUP_free(group);
    return NULL;
  }

  if (EVP_PKEY_get_raw_public_key(pkey, wallet->public_key, &pub_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave pública");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EC_GROUP_free(group);
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
    EC_GROUP_free(group);
    return NULL;
  }

  if (priv_len > sizeof(wallet->private_key))
  {
    log_message(LOG_ERROR, "Buffer da chave privada muito pequeno (%zu > %zu)",
                priv_len, sizeof(wallet->private_key));
    EVP_PKEY_free(pkey);
    EC_GROUP_free(group);
    return NULL;
  }

  if (EVP_PKEY_get_raw_private_key(pkey, wallet->private_key, &priv_len) <= 0)
  {
    log_message(LOG_ERROR, "Falha ao extrair chave privada");
    print_openssl_error();
    EVP_PKEY_free(pkey);
    EC_GROUP_free(group);
    return NULL;
  }

  print_hex("Chave privada extraída", wallet->private_key, priv_len);
  log_message(LOG_DEBUG, "Chave privada extraída com sucesso (tamanho: %zu)", priv_len);

  generate_wallet_address(wallet->public_key, wallet->address);
  wallet->balance = 0.0;
  wallet->transaction_history = malloc(sizeof(Transaction) * 1000);
  wallet->transaction_count = 0;

  EVP_PKEY_free(pkey);
  EC_GROUP_free(group);

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