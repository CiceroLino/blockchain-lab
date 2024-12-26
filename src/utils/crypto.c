#include <openssl/evp.h>
#include "crypto.h"
#include "logging.h"

void sha256_hash(unsigned char *data, size_t length, unsigned char *hash_out)
{
  log_message(LOG_DEBUG, "Starting SHA256 hash calculation");

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    log_message(LOG_ERROR, "Failed to create MD context");
    return;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
  {
    log_message(LOG_ERROR, "Failed to initialize SHA256");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  if (EVP_DigestUpdate(mdctx, data, length) != 1)
  {
    log_message(LOG_ERROR, "Failed to update digest");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  unsigned int hash_len;
  if (EVP_DigestFinal_ex(mdctx, hash_out, &hash_len) != 1)
  {
    log_message(LOG_ERROR, "Failed to finalize digest");
    EVP_MD_CTX_free(mdctx);
    return;
  }

  EVP_MD_CTX_free(mdctx);
  log_message(LOG_DEBUG, "SHA256 hash calculation completed");
}