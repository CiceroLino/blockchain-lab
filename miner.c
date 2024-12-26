#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdint.h>

// Define difficulty as bytes array for proper 256-bit comparison
static const unsigned char TARGET_DIFFICULTY_BYTES[] = {
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define LAST_BLOCK_HASH "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

void sha256_modern(unsigned char *data, size_t length, unsigned char *hash_out)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, length);
    EVP_DigestFinal_ex(mdctx, hash_out, &hash_len);

    EVP_MD_CTX_free(mdctx);
}

// Compare two 256-bit numbers (as byte arrays)
int compare_bytes(const unsigned char *a, const unsigned char *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (a[i] != b[i])
        {
            return a[i] < b[i];
        }
    }
    return 0;
}

int mine_block(const char *previous_hash)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char block_data[1024];
    uint64_t nonce = 0;
    int found = 0;

    printf("Starting mining with target difficulty...\n");
    printf("Target: ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", TARGET_DIFFICULTY_BYTES[i]);
    }
    printf("\n");

    while (!found && nonce < UINT64_MAX)
    {
        // Construct block header (simplified)
        snprintf((char *)block_data, sizeof(block_data), "%s%lu", previous_hash, nonce);

        // Generate hash
        sha256_modern(block_data, strlen((char *)block_data), hash);

        // Check if hash meets difficulty requirement
        if (compare_bytes(hash, TARGET_DIFFICULTY_BYTES, 32))
        {
            printf("\nBlock Successfully Mined!\n");
            printf("Nonce: %lu\n", nonce);
            printf("Hash: ");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", hash[i]);
            }
            printf("\n");
            found = 1;
        }

        if (nonce % 1000000 == 0)
        {
            printf("\rHashes attempted: %lu", nonce);
            fflush(stdout);
        }

        nonce++;
    }

    return found;
}

int main()
{
    printf("Starting Bitcoin Block Mining Simulation\n");
    printf("Previous Block Hash: %s\n\n", LAST_BLOCK_HASH);

    if (mine_block(LAST_BLOCK_HASH))
    {
        printf("\nMining completed successfully!\n");
    }
    else
    {
        printf("\nFailed to mine block (nonce overflow).\n");
    }

    return 0;
}