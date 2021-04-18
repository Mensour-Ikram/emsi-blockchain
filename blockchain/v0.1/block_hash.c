#include "blockchain.h"


uint8_t *block_hash(
	block_t const *block, uint8_t hash_buf[SHA256_DIGEST_LENGTH])
{
	size_t len = 0;

	if (block && hash_buf)
	{
		len = sizeof(block->info) + block->data.len;
		return (sha256((int8_t const *)block, len, hash_buf));
	}
	return (NULL);
}

