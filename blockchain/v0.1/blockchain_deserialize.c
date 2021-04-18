#include "blockchain.h"
static llist_t *blocks_deserialize(int fd, uint32_t size, uint8_t endianness)
{
	block_t *block = NULL;
	uint32_t index = 0;
	llist_t *list = llist_create(MT_SUPPORT_TRUE);

	if (!list)
		return (NULL);
	for (index = 0; index < size; index++)
	{
		block = calloc(1, sizeof(*block));
		if (!block)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (read(fd, &(block->info), sizeof(block->info)) !=
				sizeof(block->info))
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (endianness)
		{
			SWAPENDIAN(block->info.index);
			SWAPENDIAN(block->info.difficulty);
			SWAPENDIAN(block->info.timestamp);
			SWAPENDIAN(block->info.nonce);
		}
		if (read(fd, &(block->data.len), 4) != 4)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (endianness)
			SWAPENDIAN(block->data.len);
		if (read(fd, block->data.buffer, block->data.len) !=
				block->data.len)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (read(fd, block->hash, SHA256_DIGEST_LENGTH) !=
			SHA256_DIGEST_LENGTH)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (llist_add_node(list, block, ADD_NODE_REAR))
			return (free(block), llist_destroy(list, 1, NULL), NULL);
	}
	return (list);
}
#include "blockchain.h"
static llist_t *blocks_deserialize(int fd, uint32_t size, uint8_t endianness)
{
	block_t *block = NULL;
	uint32_t index = 0;
	llist_t *list = llist_create(MT_SUPPORT_TRUE);

	if (!list)
		return (NULL);
	for (index = 0; index < size; index++)
	{
		block = calloc(1, sizeof(*block));
		if (!block)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (read(fd, &(block->info), sizeof(block->info)) !=
				sizeof(block->info))
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (endianness)
		{
			SWAPENDIAN(block->info.index);
			SWAPENDIAN(block->info.difficulty);
			SWAPENDIAN(block->info.timestamp);
			SWAPENDIAN(block->info.nonce);
		}
		if (read(fd, &(block->data.len), 4) != 4)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (endianness)
			SWAPENDIAN(block->data.len);
		if (read(fd, block->data.buffer, block->data.len) !=
				block->data.len)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (read(fd, block->hash, SHA256_DIGEST_LENGTH) !=
			SHA256_DIGEST_LENGTH)
			return (free(block), llist_destroy(list, 1, NULL), NULL);
		if (llist_add_node(list, block, ADD_NODE_REAR))
			return (free(block), llist_destroy(list, 1, NULL), NULL);
	}
	return (list);
}
blockchain_t *blockchain_deserialize(char const *path)
{
	int fd = -1;
	blockchain_t *blockchain = NULL;
	uint8_t endianness = 0;
	char buf[4096] = {0};
	uint32_t size = 0;

	if (!path)
		return (NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (NULL);
	if (read(fd, buf, HBLK_MAGIC_LEN) != HBLK_MAGIC_LEN ||
			strcmp(buf, HBLK_MAGIC))
		return (free(blockchain), close(fd), NULL);
	buf[strlen(HBLK_VERSION)] = 0;
	if (read(fd, buf, HBLK_VERSION_LEN) != HBLK_VERSION_LEN ||
			strcmp(buf, HBLK_VERSION))
		return (free(blockchain), close(fd), NULL);
	blockchain = calloc(1, sizeof(*blockchain));
	if (!blockchain)
		return (free(blockchain), close(fd), NULL);
	if (read(fd, &endianness, 1) != 1)
		return (free(blockchain), close(fd), NULL);
	endianness = endianness != _get_endianness();
	if (read(fd, &size, 4) != 4)
		return (free(blockchain), close(fd), NULL);
	if (endianness)
		SWAPENDIAN(size);
	blockchain->chain = blocks_deserialize(fd, size, endianness);
	if (!blockchain)
		return (free(blockchain), close(fd), NULL);
	return (close(fd), blockchain);
}

