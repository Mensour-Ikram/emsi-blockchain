#ifndef _BLOCKCHAIN_H_
#define _BLOCKCHAIN_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <llist.h>

#include "../../crypto/hblk_crypto.h"
#include "provided/endianness.h"

#define HBLK_MAGIC								\
	"HBLK"

#define HBLK_MAGIC_LEN								\
	4

#define HBLK_VERSION								\
	"0.1"

#define HBLK_VERSION_LEN							\
	3

#define BLOCK_DATA_MAX_LEN							\
	1024

#define BLOCK_GENESIS_INIT_INFO_INDEX						\
	0
#define BLOCK_GENESIS_INIT_INFO_DIFFICULTY					\
	0
#define BLOCK_GENESIS_INIT_INFO_TIMESTAMP					\
	1537578000
#define BLOCK_GENESIS_INIT_INFO_NONCE						\
	0
#define BLOCK_GENESIS_INIT_INFO_PREV_HASH					\
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"	\
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define BLOCK_GENESIS_INIT_DATA_BUFFER						\
	"Holberton School"
#define BLOCK_GENESIS_INIT_DATA_LEN						\
	16
#define BLOCK_GENESIS_INIT_DATA							\
{										\
	BLOCK_GENESIS_INIT_DATA_BUFFER,						\
	BLOCK_GENESIS_INIT_DATA_LEN						\
}

#define BLOCK_GENESIS_INIT_HASH							\
	"\xc5\x2c\x26\xc8\xb5\x46\x16\x39\x63\x5d\x8e\xdf\x2a\x97\xd4\x8d"	\
	"\x0c\x8e\x00\x09\xc8\x17\xf2\xb1\xd3\xd7\xff\x2f\x04\x51\x58\x03"

#define BLOCK_GENESIS_INIT							\
{										\
	{									\
		BLOCK_GENESIS_INIT_INFO_INDEX,					\
		BLOCK_GENESIS_INIT_INFO_DIFFICULTY,				\
		BLOCK_GENESIS_INIT_INFO_TIMESTAMP,				\
		BLOCK_GENESIS_INIT_INFO_NONCE,					\
		BLOCK_GENESIS_INIT_INFO_PREV_HASH				\
	},									\
	{									\
		BLOCK_GENESIS_INIT_DATA_BUFFER,					\
		BLOCK_GENESIS_INIT_DATA_LEN					\
	},									\
	BLOCK_GENESIS_INIT_HASH							\
}

/**
 * struct block_info_s - block info
 *
 * @index: index of the block in the blockchain
 * @difficulty: difficulty of proof of work (hash leading zero bits)
 * @timestamp: time the block was created at (UNIX timestamp)
 * @nonce: salt used to create the block hash
 * @prev_hash: hash of the previous block in the blockchain
 */
typedef struct block_info_s
{
	/*
	 * The order of the elements in this structure should remain the same.
	 * It was designed so every element of this structure is aligned and
	 * doesn't require padding from the compiler.
	 * Therefore, it is possible to use the structure as an array of char,
	 * on any architecture.
	 */
	uint32_t	index;
	uint32_t	difficulty;
	uint64_t	timestamp;
	uint64_t	nonce;
	uint8_t	prev_hash[SHA256_DIGEST_LENGTH];
} block_info_t;

/**
 * struct block_data_s - block data
 *
 * @buffer: data buffer
 * @len: data size (in bytes)
 */
typedef struct block_data_s
{
	/*
	 * @buffer must stay first, so we can directly use the structure as
	 * an array of char
	 */
	int8_t	buffer[BLOCK_DATA_MAX_LEN];
	uint32_t	len;
} block_data_t;

/**
 * struct block_s - block
 *
 * @info: block info
 * @data: block data
 * @hash: 256-bit digest of the Block, to ensure authenticity
 */
typedef struct block_s
{
	block_info_t	info; /* this must stay first */
	block_data_t	data; /* this must stay second */
	uint8_t	hash[SHA256_DIGEST_LENGTH];
} block_t;

/**
 * struct blockchain_s - blockchain
 *
 * @chain: linked list of pointers to block_t structures
 */
typedef struct blockchain_s
{
	llist_t	*chain;
} blockchain_t;

blockchain_t *blockchain_create(void);

block_t *block_create(
	block_t const *prev, int8_t const *data, uint32_t data_len);

void block_destroy(block_t *block);

void blockchain_destroy(blockchain_t *blockchain);

uint8_t *block_hash(
	block_t const *block, uint8_t hash_buf[SHA256_DIGEST_LENGTH]);

int blockchain_serialize(blockchain_t const *blockchain, char const *path);

blockchain_t *blockchain_deserialize(char const *path);

int block_is_valid(block_t const *block, block_t const *prev_block);

#endif /* _BLOCKCHAIN_H_ */

