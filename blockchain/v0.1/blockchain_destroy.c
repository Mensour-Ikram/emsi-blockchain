#include "blockchain.h"

/**
 * blockchain_destroy - destroy a blockchain
 *
 * @blockchain: pointer to the blockchain
 */
void blockchain_destroy(blockchain_t *blockchain)
{
	if (blockchain)
	{
		llist_destroy(blockchain->chain, 1, (node_dtor_t)free);
		blockchain->chain = NULL;
		free(blockchain);
	}
}

