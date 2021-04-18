#include <stdlib.h>

#include "blockchain.h"


void _blockchain_destroy(blockchain_t *blockchain)
{
	if (!blockchain)
		return;

	llist_destroy(blockchain->chain, 1, (node_dtor_t)free);

	free(blockchain);
}

