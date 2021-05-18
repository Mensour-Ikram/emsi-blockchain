#include "blockchain.h"
uint32_t blockchain_difficulty(blockchain_t const *blockchain)
{
block_t *l_block = NULL;
block_t *adj_block = NULL;
uint64_t expected_elapsed_time = 0;
uint64_t actual_elapsed_time = 0;
l_block = llist_get_tail(blockchain->chain);
if (blockchain == NULL || l_block == NULL)
return (0);
if (l_block->info.index % DIFFICULTY_ADJUSTMENT_INTERVAL
&& l_block->info.index != 0){
adj_block = llist_get_node_at(blockchain->chain,
last_block->info.index + 1 - DIFFICULTY_ADJUSTMENT_INTERVAL)
expected_elapsed_time = DIFFICULTY_ADJUSTEMENT_INTERVAL *
BLOCK_GENERATION_INTERVAL;
actual_elapsed_time = l_block->info.timestamp - adj_block->info.timestamp;
if (actual_elapsed_time < expected_elapsed_time * 0.5)
return (l_block->info.difficulty + 1);
else if (actual_elapsed_time > 2 * expected elapsed_time)
return (l_block->info.difficulty - 1);
else
return (l_block->info.difficulty);
}
return (l_block->info.difficulty);

