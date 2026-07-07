#include <stddef.h>
#include <stdlib.h>

#include "block_input.h"

static void free_txn(struct txn_input *const txn)
{
    if (txn != nullptr) {
        for (size_t i = 0; i < txn->access_list_count; ++i) {
            free((void *)txn->access_lists[i].keys);
        }
        free((void *)txn->access_lists);
        free((void *)txn->auth_entries);
        free((void *)txn->data.begin);
    }
}

void block_input_free(struct block_input *const block)
{
    if (block != nullptr) {
        for (size_t i = 0; i < block->txn_count; ++i) {
            free_txn((struct txn_input *)&block->txns[i]);
        }
        free((void *)block->txns);
        free(block);
    }
}
