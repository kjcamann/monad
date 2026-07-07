#include <stddef.h>
#include <stdlib.h>

#include "block_input.h"
#include "input.h"
#include "mem_state_db.h"
#include "state_db.h"

void sim_input_destroy(struct sim_input *const si)
{
    state_db_destroy(&si->overlay->self);
    for (size_t b = 0; b < si->block_count; ++b) {
        block_input_free((struct block_input *)&si->blocks[b]);
    }
    free((void *)si->description);
    free(si);
}
