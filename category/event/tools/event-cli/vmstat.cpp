#include "command.hpp"

#include <span>

#include <category/core/assert.h>

void vmstat_thread_main(std::span<Command *const> commands)
{
    MONAD_ASSERT(size(commands) == 1);
}
