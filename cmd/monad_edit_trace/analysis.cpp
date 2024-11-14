#include <monad/event/event.h>
#include <monad/trace/trace_file.h>

#include "analysis.hpp"

monad_trace_flow_type annotate_flow_type(monad_trace_event const &evt)
{
    switch (evt.type) {
    case MONAD_EVENT_BLOCK_START:
        return MONAD_TRACE_FLOW_BLOCK;
    case MONAD_EVENT_TXN_RECOVER:
        return evt.pop_scope ? MONAD_TRACE_FLOW_NONE : MONAD_TRACE_FLOW_TXN;
    case MONAD_EVENT_TXN_EXEC_START:
        return MONAD_TRACE_FLOW_TXN;
    default:
        return MONAD_TRACE_FLOW_NONE;
    }
}

bool event_closes_scope(monad_trace_event const &open_scope, monad_trace_event const &close_scope)
{
    if (open_scope.type == MONAD_EVENT_BLOCK_START &&
        close_scope.type == MONAD_EVENT_BLOCK_END) {
        return true;
    }
    if (open_scope.type == MONAD_EVENT_TXN_EXEC_START &&
        close_scope.type == MONAD_EVENT_TXN_EXEC_END) {
        return true;
    }
    return open_scope.type == close_scope.type;
}
