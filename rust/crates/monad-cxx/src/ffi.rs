// Copyright (C) 2025-26 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use tracing::{event, Level};

pub(crate) use self::bindings::{
    monad_log, monad_log_flush_callback, monad_log_get_last_error, monad_log_handler,
    monad_log_handler_create, monad_log_handler_destroy, monad_log_init, monad_log_write_callback,
};

#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Called back by C++, sent to tracing framework via the event! macro
pub(crate) unsafe extern "C" fn log_callback(plog: *const monad_log, _: usize) {
    if plog.is_null() {
        event!(Level::ERROR, "C++ log callback received null pointer");
        return;
    }

    let monad_log {
        syslog_level,
        message,
        message_len,
    } = unsafe { *plog };

    if message.is_null() {
        event!(
            Level::ERROR,
            "C++ log callback received log with null message pointer"
        );
        return;
    }

    let message = String::from_utf8_lossy(unsafe {
        std::slice::from_raw_parts(message as *const u8, message_len)
    });

    match syslog_level {
        0..=3 => event!(Level::ERROR, %message),
        4 => event!(Level::WARN, %message),
        5 => event!(Level::INFO, %message),
        6 => event!(Level::DEBUG, %message),
        _ => event!(Level::TRACE, %message),
    };
}
