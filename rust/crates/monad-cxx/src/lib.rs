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

use std::sync::OnceLock;

use tracing::Level;

use self::{
    error::{check_log_library_error, LogError},
    ffi::{
        log_callback, monad_log_flush_callback, monad_log_handler, monad_log_handler_create,
        monad_log_handler_destroy, monad_log_init, monad_log_write_callback,
    },
};

mod error;
mod ffi;

struct LogHandler {
    c_handle: *mut monad_log_handler,
}

// it's safe to call monad_log_handler_create and monad_log_handler_destroy on different threads
unsafe impl Send for LogHandler {}
unsafe impl Sync for LogHandler {}

impl LogHandler {
    fn create(
        name: &str,
        write: monad_log_write_callback,
        flush_opt: monad_log_flush_callback,
        user: usize,
    ) -> Result<LogHandler, LogError> {
        let mut c_handle: *mut monad_log_handler = std::ptr::null_mut();

        let c_name_buf =
            std::ffi::CString::new(name).map_err(|err| LogError::new(err.to_string()))?;

        let rc = unsafe {
            monad_log_handler_create(&mut c_handle, c_name_buf.as_ptr(), write, flush_opt, user)
        };

        check_log_library_error(rc).map(|()| LogHandler { c_handle })
    }
}

impl Drop for LogHandler {
    fn drop(&mut self) {
        unsafe { monad_log_handler_destroy(self.c_handle) }
    }
}

static SINGLETON_LOG_HANDLER: OnceLock<LogHandler> = OnceLock::new();

pub fn init_cxx_logging(log_level: Level) {
    SINGLETON_LOG_HANDLER.get_or_init(|| {
        let handler = LogHandler::create("cxx_to_rust", Some(log_callback), None, 0)
            .expect("failed to create C++ log handler");

        let syslog_level: u8 = match log_level {
            Level::ERROR => 3,
            Level::WARN => 4,
            Level::INFO => 5,
            Level::DEBUG => 6,
            Level::TRACE => 7,
        };

        let mut handler_array: [*mut monad_log_handler; 1] = [handler.c_handle];

        let rc = unsafe { monad_log_init(handler_array.as_mut_ptr(), 1, syslog_level) };

        if let Err(err) = check_log_library_error(rc) {
            panic!("monad_init_log failed: {err}");
        }

        handler
    });
}
