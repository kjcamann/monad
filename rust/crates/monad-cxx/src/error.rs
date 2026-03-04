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

use crate::ffi::monad_log_get_last_error;

#[derive(Debug)]
pub(crate) struct LogError(String);

impl LogError {
    pub(crate) fn new(err: String) -> Self {
        Self(err)
    }
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LogError {}

pub(crate) fn check_log_library_error(rc: std::ffi::c_int) -> Result<(), LogError> {
    if rc == 0 {
        return Ok(());
    }

    let err_str = unsafe {
        std::ffi::CStr::from_ptr(monad_log_get_last_error())
            .to_str()
            .unwrap_or("monad_log_get_last_error returned string with non-UTF8 chars")
    };

    Err(LogError(String::from(err_str)))
}
