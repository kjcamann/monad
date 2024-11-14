#pragma once

/**
 * @file
 *
 * A C++20 equivalent of the BSD <err.h> header; uses std::error_condition
 * instead of errno and <format> instead of printf
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <system_error>

#include "print_compat.hpp"

extern char const *__progname;

template <typename... Args>
[[noreturn]] void errc_f(
    int eval, std::error_condition const &ec, std::format_string<Args...> fmt,
    Args &&...args)
{
    std::print(stderr, "{}: ", __progname);
    std::print(stderr, fmt, std::forward<Args>(args)...);
    if (ec) {
        std::println(stderr, ": {} [{}]", ec.message(), ec.value());
    }
    else {
        std::println(stderr);
    }
    std::exit(eval);
}

template <typename... Args>
[[noreturn]] void errc_f(
    int eval, int errno_code, std::format_string<Args...> fmt, Args &&...args)
{
    errc_f(
        eval,
        static_cast<std::errc>(errno_code),
        fmt,
        std::forward<Args>(args)...);
}

template <typename... Args>
void err_f(int eval, std::format_string<Args...> fmt, Args &&...args)
{
    errc_f(
        eval, static_cast<std::errc>(errno), fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void errx_f(int eval, std::format_string<Args...> fmt, Args &&...args)
{
    errc_f(eval, {}, fmt, std::forward<Args>(args)...);
}
