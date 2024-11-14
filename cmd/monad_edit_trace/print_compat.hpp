#pragma once

/**
 * @file
 *
 * Compatibility shim for C++23 <print> which might be missing in our standard
 * library; this is a simple emulation and is missing the vprint_unicode
 * functions
 */

#if !__has_include(<print>)

    #include <cstdio>
    #include <filesystem>
    #include <format>
    #include <string>
    #include <string_view>

namespace std
{

    template <typename... Args>
    void print(std::FILE *file, std::format_string<Args...> fmt, Args &&...args)
    {
        std::string const s = std::format(fmt, std::forward<Args>(args)...);
        std::fwrite(s.c_str(), size(s), 1, file);
    }

    inline void println(std::FILE *file)
    {
        std::fwrite("\n", 1, 1, file);
    }

    template <typename... Args>
    void
    println(std::FILE *file, std::format_string<Args...> fmt, Args &&...args)
    {
        print(file, fmt, std::forward<Args>(args)...);
        println(file);
    }

    template <typename... Args>
    void print(std::format_string<Args...> fmt, Args &&...args)
    {
        print(stdout, fmt, std::forward<Args>(args)...);
    }

    inline void println()
    {
        println(stdout);
    }

    template <typename... Args>
    void println(std::format_string<Args...> fmt, Args &&...args)
    {
        println(stdout, fmt, std::forward<Args>(args)...);
    }

} // namespace std

// Anything too old to have <print> also doesn't have the formatter for
// paths; add that too
template <>
struct std::formatter<std::filesystem::path> : std::formatter<std::string_view>
{
    using std::formatter<std::string_view>::parse;

    template <typename FmtCtx>
    auto format(std::filesystem::path const &p, FmtCtx &ctx) const
    {
        return std::formatter<std::string_view>::format(p.string(), ctx);
    }
};

#else

namespace std
{

    // For libc++, which has <print> but not the C++26 blank-line functions
    inline void println(std::FILE *file)
    {
        std::println(file, "");
    }

    inline void println()
    {
        std::println(stdout);
    }

}

#endif
