#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// clang-format off

constexpr char HEX_DIGITS[] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

// clang-format on

void hexdump(FILE *file, void const *const buf, size_t const buflen)
{
    char fmt[2];
    uint8_t const *const buf_end = (uint8_t const *)buf + buflen;

    for (uint8_t const *line = (uint8_t const *)buf; line < buf_end;
         line += 16) {
        // Print one line of the dump, which is 16 bytes, in the form:
        // <offset> <8 bytes> <8 bytes>  <ascii-dump>
        fprintf(file, "%08zx ", (size_t)(line - (uint8_t const *)buf));
        for (uint8_t b = 0; b < 16; ++b) {
            if (line + b < buf_end) {
                fmt[0] = HEX_DIGITS[line[b] >> 4];
                fmt[1] = HEX_DIGITS[line[b] & 0xF];
            }
            else {
                fmt[0] = fmt[1] = ' ';
            }
            fwrite(fmt, sizeof fmt, 1, file);
            if (b == 7) {
                fputc(' ', file);
            }
        }
        fmt[0] = fmt[1] = ' ';
        fwrite(fmt, sizeof fmt, 1, file);
        for (uint8_t b = 0; b < 16 && line + b < buf_end; ++b) {
            int const byte = line[b];
            fputc(isprint(byte) ? byte : '.', file);
        }
        fputc('\n', file);
    }
}
