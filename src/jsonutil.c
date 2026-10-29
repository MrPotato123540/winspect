// Tiny JSON string emitter shared by the --json output paths.
// We only need to print string VALUES correctly; the objects and arrays around
// them are assembled with plain printf in each command. Keeping it this small
// means there is no JSON library to trust and nothing stateful to get wrong.

#include "jsonutil.h"

#include <stdio.h>

void json_str(const char *s)
{
    putchar('"');
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            // Everything below U+0020 must be escaped as \uXXXX in JSON; the rest
            // (including UTF-8 bytes) passes through unchanged.
            if (c < 0x20) {
                printf("\\u%04x", c);
            } else {
                putchar((int)c);
            }
        }
    }
    putchar('"');
}

void csv_str(const char *s)
{
    if (s == NULL) {
        s = "";
    }
    // Does this field need quoting? Only if it contains a comma, a double quote,
    // a newline or a carriage return.
    int needs_quotes = 0;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quotes = 1;
            break;
        }
    }
    if (!needs_quotes) {
        fputs(s, stdout);
        return;
    }
    putchar('"');
    for (const char *p = s; *p != '\0'; p++) {
        if (*p == '"') {
            putchar('"');   // RFC 4180: double an embedded quote
        }
        putchar(*p);
    }
    putchar('"');
}
